/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

mod pamlib;

use pamsm::{LogLvl, Pam, PamError, PamFlags, PamLibExt, PamMsgStyle, PamServiceModule, pam_module};
use dirlock::{DirStatus, EncryptedDir, protector::ProtectorId};
use std::ffi::c_int;
use zeroize::Zeroizing;

const PAM_UPDATE_AUTHTOK : c_int = 0x2000;
const PAM_PRELIM_CHECK   : c_int = 0x4000;

// Use with:
// auth [success=done user_unknown=ignore default=die] pam_dirlock.so
// password [success=done user_unknown=ignore default=die] pam_dirlock.so
// We cannot use 'default=ignore' because we don't want the unix
// module to try to authenticate this

/// Authentication data to store in the PAM context.
/// This contains a protector and a password to unlock the user's home
/// directory.
#[derive(Clone)]
struct AuthData(ProtectorId, Zeroizing<Vec<u8>>);

impl AuthData {
    /// Name for the Pam::send_data() function
    const PAM_NAME: &str = "dirlock_authdata";

    fn new(protid: &ProtectorId, pass: &[u8]) -> Self {
        AuthData(*protid, Zeroizing::new(Vec::from(pass)))
    }

    fn protector_id(&self) -> &ProtectorId {
        &self.0
    }

    fn pass(&self) -> &[u8] {
        &self.1
    }
}

impl pamsm::PamData for AuthData {
    fn cleanup(&self, _pam: Pam, _flags: PamFlags, _status: PamError) {
    }
}


fn log_warning(pamh: &Pam, msg: impl AsRef<str>) {
    let _ = pamh.syslog(LogLvl::WARNING, msg.as_ref());
}

fn log_notice(pamh: &Pam, msg: impl AsRef<str>) {
    let _ = pamh.syslog(LogLvl::NOTICE, msg.as_ref());
}

fn log_info(pamh: &Pam, msg: impl AsRef<str>) {
    let _ = pamh.syslog(LogLvl::INFO, msg.as_ref());
}

/// Get the user name and check that it's an ASCII string
fn get_user(pamh: &Pam) -> Result<&str, PamError> {
    match pamh.get_user(None)?.ok_or(PamError::AUTH_ERR)?.to_str() {
        Ok(s) if s.is_ascii() => Ok(s),
        _ => Err(PamError::AUTH_ERR),
    }
}

/// Get information about the user's home directory.
///
/// If it's not encrypted by dirlock then return PAM_USER_UNKNOWN so
/// other PAM modules can try to handle it.
fn get_home_data(user: &str) -> Result<EncryptedDir, PamError> {
    match dirlock::open_home(user) {
        Ok(Some(DirStatus::Encrypted(d))) => Ok(d),
        Ok(Some(_)) => Err(PamError::USER_UNKNOWN), // The home directory is not encrypted with dirlock
        Ok(None)    => Err(PamError::USER_UNKNOWN), // The home directory does not exist
        Err(_)      => Err(PamError::SERVICE_ERR),
    }
}

/// Implementation of pam_sm_authenticate().
///
/// Used for authentication.
fn do_authenticate(pamh: Pam) -> Result<(), PamError> {
    let user = get_user(&pamh)?;
    let homedir = get_home_data(user)?;

    let mut available_protectors = false;

    for p in &homedir.protectors {
        if ! p.protector.is_available() {
            continue;
        }

        let prompt = match p.protector.get_prompt() {
            Ok(p) => p,
            Err(e) => {
                _ = pamh.conv(Some(&e), PamMsgStyle::ERROR_MSG);
                continue;
            },
        };

        available_protectors = true;

        // Get the password
        let pass = if p.protector.needs_password() {
            pamh.conv(Some(&format!("{prompt}: ")), PamMsgStyle::PROMPT_ECHO_OFF)?
                .map(|p| p.to_bytes())
                .ok_or(PamError::AUTH_ERR)?
        } else {
            _ = pamh.conv(Some(&prompt), PamMsgStyle::TEXT_INFO);
            b""
        };

        // Check if the password can unlock the home directory (but don't actually unlock it)
        let protid = &p.protector.id;
        match p.protector.unwrap_policy_key(&p.policy_key, pass) {
            Ok(Some(_)) => {
                // Store the protector id and the password in the PAM session
                // in order to unlock the home directory in pam_open_session().
                let authtok_data = AuthData::new(protid, pass);
                unsafe { pamh.send_data(AuthData::PAM_NAME, authtok_data)? };
                return Ok(());
            },
            Ok(None) => log_notice(&pamh, format!("authentication failure; user={user} protector={protid}")),
            Err(e) => log_warning(&pamh, format!("authentication failure; user={user} protector={protid} error={e}")),
        }

        _ = pamh.conv(Some("Authentication failed"), PamMsgStyle::ERROR_MSG);
    }

    if !available_protectors {
        _ = pamh.conv(Some("Cannot authenticate: no available protectors"), PamMsgStyle::ERROR_MSG);
    }

    Err(PamError::AUTH_ERR)
}


/// Implementation of pam_sm_chauthtok
///
/// Used for changing passwords (with 'passwd' or similar)
fn do_chauthtok(pamh: Pam, flags: PamFlags) -> Result<(), PamError> {
    let user = get_user(&pamh)?;
    let mut homedir = get_home_data(user)?;

    // Get only the protectors that are available and can be updated
    let prots : Vec<_> = homedir.protectors.iter_mut().filter(|p| {
        p.protector.can_change_password() && p.protector.is_available()
    }).collect();

    if prots.is_empty() {
        let _ = pamh.conv(Some("No available protectors."), PamMsgStyle::ERROR_MSG);
        log_notice(&pamh, format!("cannot change password; no available protectors; user={user}"));
        return Err(PamError::AUTH_ERR);
    }

    // Get the current password
    let pass = pamlib::get_oldauthtok(&pamh).map(|p| p.to_bytes())?;

    // Check that the current password is correct.
    // Do it only at the preliminary check step because we'll anyway
    // have to do it again later when we actually change the password.
    if flags.bits() & PAM_PRELIM_CHECK != 0 {
        for p in prots {
            match p.protector.unwrap_key(pass) {
                Ok(None) => (),
                Ok(Some(_)) => return Ok(()),
                Err(e) => {
                    log_warning(&pamh, format!("authentication failure; user={user} error={e}"));
                    return Err(PamError::AUTH_ERR);
                },
            }
        }
        log_notice(&pamh, format!("authentication failure; user={user}"));
        return Err(PamError::AUTH_ERR);
    }

    // If we don't receive PAM_UPDATE_AUTHTOK at this point then something is wrong
    if flags.bits() & PAM_UPDATE_AUTHTOK == 0 {
        return Err(PamError::ABORT);
    }

    // Get the new pasword
    let newpass = pamh.get_authtok(None)?
        .map(|p| p.to_bytes())
        .ok_or(PamError::AUTHTOK_ERR)?;

    // Check that the new password is not empty
    if newpass.is_empty() {
        if ! flags.contains(PamFlags::SILENT) {
            let _ = pamh.conv(Some("No password has been supplied."), PamMsgStyle::ERROR_MSG);
        }
        return Err(PamError::AUTHTOK_ERR);
    }

    // Check that the new password is different from the old one
    if newpass == pass {
        if ! flags.contains(PamFlags::SILENT) {
            let _ = pamh.conv(Some("The password has not been changed."), PamMsgStyle::ERROR_MSG);
        }
        return Err(PamError::AUTHTOK_ERR);
    }

    // Change the password
    for p in prots {
        match dirlock::update_protector_password(&mut p.protector, pass, newpass) {
            Ok(false) => (),
            Ok(true) => {
                let protid = &p.protector.id;
                log_notice(&pamh, format!("password changed for user {user}, protector={protid}"));
                return Ok(());
            },
            Err(e) => {
                log_warning(&pamh, format!("error changing password; user={user}, error={e}"));
                return Err(PamError::AUTH_ERR);
            },
        }
    }

    log_warning(&pamh, format!("password for user {user} changed by another process"));
    Err(PamError::AUTH_ERR)
}

fn do_open_session(pamh: Pam) -> Result<(), PamError> {
    let user = get_user(&pamh)?;
    let homedir = get_home_data(user)?;
    // If the home directory is already unlocked then we are done
    if homedir.key_status == dirlock::fscrypt::KeyStatus::Present {
        log_info(&pamh, format!("session opened for user {user}"));
        return Ok(());
    }
    // Otherwise we need to unlock it using the password stored in the session
    let Ok(data) : Result<AuthData, _> = (unsafe { pamh.retrieve_data(AuthData::PAM_NAME) }) else {
        log_warning(&pamh, format!("error retrieving auth token from session for user {user}"));
        return Err(PamError::SESSION_ERR);
    };
    match homedir.unlock(data.pass(), data.protector_id()) {
        Ok(true) => {
            log_info(&pamh, format!("session opened for user {user}; home unlocked"));
            Ok(())
        },
        Ok(false) => {
            log_warning(&pamh, format!("error unlocking home for user {user}; did another process change the password?"));
            Err(PamError::SESSION_ERR)
        },
        Err(e) => {
            log_warning(&pamh, format!("error unlocking home; user={user}, error={e}"));
            Err(PamError::SESSION_ERR)
        },
    }
}

fn do_close_session(pamh: Pam) -> Result<(), PamError> {
    let user = get_user(&pamh)?;
    let _homedir = get_home_data(user)?;
    log_info(&pamh, format!("session closed for user {user}"));
    Ok(())
}

// This is the glue for the pamsm crate
struct FscryptPam;
pam_module!(FscryptPam);

impl PamServiceModule for FscryptPam {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        dirlock::init();
        do_authenticate(pamh).err().unwrap_or(PamError::SUCCESS)
    }

    fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        dirlock::init();
        match do_open_session(pamh) {
            Ok(()) => PamError::SUCCESS,
            Err(PamError::USER_UNKNOWN) => PamError::SUCCESS,
            Err(_) => PamError::SESSION_ERR,
        }
    }

    fn close_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        dirlock::init();
        match do_close_session(pamh) {
            Ok(()) => PamError::SUCCESS,
            Err(PamError::USER_UNKNOWN) => PamError::SUCCESS,
            Err(_) => PamError::SESSION_ERR,
        }
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn chauthtok(pamh: Pam, flags: PamFlags, _args: Vec<String>) -> PamError {
        dirlock::init();
        do_chauthtok(pamh, flags).err().unwrap_or(PamError::SUCCESS)
    }
}
