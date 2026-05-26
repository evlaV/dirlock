/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

mod pamlib;

use pamsm::{LogLvl, Pam, PamError, PamFlags, PamLibExt, PamMsgStyle, PamServiceModule, pam_module};
use dirlock::{DirStatus, EncryptedDir, Host, Keystore, protector::ProtectorKey, recovery::RecoveryKey};
use std::ffi::c_int;

type Result<T> = std::result::Result<T, PamError>;

const PAM_UPDATE_AUTHTOK : c_int = 0x2000;
const PAM_PRELIM_CHECK   : c_int = 0x4000;

// Use with:
// auth [success=done user_unknown=ignore default=die] pam_dirlock.so
// password [success=done user_unknown=ignore default=die] pam_dirlock.so
// We cannot use 'default=ignore' because we don't want the unix
// module to try to authenticate this

/// Authentication data to store in the PAM context.
/// This contains the protector key to unlock the user's home directory.
#[derive(Clone)]
struct AuthData(ProtectorKey);

impl AuthData {
    /// Name for the Pam::send_data() function
    const PAM_NAME: &str = "dirlock_authdata";

    fn new(protkey: ProtectorKey) -> Self {
        AuthData(protkey)
    }

    fn protector_key(&self) -> &ProtectorKey {
        &self.0
    }

    /// Store a [`ProtectorKey`] in the PAM session so it can later be
    /// used to unlock the home directory in `pam_open_session()`.
    fn store_in_session(pamh: &Pam, protkey: ProtectorKey) -> Result<()> {
        let authtok_data = AuthData::new(protkey);
        unsafe { pamh.send_data(Self::PAM_NAME, authtok_data)? };
        Ok(())
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

fn pam_init(pamh: &Pam) -> bool {
    if let Err(e) = dirlock::init() {
        log_warning(pamh, format!("{e}"));
        false
    } else {
        true
    }
}

/// Get the user name and check that it's an ASCII string
fn get_user(pamh: &Pam) -> Result<&str> {
    match pamh.get_user(None)?.ok_or(PamError::AUTH_ERR)?.to_str() {
        Ok(s) if s.is_ascii() => Ok(s),
        _ => Err(PamError::AUTH_ERR),
    }
}

/// Get information about the user's home directory.
///
/// If it's not encrypted by dirlock then return PAM_USER_UNKNOWN so
/// other PAM modules can try to handle it.
fn get_home_data(user: &str, ks: &Keystore) -> Result<EncryptedDir> {
    match dirlock::open_home(user, ks) {
        Ok(Some(DirStatus::Encrypted(d))) => Ok(d),
        Ok(Some(_)) => Err(PamError::USER_UNKNOWN), // The home directory is not encrypted with dirlock
        Ok(None)    => Err(PamError::USER_UNKNOWN), // The home directory does not exist
        Err(_)      => Err(PamError::SERVICE_ERR),
    }
}

/// Get the value of PAM_RHOST and return whether it is local or remote.
fn get_rhost(pamh: &Pam) -> Host {
    let rhost = pamh.get_rhost().unwrap_or(None).map(|h| h.to_bytes());
    match rhost.unwrap_or(b"") {
        b"" | b"localhost" | b"127.0.0.1" | b"::1" => Host::Local,
        _ => Host::Remote,
    }
}

/// Show an error message to the user
fn show_pam_error(pamh: &Pam, text: &str) {
    match pamh.get_service() {
        // ssh won't display the error messages until the user is
        // logged in, so it's better not to show anything
        Ok(Some(s)) if s == c"sshd" => (),
        _ => _ = pamh.conv(Some(text), PamMsgStyle::ERROR_MSG),
    }
}

/// Try the modhex-encoded recovery key `pass` on `dir`.
///
/// If `pass` is unset, the user will be prompted for one.
///
/// Returns `true` on success (storing the key in the PAM session),
/// `false` if the directory cannot be unlocked with `pass`, or an
/// error if PAM returns one.
fn try_recovery_key(pamh: &Pam, dir: &EncryptedDir, pass: Option<&[u8]>) -> Result<bool> {
    let Some(recovery) = &dir.recovery else {
        return Ok(false);
    };
    let pass = match pass {
        Some(p) => p,
        None => pamh.conv(Some("Enter recovery key: "), PamMsgStyle::PROMPT_ECHO_OFF)?
            .map(|p| p.to_bytes())
            .ok_or(PamError::AUTH_ERR)?
    };
    if let Ok(key) = RecoveryKey::from_ascii_bytes(pass) {
        if recovery.unwrap_key(key.protector_key()).is_some() {
            AuthData::store_in_session(pamh, key.into_protector_key())?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Implementation of pam_sm_authenticate().
///
/// Used for authentication.
fn do_authenticate(pamh: Pam, autologin: bool) -> Result<()> {
    let ks = Keystore::default();
    let user = get_user(&pamh)?;
    let homedir = get_home_data(user, &ks)?;
    let rhost = get_rhost(&pamh);

    // If autologin is enabled we don't ask for a password.
    // We succeed or fail depending on whether the home directory
    // is already unlocked.
    if autologin {
        if homedir.key_status == dirlock::KeyStatus::Present {
            log_info(&pamh, format!("autologin; home already unlocked for user {user}"));
            return Ok(());
        }
        log_warning(&pamh, format!("autologin; home is locked for user {user}"));
        return Err(PamError::AUTH_ERR);
    }

    let mut available_protectors = false;

    for p in &homedir.protectors {
        if ! p.protector.is_available() {
            continue;
        }

        let protid = &p.protector.id;
        let prompt = match p.protector.get_prompt(rhost) {
            Ok(p) => p,
            Err(e) => {
                log_warning(&pamh, format!("unable to use protector {protid}; user={user} error={e}"));
                show_pam_error(&pamh, &e);
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

        // If the user entered something that resembles a recovery key, try it first
        if try_recovery_key(&pamh, &homedir, Some(pass))? {
            return Ok(());
        }

        // Check if the password can unlock the home directory (but don't actually unlock it)
        match p.protector.unwrap_key(pass) {
            Ok(Some(protkey)) => {
                return AuthData::store_in_session(&pamh, protkey);
            },
            Ok(None) => log_notice(&pamh, format!("authentication failure; user={user} protector={protid}")),
            Err(e) => log_warning(&pamh, format!("authentication failure; user={user} protector={protid} error={e}")),
        }

        show_pam_error(&pamh, "Authentication failed");
    }

    if !available_protectors {
        // If there were no available protectors maybe we can still use a recovery key
        if homedir.recovery.is_some() {
            if try_recovery_key(&pamh, &homedir, None)? {
                return Ok(());
            }
            show_pam_error(&pamh, "Authentication failed");
        } else {
            show_pam_error(&pamh, "Cannot authenticate: no available protectors");
        }
    }

    Err(PamError::AUTH_ERR)
}


/// Implementation of pam_sm_chauthtok
///
/// Used for changing passwords (with 'passwd' or similar)
fn do_chauthtok(pamh: Pam, flags: PamFlags) -> Result<()> {
    let ks = Keystore::default();
    let user = get_user(&pamh)?;
    let mut homedir = get_home_data(user, &ks)?;
    let rhost = get_rhost(&pamh);

    // Get only the protectors that are available and can be updated
    let prots : Vec<_> = homedir.protectors.iter_mut().filter(|p| {
        p.protector.can_change_password() && p.protector.is_available() &&
        p.protector.get_prompt(rhost).is_ok()
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
        match dirlock::update_protector_password(&mut p.protector, pass, newpass, &ks) {
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

fn do_open_session(pamh: Pam) -> Result<()> {
    let ks = Keystore::default();
    let user = get_user(&pamh)?;

    // If a conversion is in progress for this user's home, mark it as
    // dirty and let them log in (the directory is still unencrypted
    // so there's no need to unlock it).
    // TODO: if the conversion was interrupted due to e.g. a system crash
    // it must be manually restarted. Maybe notify the user about it?
    match dirlock::mark_home_dirty(user) {
        Ok(true) => {
            log_info(&pamh, format!("session opened during conversion for user {user}"));
            return Ok(());
        }
        Ok(false) => (),  // No conversion in progress; fall through.
        Err(e) => {
            log_warning(&pamh, format!("error checking conversion for user {user}: {e}"));
            return Err(PamError::SERVICE_ERR);
        }
    }

    let homedir = get_home_data(user, &ks)?;
    // If the home directory is already unlocked then we are done
    if homedir.key_status == dirlock::KeyStatus::Present {
        log_info(&pamh, format!("session opened for user {user}"));
        return Ok(());
    }
    // Otherwise we need to unlock it using the protector key stored in the session
    let Ok(data) : Result<AuthData> = (unsafe { pamh.retrieve_data(AuthData::PAM_NAME) }) else {
        log_warning(&pamh, format!("error retrieving auth token from session for user {user}"));
        return Err(PamError::SESSION_ERR);
    };
    match homedir.unlock_with_protkey(data.protector_key()) {
        Ok(true) => {
            log_info(&pamh, format!("session opened for user {user}; home unlocked"));
            Ok(())
        },
        Ok(false) => {
            log_warning(&pamh, format!("error unlocking home; user={user}, error=invalid protector key!"));
            Err(PamError::SESSION_ERR)
        },
        Err(e) => {
            log_warning(&pamh, format!("error unlocking home; user={user}, error={e}"));
            Err(PamError::SESSION_ERR)
        },
    }
}

fn do_close_session(pamh: Pam) -> Result<()> {
    let ks = Keystore::default();
    let user = get_user(&pamh)?;
    let _homedir = get_home_data(user, &ks)?;
    log_info(&pamh, format!("session closed for user {user}"));
    Ok(())
}

// This is the glue for the pamsm crate
struct FscryptPam;
pam_module!(FscryptPam);

impl PamServiceModule for FscryptPam {
    fn authenticate(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        if ! pam_init(&pamh) {
            return PamError::SERVICE_ERR;
        }
        let autologin = args.iter().any(|a| a == "autologin");
        do_authenticate(pamh, autologin).err().unwrap_or(PamError::SUCCESS)
    }

    fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        if ! pam_init(&pamh) {
            return PamError::SERVICE_ERR;
        }
        match do_open_session(pamh) {
            Ok(()) => PamError::SUCCESS,
            Err(PamError::USER_UNKNOWN) => PamError::SUCCESS,
            Err(_) => PamError::SESSION_ERR,
        }
    }

    fn close_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        if ! pam_init(&pamh) {
            return PamError::SERVICE_ERR;
        }
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
        if ! pam_init(&pamh) {
            return PamError::SERVICE_ERR;
        }
        do_chauthtok(pamh, flags).err().unwrap_or(PamError::SUCCESS)
    }
}
