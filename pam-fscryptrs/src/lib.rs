
mod pamlib;

use pamsm::{LogLvl, Pam, PamError, PamFlags, PamLibExt, PamMsgStyle, PamServiceModule, pam_module};
use fscrypt_rs::{DirStatus, UnlockAction};
use std::ffi::c_int;

const PAM_UPDATE_AUTHTOK : c_int = 0x2000;
const PAM_PRELIM_CHECK   : c_int = 0x4000;

// Use with:
// auth [success=done user_unknown=ignore default=die] pam_fscryptrs.so
// password [success=done user_unknown=ignore default=die] pam_fscryptrs.so
// We cannot use 'default=ignore' because we don't want the unix
// module to try to authenticate this

fn log_notice(pamh: &Pam, msg: impl AsRef<str>) {
    let _ = pamh.syslog(LogLvl::NOTICE, msg.as_ref());
}

/// Implementation of pam_sm_authenticate().
///
/// Used for authentication.
fn do_authenticate(pamh: Pam) -> Result<(), PamError> {
    // Get the user name and check that it's an ASCII string
    let user = match pamh.get_user(None)?.ok_or(PamError::AUTH_ERR)?.to_str() {
        Ok(s) if s.is_ascii() => s,
        _ => return Err(PamError::AUTH_ERR),
    };

    // Get the data of the user's home directory
    let dir_data = match fscrypt_rs::get_homedir_data(user) {
        Ok(Some(DirStatus::Encrypted(d))) => d,
        Ok(Some(_)) => return Err(PamError::USER_UNKNOWN), // The home directory is not encrypted by us
        Ok(None)    => return Err(PamError::USER_UNKNOWN), // The home directory does not exist
        Err(_)      => return Err(PamError::SERVICE_ERR),
    };

    // Get the password
    let pass = pamh.get_authtok(None)?
        .map(|p| p.to_bytes())
        .ok_or(PamError::AUTH_ERR)?;

    // Unlock the home directory with the password
    match fscrypt_rs::unlock_dir(&dir_data, pass, UnlockAction::AuthAndUnlock) {
        Ok(true) => Ok(()),
        Ok(false) => {
            log_notice(&pamh, format!("authentication failure; user={user}"));
            Err(PamError::AUTH_ERR)
        },
        Err(e) => {
            log_notice(&pamh, format!("authentication failure; user={user} error={e}"));
            Err(PamError::AUTH_ERR)
        }
    }
}


/// Implementation of pam_sm_chauthtok
///
/// Used for changing passwords (with 'passwd' or similar)
fn do_chauthtok(pamh: Pam, flags: PamFlags) -> Result<(), PamError> {
    // Get the user name and check that it's an ASCII string
    let user = match pamh.get_user(None)?.ok_or(PamError::AUTH_ERR)?.to_str() {
        Ok(s) if s.is_ascii() => s,
        _ => return Err(PamError::AUTH_ERR),
    };

    // Get the data of the user's home directory
    let mut dir_data = match fscrypt_rs::get_homedir_data(user) {
        Ok(Some(DirStatus::Encrypted(d))) => d,
        Ok(Some(_)) => return Err(PamError::USER_UNKNOWN), // The home directory is not encrypted by us
        Ok(None)    => return Err(PamError::USER_UNKNOWN), // The home directory does not exist
        Err(_)      => return Err(PamError::SERVICE_ERR),
    };

    if flags.bits() & PAM_PRELIM_CHECK != 0 {
        return Ok(());
    }

    // If we don't receive PAM_UPDATE_AUTHTOK at this point then something is wrong
    if flags.bits() & PAM_UPDATE_AUTHTOK == 0 {
        return Err(PamError::ABORT);
    }

    // Get the current password
    let pass = pamlib::get_oldauthtok(&pamh).map(|p| p.to_bytes())?;

    // Check that the password is correct
    match fscrypt_rs::unlock_dir(&dir_data, pass, UnlockAction::AuthOnly) {
        Ok(true) => (),
        Ok(false) => {
            log_notice(&pamh, format!("authentication failure; user={user}"));
            return Err(PamError::AUTH_ERR)
        },
        Err(e) => {
            log_notice(&pamh, format!("authentication failure; user={user} error={e}"));
            return Err(PamError::AUTH_ERR)
        }
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
    match fscrypt_rs::change_dir_password(&mut dir_data, pass, newpass) {
        Ok(true) => {
            log_notice(&pamh, format!("password changed for {user}"));
            Ok(())
        },
        _ => {
            log_notice(&pamh, format!("error changing password for {user}"));
            Err(PamError::AUTH_ERR)
        }
    }
}

// This is the glue for the pamsm crate
struct FscryptPam;
pam_module!(FscryptPam);

impl PamServiceModule for FscryptPam {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        do_authenticate(pamh).err().unwrap_or(PamError::SUCCESS)
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn chauthtok(pamh: Pam, flags: PamFlags, _args: Vec<String>) -> PamError {
        do_chauthtok(pamh, flags).err().unwrap_or(PamError::SUCCESS)
    }
}
