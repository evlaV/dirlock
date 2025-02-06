
pub mod config;
pub mod fscrypt;
pub mod protector;
mod util;

use anyhow::{anyhow, bail, Result};
use config::Config;
use fscrypt::{KeyIdentifier, RemovalStatusFlags};
use protector::{Protector, PasswordProtector};
use std::path::Path;

pub enum DirStatus {
    Unencrypted,
    Encrypted(EncryptedDirData),
    KeyMissing,
    Unsupported,
}

impl std::fmt::Display for DirStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use DirStatus::*;
        let msg = match self {
            Encrypted(_) => "Directory already encrypted",
            Unencrypted  => "Directory not encrypted",
            Unsupported  => "Directory using an unsupported encryption mechanism",
            KeyMissing   => "Directory encrypted, key missing",
        };
        write!(f, "{}", msg)
    }
}

/// Encryption data (policy, key status) of a given directory
pub struct EncryptedDirData {
    pub policy: fscrypt::PolicyV2,
    pub key_status: fscrypt::KeyStatus,
    pub _key_flags: fscrypt::KeyStatusFlags,
}

/// Return an [`EncryptedDirData`] object for the directory.
///
/// If a value is returned it implies that:
/// 1. The directory is encrypted with a supported fscrypt policy (v2).
/// 2. The configuration contains a protector for that policy.
pub fn get_encrypted_dir_data(path: &Path, cfg: &Config) -> Result<DirStatus> {
    let policy = match fscrypt::get_policy(path).
        map_err(|e| anyhow!("Failed to get encryption policy: {e}"))? {
        Some(fscrypt::Policy::V2(p)) => p,
        None => return Ok(DirStatus::Unencrypted),
        _    => return Ok(DirStatus::Unsupported),
    };

    if ! cfg.has_protector(&policy.master_key_identifier) {
        return Ok(DirStatus::KeyMissing);
    };

    let (key_status, _key_flags) = fscrypt::get_key_status(path, &policy.master_key_identifier)
        .map_err(|e| anyhow!("Failed to get key status: {e}"))?;

    Ok(DirStatus::Encrypted(EncryptedDirData { policy, key_status, _key_flags }))
}

/// Convenience function to call `get_encrypted_dir_data` on a user's home directory
pub fn get_homedir_data(user: &str, cfg: &Config) -> Result<DirStatus> {
    get_encrypted_dir_data(&util::get_homedir(user)?, cfg)
}

/// Convenience function to call `lock_dir` on a user's home directory
pub fn lock_user(user: &str, cfg: &Config) -> Result<RemovalStatusFlags> {
    lock_dir(&util::get_homedir(user)?, cfg)
}

/// Convenience function to call `unlock_dir` on a user's home directory
pub fn unlock_user(user: &str, password: &str, cfg: &Config) -> Result<()> {
    unlock_dir(&util::get_homedir(user)?, password, cfg)
}

pub fn auth_user(user: &str, password: &str, cfg: &Config) -> Result<bool> {
    let homedir = util::get_homedir(user)?;
    let dir_data = match get_encrypted_dir_data(&homedir, cfg)? {
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    // TODO: At this point we should already know that we have a key
    // Maybe store it in the dir data?
    let Some(prot) = cfg.get_protector(&dir_data.policy.master_key_identifier) else {
        bail!("Unable to find a key to decrypt directory {}", homedir.display());
    };

    let master_key = prot.decrypt(password.as_bytes());
    Ok(dir_data.policy.master_key_identifier == master_key.get_id())
}

/// Unlocks a directory with the given password
pub fn unlock_dir(path: &Path, password: &str, cfg: &Config) -> Result<()> {
    let dir_data = match get_encrypted_dir_data(path, cfg)? {
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    if dir_data.key_status == fscrypt::KeyStatus::Present {
        bail!("The directory {} is already unlocked", path.display());
    }

    // TODO: At this point we should already know that we have a key
    // Maybe store it in the dir data?
    let Some(prot) = cfg.get_protector(&dir_data.policy.master_key_identifier) else {
        bail!("Unable to find a key to decrypt directory {}", path.display());
    };

    let master_key = prot.decrypt(password.as_bytes());
    if dir_data.policy.master_key_identifier != master_key.get_id() {
        bail!("Unable to decrypt master key: wrong password?");
    }

    if let Err(e) = fscrypt::add_key(path, &master_key) {
        bail!("Unable to unlock directory with master key: {}", e);
    }

    Ok(())
}


/// Locks a directory
pub fn lock_dir(path: &Path, cfg: &Config) -> Result<RemovalStatusFlags> {
    let dir_data = match get_encrypted_dir_data(path, cfg)? {
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    if dir_data.key_status == fscrypt::KeyStatus::Absent {
        bail!("The directory {} is already locked", path.display());
    }

    let user = fscrypt::RemoveKeyUsers::CurrentUser;
    fscrypt::remove_key(path, &dir_data.policy.master_key_identifier, user)
        .map_err(|e|anyhow!("Unable to lock directory: {e}"))
}


/// Encrypts a directory
pub fn encrypt_dir(path: &Path, password: &str, cfg: &mut Config) -> Result<KeyIdentifier> {
    match get_encrypted_dir_data(path, cfg)? {
        DirStatus::Unencrypted => (),
        x => bail!("{}", x),
    };

    if ! util::dir_is_empty(path)? {
        bail!("Cannot encrypt a non-empty directory");
    }

    let master_key = fscrypt::RawKey::new_random();
    let keyid = fscrypt::add_key(path, &master_key)?;
    if let Err(e) = fscrypt::set_policy(path, &keyid) {
        let user = fscrypt::RemoveKeyUsers::CurrentUser;
        let _ = fscrypt::remove_key(path, &keyid, user);
        bail!("Failed to encrypt directory: {e}");
    }

    let prot = PasswordProtector::new(&master_key, password.as_bytes())?;
    cfg.add_protector(&keyid, Protector::Password(prot));
    // FIXME: At this point the directory is encrypted and we don't have a key
    cfg.save().map_err(|e| anyhow!("Failed to save config: {e}"))?;
    Ok(keyid)
}
