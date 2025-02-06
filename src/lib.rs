
pub mod config;
pub mod fscrypt;
pub mod protector;
mod util;

use anyhow::{anyhow, bail, Result};
use config::Config;
use fscrypt::{Policy, PolicyKeyId, RemovalStatusFlags};
use protector::{Protector, PasswordProtector, WrappedPolicyKey};
use std::path::{Path, PathBuf};

#[derive(PartialEq)]
pub enum UnlockAction {
    /// Check that the password is valid but don't unlock the directory.
    AuthOnly,
    /// Check that the password is valid and unlock the directory.
    AuthAndUnlock,
}

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
    pub path: PathBuf,
    pub policy: fscrypt::PolicyV2,
    pub key_status: fscrypt::KeyStatus,
    pub key_flags: fscrypt::KeyStatusFlags,
}

/// Return an [`EncryptedDirData`] object for the directory.
///
/// If a value is returned it implies that:
/// 1. The directory is encrypted with a supported fscrypt policy (v2).
/// 2. The configuration contains a protector for that policy.
pub fn get_encrypted_dir_data(path: &Path, cfg: &Config) -> Result<DirStatus> {
    let policy = match fscrypt::get_policy(path).
        map_err(|e| anyhow!("Failed to get encryption policy: {e}"))? {
        Some(Policy::V2(p)) => p,
        Some(_) => return Ok(DirStatus::Unsupported),
        None    => return Ok(DirStatus::Unencrypted),
    };

    if cfg.get_protectors_for_policy(&policy.keyid).is_empty() {
        return Ok(DirStatus::KeyMissing);
    };

    let (key_status, key_flags) = fscrypt::get_key_status(path, &policy.keyid)
        .map_err(|e| anyhow!("Failed to get key status: {e}"))?;

    Ok(DirStatus::Encrypted(EncryptedDirData { path: path.into(), policy, key_status, key_flags }))
}

/// Convenience function to call `get_encrypted_dir_data` on a user's home directory
pub fn get_homedir_data(user: &str, cfg: &Config) -> Result<DirStatus> {
    get_encrypted_dir_data(&util::get_homedir(user)?, cfg)
}

/// Unlocks a directory with the given password
///
/// Returns true on success, false if the password is incorrect. Note
/// that this call also succeeds if the directory is already unlocked
/// as long as the password is correct.
pub fn unlock_dir(dir: &EncryptedDirData, password: &[u8], action: UnlockAction, cfg: &Config) -> Result<bool> {
    let protectors = cfg.get_protectors_for_policy(&dir.policy.keyid);
    if protectors.is_empty() {
        bail!("Unable to find a key to decrypt directory {}", dir.path.display());
    }

    for (_, prot, policykey) in protectors {
        if let Some(master_key) = prot.decrypt(policykey, password) {
            if action == UnlockAction::AuthAndUnlock {
                if let Err(e) = fscrypt::add_key(&dir.path, &master_key) {
                    bail!("Unable to unlock directory with master key: {}", e);
                }
            }
            return Ok(true)
        }
    }

    Ok(false)
}

/// Locks a directory
pub fn lock_dir(dir: &EncryptedDirData) -> Result<RemovalStatusFlags> {
    if dir.key_status == fscrypt::KeyStatus::Absent {
        bail!("The directory {} is already locked", dir.path.display());
    }

    let user = fscrypt::RemoveKeyUsers::CurrentUser;
    fscrypt::remove_key(&dir.path, &dir.policy.keyid, user)
        .map_err(|e|anyhow!("Unable to lock directory: {e}"))
}

/// Encrypts a directory
pub fn encrypt_dir(path: &Path, password: &[u8], cfg: &mut Config) -> Result<PolicyKeyId> {
    match get_encrypted_dir_data(path, cfg)? {
        DirStatus::Unencrypted => (),
        x => bail!("{}", x),
    };

    if ! util::dir_is_empty(path)? {
        bail!("Cannot encrypt a non-empty directory");
    }

    // Generate a master key and encrypt the directory with it
    let master_key = fscrypt::PolicyKey::new_random();
    let keyid = fscrypt::add_key(path, &master_key)?;
    if let Err(e) = fscrypt::set_policy(path, &keyid) {
        let user = fscrypt::RemoveKeyUsers::CurrentUser;
        let _ = fscrypt::remove_key(path, &keyid, user);
        bail!("Failed to encrypt directory: {e}");
    }

    // Generate a protector key and use it to wrap the master key
    let protector_key = protector::ProtectorKey::new_random();
    let protector_id = protector_key.get_id();
    let policy = WrappedPolicyKey::new(master_key, &protector_key)?;

    // Wrap the protector key with a password
    let protector = PasswordProtector::new(protector_key, password)?;

    // Store the new protector and policy in the configuration
    cfg.add_protector(protector_id.clone(), Protector::Password(protector))?;
    cfg.add_policy(keyid.clone(), protector_id, policy)?;
    // FIXME: At this point the directory is encrypted and we don't have a key
    cfg.save().map_err(|e| anyhow!("Failed to save config: {e}"))?;
    Ok(keyid)
}
