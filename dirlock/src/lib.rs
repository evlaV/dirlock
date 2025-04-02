/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

pub mod convert;
pub mod fscrypt;
pub mod kdf;
pub mod keystore;
pub mod protector;
pub mod util;

use anyhow::{anyhow, bail, Result};
use fscrypt::{Policy, PolicyKey, PolicyKeyId, RemoveKeyUsers, RemovalStatusFlags};
use protector::{
    ProtectedPolicyKey,
    Protector,
    ProtectorId,
    ProtectorKey,
    WrappedPolicyKey,
    opts::ProtectorOpts
};
use std::path::{Path, PathBuf};

pub enum DirStatus {
    Unencrypted,
    Encrypted(EncryptedDir),
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
pub struct EncryptedDir {
    pub path: PathBuf,
    pub policy: fscrypt::PolicyV2,
    pub key_status: fscrypt::KeyStatus,
    pub key_flags: fscrypt::KeyStatusFlags,
    pub protectors: Vec<ProtectedPolicyKey>,
}

/// Gets the encryption status of a directory.
///
/// If [`DirStatus::Encrypted`] is returned it implies that:
/// 1. The directory is encrypted with a supported fscrypt policy (v2).
/// 2. The keystore contains a protector for that policy.
pub fn open_dir(path: &Path) -> Result<DirStatus> {
    let policy = match fscrypt::get_policy(path).
        map_err(|e| anyhow!("Failed to get encryption policy: {e}"))? {
        Some(Policy::V2(p)) => p,
        Some(_) => return Ok(DirStatus::Unsupported),
        None    => return Ok(DirStatus::Unencrypted),
    };

    let protectors = keystore::get_protectors_for_policy(&policy.keyid)?;
    if protectors.is_empty() {
        return Ok(DirStatus::KeyMissing);
    };

    let (key_status, key_flags) = fscrypt::get_key_status(path, &policy.keyid)
        .map_err(|e| anyhow!("Failed to get key status: {e}"))?;

    Ok(DirStatus::Encrypted(EncryptedDir { path: path.into(), policy, key_status, key_flags, protectors }))
}

/// Convenience function to call `open_dir` on a user's home directory
///
/// Returns None if the user does not exist.
pub fn open_home(user: &str) -> Result<Option<DirStatus>> {
    if let Some(dir) = util::get_homedir(user)? {
        let dir = open_dir(&dir)?;
        Ok(Some(dir))
    } else {
        Ok(None)
    }
}

impl EncryptedDir {
    /// Get a directory's master encryption key using the password of one of its protectors
    ///
    /// If `protector_id` is `None` try all available protectors.
    pub fn get_master_key(&self, pass: &[u8], protector_id: Option<&ProtectorId>) -> Option<PolicyKey> {
        for p in &self.protectors {
            if let Some(id) = protector_id {
                if *id != p.protector.id {
                    continue;
                }
            }
            if let Some(k) = p.protector.unwrap_policy_key(&p.policy_key, pass) {
                return Some(k);
            }
        }
        None
    }

    /// Checks if the given password is valid to unlock this directory
    ///
    /// This call only checks the password and nothing else, and it
    /// also does not care if the directory is locked or unlocked.
    ///
    /// If `protector_id` is `None` try all available protectors.
    pub fn check_pass(&self, password: &[u8], protector_id: Option<&ProtectorId>) -> bool {
        self.get_master_key(password, protector_id).is_some()
    }

    /// Unlocks a directory with the given password
    ///
    /// Returns true on success, false if the password is incorrect.
    /// This call also succeeds if the directory is already unlocked
    /// as long as the password is correct.
    pub fn unlock(&self, password: &[u8], protector_id: Option<&ProtectorId>) -> Result<bool> {
        if let Some(master_key) = self.get_master_key(password, protector_id) {
            if let Err(e) = fscrypt::add_key(&self.path, &master_key) {
                bail!("Unable to unlock directory with master key: {}", e);
            }
            return Ok(true)
        }

        Ok(false)
    }

    /// Locks a directory
    pub fn lock(&self, user: RemoveKeyUsers) -> Result<RemovalStatusFlags> {
        if self.key_status == fscrypt::KeyStatus::Absent {
            bail!("The directory {} is already locked", self.path.display());
        }

        fscrypt::remove_key(&self.path, &self.policy.keyid, user)
            .map_err(|e|anyhow!("Unable to lock directory: {e}"))
    }

    /// Finds a protector that can be unlocked with the given password
    pub fn get_protector_id_by_pass(&self, pass: &[u8]) -> Result<ProtectorId> {
        for p in &self.protectors {
            if p.protector.unwrap_key(pass).is_some() {
                return Ok(p.protector.id.clone());
            }
        }
        bail!("No protector found with that password in the directory");
    }

    /// Find a protector using its ID in string form
    pub fn get_protector_id_by_str(&self, id_str: impl AsRef<str>) -> Result<ProtectorId> {
        let id = ProtectorId::try_from(id_str.as_ref())?;
        if !self.protectors.iter().any(|p| p.protector.id == id) {
            bail!("No protector found with that ID in the directory");
        }
        Ok(id)
    }

    /// Changes the password of a protector used to lock this directory
    ///
    /// If `protector_id` is `None`, change the first protector with a matching password.
    pub fn change_password(&mut self, pass: &[u8], newpass: &[u8], protector_id: Option<&ProtectorId>) -> Result<bool> {
        for p in &mut self.protectors {
            if let Some(id) = protector_id {
                if *id != p.protector.id {
                    continue;
                }
            }
            if p.protector.change_pass(pass, newpass) {
                keystore::save_protector(&p.protector, keystore::SaveProtector::UpdateExisting)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Remove a protector from a directory.
    /// Note: this will remove the protector even if it's the only one left.
    pub fn remove_protector(&self, id: &ProtectorId) -> Result<bool> {
        for ProtectedPolicyKey { protector, .. } in &self.protectors {
            if &protector.id == id {
                if keystore::remove_protector_from_policy(&self.policy.keyid, &protector.id)? {
                    // TODO: add an option to make this conditional
                    keystore::remove_protector_if_unused(&protector.id)?;
                    return Ok(true);
                }
                return Ok(false);
            }
        }

        Ok(false)
    }
}


/// Encrypts a directory
pub fn encrypt_dir(path: &Path, protector_key: ProtectorKey) -> Result<PolicyKeyId> {
    match open_dir(path)? {
        DirStatus::Unencrypted => (),
        x => bail!("{}", x),
    };

    if ! util::dir_is_empty(path)? {
        bail!("Cannot encrypt a non-empty directory");
    }

    // Generate a master key and encrypt the directory with it
    // FIXME: Write the key to disk before encrypting the directory
    let master_key = fscrypt::PolicyKey::new_random();
    let keyid = fscrypt::add_key(path, &master_key)?;
    if let Err(e) = fscrypt::set_policy(path, &keyid) {
        let user = RemoveKeyUsers::CurrentUser;
        let _ = fscrypt::remove_key(path, &keyid, user);
        bail!("Failed to encrypt directory: {e}");
    }

    // Wrap the master key with the protector key
    let protector_id = protector_key.get_id();
    let wrapped_policy_key = WrappedPolicyKey::new(master_key, &protector_key);

    // Store the new wrapped policy key
    keystore::add_protector_to_policy(&keyid, protector_id, wrapped_policy_key)?;
    Ok(keyid)
}

/// Get an existing protector
pub fn get_protector_by_str(id_str: impl AsRef<str>) -> Result<Protector> {
    let id = ProtectorId::try_from(id_str.as_ref())?;
    let Some(prot) = keystore::load_protector(id)? else {
        bail!("Protector {} not found", id_str.as_ref());
    };
    Ok(prot)
}

/// Create (and store on disk) a new protector using a password
pub fn create_protector(opts: ProtectorOpts, pass: &[u8]) -> Result<ProtectorKey> {
    let protector_key = ProtectorKey::new_random();
    let protector = Protector::new(opts, protector_key.clone(), pass)?;
    keystore::save_protector(&protector, keystore::SaveProtector::AddNew)?;
    Ok(protector_key)
}

/// Wrap `policy_key` using `protector_key` and store the result on disk
pub fn wrap_and_save_policy_key(protector_key: ProtectorKey, policy_key: PolicyKey) -> Result<()> {
    let protector_id = protector_key.get_id();
    let policy_id = policy_key.get_id();
    let wrapped_policy_key = WrappedPolicyKey::new(policy_key, &protector_key);
    keystore::add_protector_to_policy(&policy_id, protector_id, wrapped_policy_key)
}

/// Change a protector's password and save it to disk
pub fn change_protector_password(mut protector: Protector, pass: &[u8], newpass: &[u8]) -> Result<bool> {
    if protector.change_pass(pass, newpass) {
        keystore::save_protector(&protector, keystore::SaveProtector::UpdateExisting)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Initialize the dirlock library
pub fn init() {
    use std::sync::Once;
    static DIRLOCK_INIT: Once = Once::new();
    DIRLOCK_INIT.call_once(|| {
        // Disable log messages from the TPM2 library
        std::env::set_var("TSS2_LOG", "all+NONE");
    });
}
