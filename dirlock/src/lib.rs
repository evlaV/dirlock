/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

pub mod convert;
pub mod fscrypt;
pub mod keystore;
pub mod protector;
pub mod util;

use anyhow::{anyhow, bail, Result};
use fscrypt::{Policy, PolicyKey, PolicyKeyId, RemoveKeyUsers, RemovalStatusFlags};
use protector::{ProtectorId, ProtectedPolicyKey, opts::ProtectorOpts};
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
                if *id != p.protector_id {
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
                return Ok(p.protector_id.clone());
            }
        }
        bail!("No protector found with that password in the directory");
    }

    /// Find a protector using its ID in string form
    pub fn get_protector_id_by_str(&self, id_str: impl AsRef<str>) -> Result<ProtectorId> {
        let id = ProtectorId::try_from(id_str.as_ref())?;
        if !self.protectors.iter().any(|p| p.protector_id == id) {
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
                if *id != p.protector_id {
                    continue;
                }
            }
            if p.protector.change_pass(pass, newpass) {
                keystore::add_protector(&p.protector_id, &p.protector, true)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Adds a new protector to a directory
    pub fn add_protector(&self, ptype: ProtectorOpts, pass: &[u8], newpass: &[u8]) -> Result<Option<ProtectorId>> {
        // TODO: Allow selecting one specific protector. This tries
        // all protectors until one can be unlocked with pass
        for ProtectedPolicyKey { protector_id: _, protector, policy_key } in &self.protectors {
            if let Some(master_key) = protector.unwrap_policy_key(policy_key, pass) {
                // Generate a protector and use it to wrap the master key
                let p = ProtectedPolicyKey::new(ptype, master_key, newpass)?;
                let protid = p.protector_id.clone();

                // Store the new protector and policy
                keystore::add_protector(&p.protector_id, &p.protector, false)?;
                keystore::add_protector_to_policy(&self.policy.keyid, p)?;
                return Ok(Some(protid))
            }
        }

        Ok(None)
    }

    /// Remove a protector from a directory.
    /// Note: this will remove the protector even if it's the only one left.
    pub fn remove_protector(&self, id: &ProtectorId) -> Result<bool> {
        for ProtectedPolicyKey { protector_id, .. } in &self.protectors {
            if protector_id == id {
                if keystore::remove_protector_from_policy(&self.policy.keyid, protector_id)? {
                    // TODO: add an option to make this conditional
                    keystore::remove_protector_if_unused(protector_id)?;
                    return Ok(true);
                }
                return Ok(false);
            }
        }

        Ok(false)
    }
}


/// Encrypts a directory
pub fn encrypt_dir(path: &Path, password: &[u8]) -> Result<PolicyKeyId> {
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

    // Generate a protector and use it to wrap the master key
    let k = ProtectedPolicyKey::new(ProtectorOpts::Password, master_key, password)?;

    // Store the new protector and policy
    keystore::add_protector(&k.protector_id, &k.protector, false)?;
    keystore::add_protector_to_policy(&keyid, k)?;
    Ok(keyid)
}

// TODO: temporary function, used by the import-master-key command
pub fn import_policy_key(master_key: fscrypt::PolicyKey, password: &[u8]) -> Result<()> {
    let keyid = master_key.get_id();

    if ! keystore::get_protectors_for_policy(&keyid)?.is_empty() {
        bail!("This key has already been imported");
    }

    // Generate a protector and use it to wrap the master key
    let k = ProtectedPolicyKey::new(ProtectorOpts::Password, master_key, password)?;

    // Store the new protector and policy
    keystore::add_protector(&k.protector_id, &k.protector, false)?;
    keystore::add_protector_to_policy(&keyid, k)?;
    Ok(())
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
