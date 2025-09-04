/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#[cfg(feature = "tpm2")]
pub(crate) mod config;

pub mod convert;
pub(crate) mod crypto;
pub mod fscrypt;
pub(crate) mod kdf;
pub mod keystore;
pub mod policy;
pub mod protector;
pub mod util;

use anyhow::{anyhow, bail, Result};
use fscrypt::{Policy, PolicyKeyId, RemoveKeyUsers, RemovalStatusFlags};
use policy::{
    PolicyData,
    PolicyKey,
    WrappedPolicyKey,
};
use protector::{
    Protector,
    ProtectorId,
    ProtectorKey,
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

/// A wrapped [`PolicyKey`] together with a [`Protector`] that can unwrap it
pub struct ProtectedPolicyKey {
    pub protector: Protector,
    pub policy_key: WrappedPolicyKey,
}

/// A [`ProtectorId`] that could not be loaded from disk
pub struct UnusableProtector {
    pub id: ProtectorId,
    pub err: std::io::Error,
}

/// Encryption data (policy, key status) of a given directory
pub struct EncryptedDir {
    pub path: PathBuf,
    pub policy: fscrypt::PolicyV2,
    pub key_status: fscrypt::KeyStatus,
    pub key_flags: fscrypt::KeyStatusFlags,
    pub protectors: Vec<ProtectedPolicyKey>,
    pub unusable: Vec<UnusableProtector>,
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

    let (protectors, unusable) = keystore::get_protectors_for_policy(&policy.keyid)?;
    if protectors.is_empty() {
        return Ok(DirStatus::KeyMissing);
    };

    let (key_status, key_flags) = fscrypt::get_key_status(path, &policy.keyid)
        .map_err(|e| anyhow!("Failed to get key status: {e}"))?;

    Ok(DirStatus::Encrypted(EncryptedDir { path: path.into(), policy, key_status, key_flags, protectors, unusable }))
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
    pub fn get_master_key(&self, pass: &[u8], protector_id: &ProtectorId) -> Result<Option<PolicyKey>> {
        let p = self.get_protected_policy_key(protector_id)?;
        if let Some(k) = p.protector.unwrap_policy_key(&p.policy_key, pass)? {
            return Ok(Some(k));
        }
        Ok(None)
    }

    /// Unlocks a directory with the given password
    ///
    /// Returns true on success, false if the password is incorrect.
    /// This call also succeeds if the directory is already unlocked
    /// as long as the password is correct.
    pub fn unlock(&self, password: &[u8], protector_id: &ProtectorId) -> Result<bool> {
        let p = self.get_protected_policy_key(protector_id)?;
        if let Some(k) = p.protector.unwrap_policy_key(&p.policy_key, password)? {
            if let Err(e) = fscrypt::add_key(&self.path, k.secret()) {
                bail!("Unable to unlock directory with master key: {}", e);
            }
            return Ok(true);
        }

        Ok(false)
    }

    /// Unlocks a directory using the protector key directly
    pub fn unlock_with_protkey(&self, protector_key: &ProtectorKey) -> Result<bool> {
        let protector_id = protector_key.get_id();
        let p = self.get_protected_policy_key(&protector_id)?;
        if let Some(k) = p.policy_key.unwrap_key(protector_key) {
            if let Err(e) = fscrypt::add_key(&self.path, k.secret()) {
                bail!("Unable to unlock directory with master key: {}", e);
            }
            return Ok(true);
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

    /// Finds a protector using its ID
    pub fn get_protector_by_id(&self, id: &ProtectorId) -> Result<&Protector> {
        self.get_protected_policy_key(id).map(|p| &p.protector)
    }

    /// Finds a protected policy key using its ID. This is an internal helper function
    fn get_protected_policy_key(&self, id: &ProtectorId) -> Result<&ProtectedPolicyKey> {
        self.protectors.iter()
            .find(|p| &p.protector.id == id)
            .ok_or_else(|| anyhow!("No protector found with that ID in the directory"))
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

    // Generate a master key and wrap it with the protector
    let master_key = PolicyKey::new_random();
    let wrapped_policy_key = WrappedPolicyKey::new(master_key.clone(), &protector_key);

    // Save the (protector-wrapped) new master key to disk
    let keyid = master_key.get_id();
    let protector_id = protector_key.get_id();
    keystore::add_protector_to_policy(&keyid, protector_id, wrapped_policy_key)?;

    // Add the key to the kernel and encrypt the directory
    fscrypt::add_key(path, master_key.secret())
        .and_then(|id| {
            if id == keyid {
                fscrypt::set_policy(path, &id)
            } else {
                // This should never happen, it means that the kernel and
                // PolicyKey::get_id() use a different algorithm.
                Err(anyhow!("fscrypt::add_key() returned an unexpected ID!!"))
            }
        })
        .map_err(|e| {
            let user = RemoveKeyUsers::CurrentUser;
            let _ = fscrypt::remove_key(path, &keyid, user);
            let _ = keystore::remove_policy(&keyid);
            anyhow!("Failed to encrypt directory: {e}")
        })?;

    Ok(keyid)
}

/// Get an existing protector
pub fn get_protector_by_id(id: ProtectorId) -> std::io::Result<Protector> {
    keystore::load_protector(id)
}

/// Get an existing policy
pub fn get_policy_by_id(id: &PolicyKeyId) -> std::io::Result<PolicyData> {
    keystore::load_policy_data(id)
}

/// Whether to save a protector when creating it
pub enum CreateProtector {
    CreateAndSave,
    CreateOnly,
}

/// Create a new protector (without saving it to disk)
pub fn create_protector(opts: ProtectorOpts, pass: &[u8], create: CreateProtector) -> Result<(Protector, ProtectorKey)> {
    let protector_key = ProtectorKey::new_random();
    let protector = Protector::new(opts, protector_key.clone(), pass)?;
    if matches!(create, CreateProtector::CreateAndSave) {
        keystore::save_protector(&protector, keystore::SaveProtector::AddNew)?;
    }
    Ok((protector, protector_key))
}

/// Change the password of `protector` from `pass` to `newpass` and save it to disk
pub fn update_protector_password(protector: &mut Protector, pass: &[u8], newpass: &[u8]) -> Result<bool> {
    if let Some(protector_key) = protector.unwrap_key(pass)? {
        wrap_and_save_protector_key(protector, protector_key, newpass)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Wrap `policy_key` using `protector_key` and store the result on disk
pub fn wrap_and_save_policy_key(protector_key: ProtectorKey, policy_key: PolicyKey) -> Result<()> {
    let protector_id = protector_key.get_id();
    let policy_id = policy_key.get_id();
    let wrapped_policy_key = WrappedPolicyKey::new(policy_key, &protector_key);
    keystore::add_protector_to_policy(&policy_id, protector_id, wrapped_policy_key)
}

/// Update `protector` (wrapping its key again with a new password) and save it to disk
pub fn wrap_and_save_protector_key(protector: &mut Protector, key: ProtectorKey, newpass: &[u8]) -> Result<()> {
    protector.wrap_key(key, newpass)?;
    keystore::save_protector(protector, keystore::SaveProtector::UpdateExisting)
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
