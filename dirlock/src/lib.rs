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
    PolicyKey,
    WrappedPolicyKey,
};
use protector::{
    ProtectedPolicyKey,
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
    pub fn get_master_key(&self, pass: &[u8], protector_id: Option<&ProtectorId>) -> Result<Option<PolicyKey>> {
        for p in &self.protectors {
            if let Some(id) = protector_id {
                if *id != p.protector.id {
                    continue;
                }
            }
            if ! p.protector.is_available() {
                continue;
            }
            if let Some(k) = p.protector.unwrap_policy_key(&p.policy_key, pass)? {
                return Ok(Some(k));
            }
        }
        Ok(None)
    }

    /// Unlocks a directory with the given password
    ///
    /// Returns true on success, false if the password is incorrect.
    /// This call also succeeds if the directory is already unlocked
    /// as long as the password is correct.
    pub fn unlock(&self, password: &[u8], protector_id: &ProtectorId) -> Result<bool> {
        if let Some(master_key) = self.get_master_key(password, Some(protector_id))? {
            if let Err(e) = fscrypt::add_key(&self.path, master_key.secret()) {
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

    /// Finds a protector using its ID
    pub fn get_protector_by_id(&self, id: &ProtectorId) -> Result<&Protector> {
        self.protectors.iter()
            .find_map(|p| if &p.protector.id == id { Some(&p.protector) } else { None })
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

    // Generate a master key and encrypt the directory with it
    // FIXME: Write the key to disk before encrypting the directory
    let master_key = PolicyKey::new_random();
    let keyid = fscrypt::add_key(path, master_key.secret())?;
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
pub fn get_protector_by_id(id: ProtectorId) -> Result<Protector> {
    let Some(prot) = keystore::load_protector(id)? else {
        bail!("Protector not found");
    };
    Ok(prot)
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
