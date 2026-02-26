/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

pub(crate) mod config;
pub(crate) mod cloner;
pub mod convert;
pub(crate) mod crypto;
pub mod fscrypt;
pub(crate) mod kdf;
mod keystore;
pub mod modhex;
pub mod policy;
pub mod protector;
pub mod recovery;
pub mod util;

use anyhow::{anyhow, bail, Result};
use keystore::Keystore;
use fscrypt::{KeyStatus, Policy, PolicyKeyId, RemoveKeyUsers, RemovalStatusFlags};
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
use recovery::RecoveryKey;
use std::path::{Path, PathBuf};

/// The encryption status of an existing directory
pub enum DirStatus {
    Unencrypted,
    Encrypted(EncryptedDir),
    KeyMissing(PolicyKeyId),
    Unsupported,
}

impl DirStatus {
    /// A stringified version of the enum value, in lower case and without spaces
    pub fn name(&self) -> &'static str {
        use DirStatus::*;
        use KeyStatus::*;
        match &self {
            Unencrypted => "unencrypted",
            Unsupported => "unsupported",
            KeyMissing(_) => "key-missing",
            Encrypted(d) => match d.key_status {
                Absent => "locked",
                Present => "unlocked",
                IncompletelyRemoved => "partially-locked",
            }
        }
    }

    /// The error message to display when the status of the directory
    /// is unexpected for a given operation.
    pub fn error_msg(&self) -> String {
        use DirStatus::*;
        match self {
            Encrypted(_) => "Directory already encrypted".into(),
            Unencrypted  => "Directory not encrypted".into(),
            Unsupported  => "Directory using an unsupported encryption mechanism".into(),
            KeyMissing(id)   => format!("Directory encrypted, key missing ({id})"),
        }
    }
}

/// Expected lock state when opening an encrypted directory with [`EncryptedDir::open`]
pub enum LockState {
    Any,
    Locked,
    Unlocked,
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
    pub key_status: KeyStatus,
    pub key_flags: fscrypt::KeyStatusFlags,
    pub protectors: Vec<ProtectedPolicyKey>,
    pub unusable: Vec<UnusableProtector>,
    pub recovery: Option<WrappedPolicyKey>,
}

/// Gets the encryption status of a directory.
///
/// If [`DirStatus::Encrypted`] is returned it implies that:
/// 1. The directory is encrypted with a supported fscrypt policy (v2).
/// 2. The keystore contains a protector for that policy.
pub fn open_dir(path: &Path, ks: &Keystore) -> Result<DirStatus> {
    let policy = match fscrypt::get_policy(path).
        map_err(|e| anyhow!("Failed to get encryption policy: {e}"))? {
        Some(Policy::V2(p)) => p,
        Some(_) => return Ok(DirStatus::Unsupported),
        None    => return Ok(DirStatus::Unencrypted),
    };

    let recovery = WrappedPolicyKey::load_xattr(path);

    let (protectors, unusable) = ks.get_protectors_for_policy(&policy.keyid)?;
    if protectors.is_empty() && recovery.is_none() {
        return Ok(DirStatus::KeyMissing(policy.keyid));
    };

    let (key_status, key_flags) = fscrypt::get_key_status(path, &policy.keyid)
        .map_err(|e| anyhow!("Failed to get key status: {e}"))?;

    Ok(DirStatus::Encrypted(EncryptedDir { path: path.into(), policy, key_status, key_flags, protectors, unusable, recovery }))
}

/// Convenience function to call `open_dir` on a user's home directory
///
/// Returns None if the user does not exist.
pub fn open_home(user: &str, ks: &Keystore) -> Result<Option<DirStatus>> {
    if let Some(dir) = util::get_homedir(user)? {
        let dir = open_dir(&dir, ks)?;
        Ok(Some(dir))
    } else {
        Ok(None)
    }
}

/// Return an error if the directory is encrypted or uses an unsupported mechanism.
pub fn ensure_unencrypted(path: &Path, ks: &Keystore) -> Result<()> {
    match open_dir(path, ks)? {
        DirStatus::Unencrypted => Ok(()),
        x => bail!("{}", x.error_msg()),
    }
}

impl EncryptedDir {
    /// Open an encrypted directory with an expected [`LockState`].
    /// Return an error if the directory is not encrypted or in an unexpected state.
    /// [`KeyStatus::IncompletelyRemoved`] never returns an error, it's considered
    /// locked or unlocked if that's what we're expecting.
    pub fn open(path: &Path, ks: &Keystore, state: LockState) -> Result<Self> {
        let dir = match open_dir(path, ks)? {
            DirStatus::Encrypted(d) => d,
            e => bail!("{}", e.error_msg()),
        };
        match (state, &dir.key_status) {
            (LockState::Locked, KeyStatus::Present) => bail!("Already unlocked"),
            (LockState::Unlocked, KeyStatus::Absent) => bail!("Already locked"),
            _ => Ok(dir),
        }
    }

    /// Get a directory's master encryption key using the password of one of its protectors
    pub fn get_master_key(&self, pass: &[u8], protector_id: &ProtectorId) -> Result<Option<PolicyKey>> {
        let p = self.get_protected_policy_key(protector_id)?;
        if let Some(k) = p.protector.unwrap_policy_key(&p.policy_key, pass)? {
            return Ok(Some(k));
        }
        Ok(None)
    }

    /// Get a directory's master encryption key using a protector key
    fn get_master_key_with_protkey(&self, protector_key: &ProtectorKey) -> Result<Option<PolicyKey>> {
        let protector_id = protector_key.get_id();
        let p = self.get_protected_policy_key(&protector_id)?;
        if let Some(k) = p.policy_key.unwrap_key(protector_key) {
            return Ok(Some(k));
        }
        Ok(None)
    }

    /// Add a recovery key to an encrypted directory (deleting the previous one).
    /// `protector_key` is used to unlock the master encryption key.
    /// Returns a new, random [`RecoveryKey`].
    pub fn add_recovery_key(&mut self, protector_key: &ProtectorKey) -> Result<RecoveryKey> {
        let Ok(Some(master_key)) = self.get_master_key_with_protkey(protector_key) else {
            bail!("Cannot unlock directory with the protector key");
        };
        let recovery_key = RecoveryKey::new_random();
        let wrapped_key = WrappedPolicyKey::new(master_key, recovery_key.protector_key());
        wrapped_key.write_xattr(&self.path)?;
        self.recovery = Some(wrapped_key);
        Ok(recovery_key)
    }

    /// Remove a recovery key from an encrypted directory
    pub fn remove_recovery_key(&mut self) -> Result<()> {
        if self.recovery.is_none() {
            bail!("This directory does not have a recovery key");
        };
        WrappedPolicyKey::remove_xattr(&self.path)?;
        self.recovery = None;
        Ok(())
    }

    /// Unlocks a directory with the given password
    ///
    /// Returns true on success, false if the password is incorrect.
    /// This call also succeeds if the directory is already unlocked
    /// as long as the password is correct.
    pub fn unlock(&self, password: &[u8], protector_id: &ProtectorId) -> Result<bool> {
        // If password looks like a recovery key, try it first
        if self.unlock_with_recovery_key(password).unwrap_or(true) {
            return Ok(true);
        }
        let p = self.get_protected_policy_key(protector_id)?;
        if let Some(k) = p.protector.unwrap_policy_key(&p.policy_key, password)? {
            unlock_dir_with_key(&self.path, &k)?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Unlocks a directory using the protector key directly
    pub fn unlock_with_protkey(&self, protector_key: &ProtectorKey) -> Result<bool> {
        let protector_id = protector_key.get_id();
        let p = self.get_protected_policy_key(&protector_id)
            .map(|p| &p.policy_key)
            // If there is no protector with this key's ID then maybe
            // it is a recovery key.
            .or_else(|e| self.recovery.as_ref().ok_or(e))?;
        if let Some(k) = p.unwrap_key(protector_key) {
            unlock_dir_with_key(&self.path, &k)?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Unlocks a directory using a [`RecoveryKey`].
    /// `pass` contains the bytes of the modhex-encoded recovery key.
    pub fn unlock_with_recovery_key(&self, pass: &[u8]) -> Result<bool> {
        let Some(recovery) = &self.recovery else {
            return Ok(false);
        };
        let Ok(key) = RecoveryKey::from_ascii_bytes(pass) else {
            return Ok(false);
        };
        let Some(master_key) = recovery.unwrap_key(key.protector_key()) else {
            return Ok(false);
        };
        unlock_dir_with_key(&self.path, &master_key)?;
        Ok(true)
    }

    /// Locks a directory
    pub fn lock(&self, user: RemoveKeyUsers) -> Result<RemovalStatusFlags> {
        if self.key_status == KeyStatus::Absent {
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

/// Unlocks a directory with a encryption key.
pub(crate) fn unlock_dir_with_key(dir: &Path, master_key: &PolicyKey) -> Result<()> {
    if let Err(e) = fscrypt::add_key(dir, master_key.secret()) {
        bail!("Unable to unlock directory with master key: {}", e);
    }
    Ok(())
}

/// Encrypts a directory with an existing encryption key.
pub fn encrypt_dir_with_key(path: &Path, master_key: &PolicyKey) -> Result<()> {
    let keyid = master_key.get_id();
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
}

/// Encrypts a directory generating a new master encryption key.
/// The key is stored to disk using the given [`Protector`].
pub fn encrypt_dir(path: &Path, protector: &Protector, protector_key: ProtectorKey,
                   ks: &Keystore) -> Result<PolicyKeyId> {
    ensure_unencrypted(path, ks)?;
    if ! util::dir_is_empty(path)? {
        bail!("Cannot encrypt a non-empty directory");
    }

    // Generate a master key
    let (policy, master_key) = create_policy_data(protector, &protector_key,
                                                  CreateOpts::CreateAndSave, ks)?;
    // Add the key to the kernel and encrypt the directory
    encrypt_dir_with_key(path, &master_key)
        .map_err(|e| {
            let user = RemoveKeyUsers::CurrentUser;
            let _ = fscrypt::remove_key(path, &policy.id, user);
            let _ = ks.remove_policy(&policy.id);
            anyhow!("Failed to encrypt directory: {e}")
        })?;

    Ok(policy.id)
}

/// Whether to save a protector or policy when creating it
pub enum CreateOpts {
    CreateAndSave,
    CreateOnly,
}

/// Create a new protector (without saving it to disk)
pub fn create_protector(opts: ProtectorOpts, pass: &[u8],
                        create: CreateOpts, ks: &Keystore) -> Result<(Protector, ProtectorKey)> {
    let protector_key = ProtectorKey::new_random();
    let protector = Protector::new(opts, protector_key.clone(), pass)?;
    if matches!(create, CreateOpts::CreateAndSave) {
        ks.save_protector(&protector)?;
    }
    Ok((protector, protector_key))
}

/// Change the password of `protector` from `pass` to `newpass` and save it to disk
pub fn update_protector_password(protector: &mut Protector, pass: &[u8],
                                 newpass: &[u8], ks: &Keystore) -> Result<bool> {
    if let Some(protector_key) = protector.unwrap_key(pass)? {
        wrap_and_save_protector_key(protector, protector_key, newpass, ks)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Update `protector` (wrapping its key again with a new password) and save it to disk
pub fn wrap_and_save_protector_key(protector: &mut Protector, key: ProtectorKey,
                                   newpass: &[u8], ks: &Keystore) -> Result<()> {
    protector.wrap_key(key, newpass)?;
    ks.save_protector(protector)
}

/// Create a new policy with a freshly generated key, returning both the policy and the key.
pub fn create_policy_data(protector: &Protector, protector_key: &ProtectorKey,
                          create: CreateOpts, ks: &Keystore) -> Result<(PolicyData, PolicyKey)> {
    let master_key = PolicyKey::new_random();
    let mut policy = PolicyData::new(master_key.get_id(), protector.uid, protector.gid);
    policy.add_protector(protector_key, master_key.clone())?;
    if matches!(create, CreateOpts::CreateAndSave) {
        ks.save_policy_data(&policy)?;
    }
    Ok((policy, master_key))
}

/// Add a protector to an policy, loading it from disk if it exists.
pub fn protect_policy_key(protector: &Protector, protector_key: &ProtectorKey,
                          master_key: PolicyKey, ks: &Keystore) -> Result<()> {
    let id = master_key.get_id();
    let mut policy = ks.load_or_create_policy_data(&id, protector.uid, protector.gid)?;
    policy.add_protector(protector_key, master_key)?;
    ks.save_policy_data(&policy)?;
    Ok(())
}

/// Get the default [`Keystore`]
pub fn keystore() -> &'static keystore::Keystore {
    Keystore::default()
}

/// Initialize the dirlock library
pub fn init() -> Result<()> {
    use config::Config;
    use std::sync::Once;
    static DIRLOCK_INIT: Once = Once::new();
    DIRLOCK_INIT.call_once(|| {
        // Disable log messages from the TPM2 library
        std::env::set_var("TSS2_LOG", "all+NONE");
    });
    Config::check()?;
    // Make sure that /run exists
    let rt_dir = Config::runtime_dir();
    if ! rt_dir.is_dir() {
        std::fs::create_dir(rt_dir)
            .map_err(|e| anyhow!("Error creating runtime dir: {e}"))?;
    }
    Ok(())
}
