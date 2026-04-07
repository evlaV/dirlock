/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, ensure, Result};
use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};
use std::cell::Cell;
use std::collections::{
    HashMap,
    hash_map::Entry,
};
use std::path::Path;

use crate::{
    fscrypt::{
        self,
        PolicyKeyId,
    },
    protector::{
        ProtectorId,
        ProtectorKey,
    },
    crypto::{
        AesIv,
        Hmac,
    },
};

const POLICY_KEY_LEN: usize = fscrypt::MAX_KEY_SIZE;

/// A raw master encryption key, meant to be added to the kernel for a specific filesystem.
#[derive(zeroize::ZeroizeOnDrop, Clone)]
pub struct PolicyKey(Box<[u8; POLICY_KEY_LEN]>);

impl From<&[u8; POLICY_KEY_LEN]> for PolicyKey {
    fn from(src: &[u8; POLICY_KEY_LEN]) -> Self {
        PolicyKey(Box::new(*src))
    }
}

impl Default for PolicyKey {
    /// Returns a key containing only zeroes.
    fn default() -> Self {
        Self(Box::new([0u8; POLICY_KEY_LEN]))
    }
}

impl PolicyKey {
    /// Return a reference to the data
    pub fn secret(&self) -> &[u8; POLICY_KEY_LEN] {
        self.0.as_ref()
    }

    /// Return a mutable reference to the data
    pub fn secret_mut(&mut self) -> &mut [u8; POLICY_KEY_LEN] {
        self.0.as_mut()
    }

    /// Generates a new, random key
    pub fn new_random() -> Self {
        let mut key = PolicyKey::default();
        OsRng.fill_bytes(key.secret_mut());
        key
    }

    /// Generates a new key, reading the data from a given source
    pub fn new_from_reader(r: &mut impl std::io::Read) -> Result<Self> {
        let mut key = PolicyKey::default();
        let len = r.read(key.secret_mut())?;
        ensure!(len == POLICY_KEY_LEN, "Expected {POLICY_KEY_LEN} bytes when reading key, got {len}");
        Ok(key)
    }

    /// Calculates the fscrypt v2 key ID for this key
    pub fn get_id(&self) -> PolicyKeyId {
        PolicyKeyId::new_from_key(self.secret())
    }
}


/// Policy data as stored on disk. It contains several instances of
/// the same fscrypt [`PolicyKey`] wrapped with different protectors.
pub struct PolicyData {
    pub id: PolicyKeyId,
    pub keys: HashMap<ProtectorId, WrappedPolicyKey>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub(crate) is_new: Cell<bool>,
}

impl PolicyData {
    /// Creates a new, empty [`PolicyData`] object.
    pub fn new(id: PolicyKeyId, uid: Option<u32>, gid: Option<u32>) -> Self {
        PolicyData { id, uid, gid, keys: Default::default(), is_new: Cell::new(true) }
    }

    /// Creates a [`PolicyData`] object from existing data (loaded from disk).
    pub fn from_existing(id: PolicyKeyId, keys: HashMap<ProtectorId, WrappedPolicyKey>,
                         uid: Option<u32>, gid: Option<u32>) -> Self {
        PolicyData { id, keys, uid, gid, is_new: Cell::new(false) }
    }

    /// Adds a new a [`PolicyKey`] to the policy, wrapping it with a [`ProtectorKey`].
    /// Fails if there's already a key with that protector.
    pub fn add_protector(&mut self, protector_key: &ProtectorKey, policy_key: PolicyKey) -> Result<()> {
        let wrapped_key = WrappedPolicyKey::new(policy_key, protector_key);
        let protector_id = protector_key.get_id();
        match self.keys.entry(protector_id) {
            Entry::Vacant(e) => _ = e.insert(wrapped_key),
            Entry::Occupied(e) => bail!("Policy {} already protected with protector {}", self.id, e.key()),
        }
        Ok(())
    }

    /// Removes the key wrapped with the given [`ProtectorId`].
    pub fn remove_protector(&mut self, id: &ProtectorId) -> Result<()> {
        if self.keys.remove(id).is_none() {
            bail!("Protector {id} is not used in policy {}", self.id);
        }
        Ok(())
    }
}


#[serde_as]
#[derive(Serialize, Deserialize)]
/// A [`PolicyKey`] wrapped with an AES key.
pub struct WrappedPolicyKey {
    #[serde_as(as = "Base64")]
    wrapped_key: [u8; POLICY_KEY_LEN],
    iv: AesIv,
    hmac: Hmac,
}

impl WrappedPolicyKey {
    const RECOVERY_KEY_XATTR: &str = "trusted.dirlock";

    /// Creates a new [`WrappedPolicyKey`] that wraps a [`PolicyKey`] with a [`ProtectorKey`]
    pub fn new(mut raw_key: PolicyKey, protector_key: &ProtectorKey) -> Self {
        let iv = AesIv::new_random();
        let hmac = protector_key.key().encrypt(&iv, raw_key.secret_mut());
        WrappedPolicyKey{ wrapped_key: *raw_key.secret(), iv, hmac }
    }

    /// Load a [`WrappedPolicyKey`] to be used for recovery from `path`
    pub fn load_xattr(path: &Path) -> Option<Self> {
        use base64::prelude::*;

        // Read the xattr containing the wrapped encryption key
        let attr = match xattr::get(path, Self::RECOVERY_KEY_XATTR) {
            Ok(Some(v)) => String::from_utf8_lossy(&v).into_owned(),
            _ => return None,
        };
        let values: Vec<&str> = attr.split(':').collect();

        // Check the version and number of fields
        if values[0] != "1" || values.len() != 4 {
            return None;
        }

        // Parse the wrapped master key
        let mut wrapped_key = [0u8; POLICY_KEY_LEN];
        match BASE64_STANDARD.decode_slice(values[1], &mut wrapped_key) {
            Ok(len) if len == POLICY_KEY_LEN => (),
            _ => return None,
        }

        // Parse the IV
        let mut iv = AesIv::default();
        match BASE64_STANDARD.decode_slice(values[2], &mut iv.0) {
            Ok(len) if len == iv.0.len() => (),
            _ => return None,
        }

        // Parse the HMAC
        let mut hmac = Hmac::default();
        match BASE64_STANDARD.decode_slice(values[3], &mut hmac.0) {
            Ok(len) if len == hmac.0.len() => (),
            _ => return None,
        }

        Some(WrappedPolicyKey { wrapped_key, iv, hmac })
    }

    /// Write this [`WrappedPolicyKey`] to an xattr in `path` so it can be used for recovery
    pub fn write_xattr(&self, path: &Path) -> Result<()> {
        use base64::prelude::*;

        let value = [
            "1", // Entry version
            &BASE64_STANDARD.encode(self.wrapped_key),
            &BASE64_STANDARD.encode(self.iv.0),
            &BASE64_STANDARD.encode(self.hmac.0),
        ].join(":");

        xattr::set(path, Self::RECOVERY_KEY_XATTR, value.as_bytes())?;

        Ok(())
    }

    /// Remove the recovery key xattr from `path`
    pub fn remove_xattr(path: &Path) -> Result<()> {
        xattr::remove(path, Self::RECOVERY_KEY_XATTR)?;
        Ok(())
    }

    /// Unwraps a [`PolicyKey`] with a [`ProtectorKey`]
    pub fn unwrap_key(&self, protector_key: &ProtectorKey) -> Option<PolicyKey> {
        let mut raw_key = PolicyKey::from(&self.wrapped_key);
        if protector_key.key().decrypt(&self.iv, &self.hmac, raw_key.secret_mut()) {
            Some(raw_key)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_wrapped_policy_key() -> Result<()> {
        for _ in 0..5 {
            // Generate random keys
            let mut protkey = ProtectorKey::new_random();
            let polkey = PolicyKey::new_random();

            // Wrap the policy key with the protector key
            let wrapped = WrappedPolicyKey::new(polkey.clone(), &protkey);

            // Unwrap it and check the results
            let result = wrapped.unwrap_key(&protkey);
            assert!(result.is_some());
            assert_eq!(result.unwrap().secret(), polkey.secret());

            // Modify the protector key and verify that unwrapping now fails
            protkey.secret_mut()[0] ^= 1;
            let result = wrapped.unwrap_key(&protkey);
            assert!(result.is_none());
        }

        Ok(())
    }

    #[test]
    fn test_xattr_round_trip() -> Result<()> {
        let tmpdir = TempDir::new("policy-xattr")?;
        let dir = tmpdir.path();

        let protkey = ProtectorKey::new_random();
        let polkey = PolicyKey::new_random();
        let wrapped = WrappedPolicyKey::new(polkey.clone(), &protkey);

        // Write the wrapped key to an xattr and load it back
        wrapped.write_xattr(dir)?;
        let loaded = WrappedPolicyKey::load_xattr(dir)
            .expect("Failed to load xattr");

        // Verify that the loaded key is identical to the written one
        assert_eq!(loaded.wrapped_key, wrapped.wrapped_key);
        assert_eq!(loaded.iv.0, wrapped.iv.0);
        assert_eq!(loaded.hmac.0, wrapped.hmac.0);

        // Unwrap the loaded key and verify that it matches the original
        let result = loaded.unwrap_key(&protkey);
        assert!(result.is_some(), "Failed to unwrap loaded key");
        assert_eq!(result.unwrap().secret(), polkey.secret());

        Ok(())
    }

    #[test]
    fn test_xattr_overwrite() -> Result<()> {
        let tmpdir = TempDir::new("policy-xattr")?;
        let dir = tmpdir.path();

        // Create two different policy keys
        let protkey = ProtectorKey::new_random();
        let polkey1 = PolicyKey::new_random();
        let polkey2 = {
            let mut key = polkey1.clone();
            key.secret_mut()[0] ^= 1;
            key
        };

        // Write the first key
        let wrapped1 = WrappedPolicyKey::new(polkey1.clone(), &protkey);
        wrapped1.write_xattr(dir)?;

        // Overwrite with the second key
        let wrapped2 = WrappedPolicyKey::new(polkey2.clone(), &protkey);
        wrapped2.write_xattr(dir)?;

        // Loading should return the second key
        let loaded = WrappedPolicyKey::load_xattr(dir).expect("Failed to load xattr");
        assert_eq!(loaded.wrapped_key, wrapped2.wrapped_key);
        assert_eq!(loaded.iv.0, wrapped2.iv.0);
        assert_eq!(loaded.hmac.0, wrapped2.hmac.0);
        let result = loaded.unwrap_key(&protkey).expect("Failed to unwrap loaded key");
        assert_eq!(result.secret(), polkey2.secret());

        Ok(())
    }

    #[test]
    fn test_xattr_remove() -> Result<()> {
        let tmpdir = TempDir::new("policy-xattr")?;
        let dir = tmpdir.path();

        let protkey = ProtectorKey::new_random();
        let polkey = PolicyKey::new_random();
        let wrapped = WrappedPolicyKey::new(polkey, &protkey);

        // Write and then remove the xattr
        wrapped.write_xattr(dir)?;
        WrappedPolicyKey::remove_xattr(dir)?;

        // Loading should return None
        assert!(WrappedPolicyKey::load_xattr(dir).is_none());

        Ok(())
    }

    #[test]
    fn test_xattr_load_empty() {
        let tmpdir = TempDir::new("policy-xattr").unwrap();

        // Loading from a directory with no xattrs should return None
        assert!(WrappedPolicyKey::load_xattr(tmpdir.path()).is_none());
    }

    #[test]
    fn test_xattr_remove_nonexistent() {
        let tmpdir = TempDir::new("policy-xattr").unwrap();

        // Removing from a directory with no recovery xattr should fail
        assert!(WrappedPolicyKey::remove_xattr(tmpdir.path()).is_err());
    }
}
