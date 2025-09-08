/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, Context, Result};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs,
    io::ErrorKind,
    io::Write,
    path::Path,
    path::PathBuf,
    sync::OnceLock,
};
use crate::{
    ProtectedPolicyKey,
    UnusableProtector,
    config::Config,
    fscrypt::PolicyKeyId,
    policy::PolicyData,
    protector::{
        Protector,
        ProtectorId,
    },
    util::SafeFile,
};

pub struct Keystore {
    policy_dir: PathBuf,
    protector_dir: PathBuf,
}

impl Keystore {
    pub fn from_path(dir: &Path) -> Self {
        let base_dir = PathBuf::from(dir);
        let policy_dir = base_dir.join("policies");
        let protector_dir = base_dir.join("protectors");
        Keystore { policy_dir, protector_dir }
    }

    pub fn default() -> &'static Self {
        static DEFAULT_KEYSTORE : OnceLock<Keystore> = OnceLock::new();
        DEFAULT_KEYSTORE.get_or_init(|| {
            Keystore::from_path(Config::keystore_dir())
        })
    }

    /// Return an iterator to the IDs of all policy keys available in the key store
    pub fn policy_key_ids(&self) -> std::io::Result<Vec<PolicyKeyId>> {
        fn id_from_entry(d: fs::DirEntry) -> Option<PolicyKeyId> {
            let path = d.path();
            if let Some(path_str) = path.file_name().and_then(OsStr::to_str) {
                path_str.parse::<PolicyKeyId>().ok()
            } else {
                None
            }
        }

        match fs::read_dir(&self.policy_dir) {
            Ok(d) => Ok(d.flatten().filter_map(id_from_entry).collect()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(vec![]),
            Err(e) => Err(e),
        }
    }


    /// Return an iterator to the IDs of all protectors available in the key store
    pub fn protector_ids(&self) -> std::io::Result<Vec<ProtectorId>> {
        fn id_from_entry(d: fs::DirEntry) -> Option<ProtectorId> {
            let path = d.path();
            if let Some(path_str) = path.file_name().and_then(OsStr::to_str) {
                path_str.parse::<ProtectorId>().ok()
            } else {
                None
            }
        }

        match fs::read_dir(&self.protector_dir) {
            Ok(d) => Ok(d.flatten().filter_map(id_from_entry).collect()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(vec![]),
            Err(e) => Err(e),
        }
    }

    /// Load a protector from disk
    pub fn load_protector(&self, id: ProtectorId) -> std::io::Result<Protector> {
        let dir = &self.protector_dir;
        let protector_file = dir.join(id.to_string());
        if !dir.exists() || !protector_file.exists() {
            return Err(std::io::Error::new(ErrorKind::NotFound, "protector not found"));
        }

        serde_json::from_reader(fs::File::open(protector_file)?)
            .map(|data| Protector::from_data(id, data))
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
    }

    /// Save a protector to disk
    pub fn save_protector(&self, prot: &Protector) -> Result<()> {
        let path = &self.protector_dir;
        fs::create_dir_all(path)
            .map_err(|e| anyhow!("Failed to create {}: {e}", path.display()))?;
        let filename = path.join(prot.id.to_string());
        match (filename.exists(), prot.is_new.get()) {
            (true, true) => bail!("Trying to overwrite an existing protector"),
            (false, false) => bail!("Trying to update a nonexistent protector"),
            _ => (),
        }
        let mut file = SafeFile::create(&filename)
            .map_err(|e| anyhow!("Failed to store protector {}: {e}", prot.id))?;
        serde_json::to_writer_pretty(&mut file, &prot.data)?;
        file.write_all(b"\n")?;
        file.commit()?;
        prot.is_new.set(false);
        Ok(())
    }

    /// Load a policy from disk
    pub fn load_policy_data(&self, id: &PolicyKeyId) -> std::io::Result<PolicyData> {
        let dir = &self.policy_dir;
        let policy_file = dir.join(id.to_string());
        if !dir.exists() || !policy_file.exists() {
            return Err(std::io::Error::new(ErrorKind::NotFound, "policy not found"));
        }

        serde_json::from_reader(fs::File::open(policy_file)?)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
            .and_then(|keys: HashMap<_,_>| {
                if keys.is_empty() {
                    Err(std::io::Error::new(ErrorKind::InvalidData, "policy contains no data"))
                } else {
                    Ok(PolicyData::from_existing(id.clone(), keys))
                }
            })
    }

    /// Load a policy from disk, or return an empty one if the file is missing
    fn load_or_create_policy_data(&self, id: &PolicyKeyId) -> std::io::Result<PolicyData> {
        match self.load_policy_data(id) {
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(PolicyData::new(id.clone())),
            x => x,
        }
    }

    /// Save a policy to disk
    pub fn save_policy_data(&self, policy: &PolicyData) -> Result<()> {
        let id = &policy.id;
        let path = &self.policy_dir;
        fs::create_dir_all(path)
            .context(format!("Failed to create {}", path.display()))?;
        let filename = path.join(id.to_string());
        match (filename.exists(), policy.is_new.get()) {
            (true, true) => bail!("Trying to overwrite existing data from policy {id}"),
            (false, false) => bail!("Trying to update nonexistent policy {id}"),
            _ => (),
        }
        if policy.keys.is_empty() {
            if filename.exists() {
                return std::fs::remove_file(filename)
                    .inspect(|_| policy.is_new.set(true))
                    .context(format!("Failed to remove data from policy {id}"));
            }
            bail!("Trying to remove nonexistent policy {id}");
        }
        let mut file = SafeFile::create(&filename)
            .context(format!("Failed to store data from policy {id}"))?;
        serde_json::to_writer_pretty(&mut file, &policy.keys)?;
        file.write_all(b"\n")?;
        file.commit()?;
        policy.is_new.set(false);
        Ok(())
    }

    /// Removes a protector if it's not being used in any policy
    pub fn remove_protector_if_unused(&self, protector_id: &ProtectorId) -> Result<bool> {
        for policy_id in self.policy_key_ids()? {
            if self.load_or_create_policy_data(&policy_id)?.keys.contains_key(protector_id) {
                return Ok(false);
            }
        }

        let filename = self.protector_dir.join(protector_id.to_string());
        if ! filename.exists() {
            bail!("Protector {protector_id} not found");
        }
        Ok(fs::remove_file(&filename).and(Ok(true))?)
    }

    /// Get all protectors that can be used to unlock the policy key identified by `id`
    pub fn get_protectors_for_policy(&self, id: &PolicyKeyId) -> std::io::Result<(Vec<ProtectedPolicyKey>, Vec<UnusableProtector>)> {
        let mut prots = vec![];
        let mut unusable = vec![];
        let policy = self.load_or_create_policy_data(id)?;
        for (protector_id, policy_key) in policy.keys {
            match self.load_protector(protector_id) {
                Ok(protector) => {
                    prots.push(ProtectedPolicyKey{ protector, policy_key });
                },
                Err(err) => {
                    unusable.push(UnusableProtector{ id: protector_id, err });
                },
            }
        }
        prots.sort_unstable_by(|a, b| a.protector.cmp(&b.protector));
        unusable.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        Ok((prots, unusable))
    }

    /// Remove an encryption policy permanently from disk
    pub fn remove_policy(&self, id: &PolicyKeyId) -> std::io::Result<()> {
        let dir = &self.policy_dir;
        let policy_file = dir.join(id.to_string());
        if !dir.exists() || !policy_file.exists() {
            return Err(ErrorKind::NotFound.into());
        }
        fs::remove_file(policy_file)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::str::FromStr;
    use tempdir::TempDir;
    use super::*;
    use crate::protector::ProtectorData;

    #[test]
    fn test_empty_keystore() -> Result<()> {
        let tmpdir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(tmpdir.path());

        // Check that the dirs are empty
        assert!(ks.policy_key_ids()?.is_empty());
        assert!(ks.protector_ids()?.is_empty());

        // Try loading a nonexistent protector
        let protid = ProtectorId::from_str("0000000000000000")?;
        let Err(err) = ks.load_protector(protid) else {
            bail!("Found unexpected protector");
        };
        assert_eq!(err.kind(), ErrorKind::NotFound);

        // Try loading a nonexistent policy
        let polid = PolicyKeyId::from_str("00000000000000000000000000000000")?;
        let Err(err) = ks.load_policy_data(&polid) else {
            bail!("Found unexpected policy");
        };
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(ks.load_or_create_policy_data(&polid)?.keys.is_empty());

        // Try removing a nonexistent policy
        let Err(err) = ks.remove_policy(&polid) else {
            bail!("Expected error removing nonexistent policy");
        };
        assert_eq!(err.kind(), ErrorKind::NotFound);

        Ok(())
    }

    #[test]
    fn test_create_protector() -> Result<()> {
        let tmpdir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(tmpdir.path());

        // This tests that the JSON serialization of a protector works as expected
        let id_str = "507e25bbfa1277f2";
        let id = ProtectorId::from_str(id_str)?;
        let json = r#"
            {
              "type": "password",
              "name": "test",
              "wrapped_key": "OGkURqRk4t9ItlrRSuT6Mg0Ur3c72OE6TvvE3Yk/HkA=",
              "iv": "7wM9e/49nm6WElpqv27luw==",
              "salt": "xT6P24w5eHBwEa39br9CJIuXKtx9y2WwLaeETWUcMQg=",
              "hmac": "bgWg3NPwaUJ6mmYlSnt8860HecOPLkHJGikYmn5F1+8=",
              "kdf": {
                "type": "pbkdf2",
                "iterations": 1
              }
            }"#;

        let data = serde_json::from_str::<ProtectorData>(json)?;
        let prot = Protector::from_data(id, data);

        // Save the protector to disk
        ks.save_protector(&prot).expect_err("Expected error saving file");
        assert!(!ks.protector_dir.join(id_str).exists());
        prot.is_new.set(true);
        ks.save_protector(&prot)?;
        assert!(ks.protector_dir.join(id_str).exists());

        // Load it again and check that it matches the previous value
        let mut prot2 = ks.load_protector(prot.id)?;
        assert_eq!(serde_json::to_value(&prot2.data)?, serde_json::to_value(&prot.data)?);

        // Compare it also to the original JSON string
        let data = serde_json::from_str::<ProtectorData>(json)?;
        assert_eq!(serde_json::to_value(&prot2.data)?, serde_json::to_value(&data)?);

        // Change the protector data and save it to disk
        match prot2.data {
            ProtectorData::Password(ref mut p) => p.name = String::from("new name"),
            _ => panic!(),
        }
        ks.save_protector(&prot2)?;

        // Load it again
        let prot3 = ks.load_protector(prot.id)?;

        // And verify that it matches the expected value
        assert_eq!(serde_json::to_value(&prot3.data)?, serde_json::to_value(&prot2.data)?);
        assert_ne!(serde_json::to_value(&prot3.data)?, serde_json::to_value(&prot.data)?);

        // Remove it from disk
        ks.remove_protector_if_unused(&prot.id)?;
        assert!(ks.load_protector(prot.id).is_err());
        assert!(!ks.protector_dir.join(id_str).exists());

        Ok(())
    }
}
