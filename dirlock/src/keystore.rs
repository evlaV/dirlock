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
    path::{Path, PathBuf},
    sync::OnceLock,
};
use crate::{
    ProtectedPolicyKey,
    UnusableProtector,
    fscrypt::PolicyKeyId,
    policy::PolicyData,
    protector::{
        Protector,
        ProtectorId,
    },
    util::SafeFile,
};

// If this variable is set use this keystore dir instead of the default one
const KEYSTORE_DIR_ENV_VAR : &str = "DIRLOCK_KEYSTORE";
const DEFAULT_KEYSTORE_DIR : &str = "/var/lib/dirlock";

struct KeystoreDirs {
    policies: PathBuf,
    protectors: PathBuf,
}

/// Get the keystore directories
fn keystore_dirs() -> &'static KeystoreDirs {
    static DIR_NAME : OnceLock<KeystoreDirs> = OnceLock::new();
    DIR_NAME.get_or_init(|| {
        let dir = std::env::var(KEYSTORE_DIR_ENV_VAR)
            .unwrap_or(String::from(DEFAULT_KEYSTORE_DIR));
        let policies = Path::new(&dir).join("policies");
        let protectors = Path::new(&dir).join("protectors");
        KeystoreDirs{ policies, protectors }
    })
}

/// Return an iterator to the IDs of all policy keys available in the key store
pub fn policy_key_ids() -> std::io::Result<Vec<PolicyKeyId>> {
    fn id_from_entry(d: fs::DirEntry) -> Option<PolicyKeyId> {
        let path = d.path();
        if let Some(path_str) = path.file_name().and_then(OsStr::to_str) {
            path_str.parse::<PolicyKeyId>().ok()
        } else {
            None
        }
    }

    let policy_dir = &keystore_dirs().policies;
    match fs::read_dir(policy_dir) {
        Ok(d) => Ok(d.flatten().filter_map(id_from_entry).collect()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e),
    }
}

/// Return an iterator to the IDs of all protectors available in the key store
pub fn protector_ids() -> std::io::Result<Vec<ProtectorId>> {
    fn id_from_entry(d: fs::DirEntry) -> Option<ProtectorId> {
        let path = d.path();
        if let Some(path_str) = path.file_name().and_then(OsStr::to_str) {
            path_str.parse::<ProtectorId>().ok()
        } else {
            None
        }
    }

    let protector_dir = &keystore_dirs().protectors;
    match fs::read_dir(protector_dir) {
        Ok(d) => Ok(d.flatten().filter_map(id_from_entry).collect()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e),
    }
}

/// Load a protector from disk
pub(crate) fn load_protector(id: ProtectorId) -> std::io::Result<Protector> {
    let dir = &keystore_dirs().protectors;
    let protector_file = dir.join(id.to_string());
    if !dir.exists() || !protector_file.exists() {
        return Err(std::io::Error::new(ErrorKind::NotFound, "protector not found"));
    }

    serde_json::from_reader(fs::File::open(protector_file)?)
        .map(|data| Protector { id, data })
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
}

/// Whether to overwrite an existing protector
pub enum SaveProtector {
    /// Add a new protector (don't overwrite an existing one)
    AddNew,
    /// Update an existing protector
    UpdateExisting,
}

/// Save a protector to disk
pub fn save_protector(prot: &Protector, save: SaveProtector) -> Result<()> {
    let path = &keystore_dirs().protectors;
    fs::create_dir_all(path)
        .map_err(|e| anyhow!("Failed to create {}: {e}", path.display()))?;
    let filename = path.join(prot.id.to_string());
    match (filename.exists(), save) {
        (true, SaveProtector::AddNew) => bail!("Trying to overwrite an existing protector"),
        (false, SaveProtector::UpdateExisting) => bail!("Trying to update a nonexistent protector"),
        _ => (),
    }
    let mut file = SafeFile::create(&filename)
        .map_err(|e| anyhow!("Failed to store protector {}: {e}", prot.id))?;
    serde_json::to_writer_pretty(&mut file, &prot.data)?;
    file.write_all(b"\n")?;
    file.commit()?;
    Ok(())
}

/// Load a policy from disk
pub(crate) fn load_policy_data(id: &PolicyKeyId) -> std::io::Result<PolicyData> {
    let dir = &keystore_dirs().policies;
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
fn load_or_create_policy_data(id: &PolicyKeyId) -> std::io::Result<PolicyData> {
    match load_policy_data(id) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(PolicyData::new(id.clone())),
        x => x,
    }
}

/// Save a policy to disk
pub(crate) fn save_policy_data(policy: &mut PolicyData) -> Result<()> {
    let id = &policy.id;
    let path = &keystore_dirs().policies;
    fs::create_dir_all(path)
        .context(format!("Failed to create {}", path.display()))?;
    let filename = path.join(id.to_string());
    match (filename.exists(), policy.is_new) {
        (true, true) => bail!("Trying to overwrite existing data from policy {id}"),
        (false, false) => bail!("Trying to update nonexistent policy {id}"),
        _ => (),
    }
    if policy.keys.is_empty() {
        if filename.exists() {
            return std::fs::remove_file(filename)
                .inspect(|_| policy.is_new = true)
                .context(format!("Failed to remove data from policy {id}"));
        }
        bail!("Trying to remove nonexistent policy {id}");
    }
    let mut file = SafeFile::create(&filename)
        .context(format!("Failed to store data from policy {id}"))?;
    serde_json::to_writer_pretty(&mut file, &policy.keys)?;
    file.write_all(b"\n")?;
    file.commit()?;
    policy.is_new = false;
    Ok(())
}

/// Removes a protector if it's not being used in any policy
pub fn remove_protector_if_unused(protector_id: &ProtectorId) -> Result<bool> {
    for policy_id in policy_key_ids()? {
        if load_or_create_policy_data(&policy_id)?.keys.contains_key(protector_id) {
            return Ok(false);
        }
    }

    let filename = keystore_dirs().protectors.join(protector_id.to_string());
    if ! filename.exists() {
        bail!("Protector {protector_id} not found");
    }
    Ok(fs::remove_file(&filename).and(Ok(true))?)
}

/// Get all protectors that can be used to unlock the policy key identified by `id`
pub fn get_protectors_for_policy(id: &PolicyKeyId) -> std::io::Result<(Vec<ProtectedPolicyKey>, Vec<UnusableProtector>)> {
    let mut prots = vec![];
    let mut unusable = vec![];
    let policy = load_or_create_policy_data(id)?;
    for (protector_id, policy_key) in policy.keys {
        match load_protector(protector_id) {
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
pub(crate) fn remove_policy(id: &PolicyKeyId) -> std::io::Result<()> {
    let dir = &keystore_dirs().policies;
    let policy_file = dir.join(id.to_string());
    if !dir.exists() || !policy_file.exists() {
        return Err(ErrorKind::NotFound.into());
    }
    fs::remove_file(policy_file)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::str::FromStr;
    use super::*;

    fn test_init() -> Result<tempdir::TempDir> {
        let tmpdir = tempdir::TempDir::new("keystore")?;
        unsafe {
            std::env::set_var("DIRLOCK_KEYSTORE", tmpdir.path());
        }
        Ok(tmpdir)
    }

    #[test]
    fn test_empty_keystore() -> Result<()> {
        let tmpdir = test_init()?;
        let poldir = tmpdir.path().join("policies");
        let protdir = tmpdir.path().join("protectors");

        // Check the paths
        assert_eq!(poldir, keystore_dirs().policies);
        assert_eq!(protdir, keystore_dirs().protectors);

        // Check that the dirs are empty
        assert!(policy_key_ids()?.is_empty());
        assert!(protector_ids()?.is_empty());

        // Try loading a nonexistent protector
        let protid = ProtectorId::from_str("0000000000000000")?;
        let Err(err) = load_protector(protid) else {
            bail!("Found unexpected protector");
        };
        assert_eq!(err.kind(), ErrorKind::NotFound);

        // Try loading a nonexistent policy
        let polid = PolicyKeyId::from_str("00000000000000000000000000000000")?;
        let Err(err) = load_policy_data(&polid) else {
            bail!("Found unexpected policy");
        };
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(load_or_create_policy_data(&polid)?.keys.is_empty());

        // Try removing a nonexistent policy
        let Err(err) = remove_policy(&polid) else {
            bail!("Expected error removing nonexistent policy");
        };
        assert_eq!(err.kind(), ErrorKind::NotFound);

        Ok(())
    }
}
