/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, Result};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use crate::protector::{Protector, ProtectorId, ProtectedPolicyKey, WrappedPolicyKey};
use crate::fscrypt::PolicyKeyId;
use crate::util::SafeFile;

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
pub fn policy_key_ids() -> Result<impl Iterator<Item = PolicyKeyId>> {
    fn id_from_entry(d: fs::DirEntry) -> Option<PolicyKeyId> {
        let path = d.path();
        if let Some(path_str) = path.file_name().and_then(OsStr::to_str) {
            PolicyKeyId::try_from(path_str).ok()
        } else {
            None
        }
    }

    let policy_dir = &keystore_dirs().policies;
    Ok(fs::read_dir(policy_dir)?.flatten().filter_map(id_from_entry))
}

/// Return an iterator to the IDs of all protectors available in the key store
pub fn protector_ids() -> Result<impl Iterator<Item = ProtectorId>> {
    fn id_from_entry(d: fs::DirEntry) -> Option<ProtectorId> {
        let path = d.path();
        if let Some(path_str) = path.file_name().and_then(OsStr::to_str) {
            path_str.parse::<ProtectorId>().ok()
        } else {
            None
        }
    }

    let protector_dir = &keystore_dirs().protectors;
    Ok(fs::read_dir(protector_dir)?.flatten().filter_map(id_from_entry))
}

/// This contains several instances of the same fscrypt policy key
/// wrapped with different protectors
type PolicyMap = HashMap<ProtectorId, WrappedPolicyKey>;

/// Load a protector from disk
pub fn load_protector(id: ProtectorId) -> Result<Option<Protector>> {
    let dir = &keystore_dirs().protectors;
    let protector_file = dir.join(id.to_string());
    if !dir.exists() || !protector_file.exists() {
        return Ok(None);
    }

    let data = match fs::OpenOptions::new().read(true).open(protector_file) {
        Ok(f) => serde_json::from_reader(f)
            .map_err(|e| anyhow!("Error reading data for protector {id}: {e}"))?,
        Err(e) => bail!("Error opening protector {id}: {e}"),
    };

    Ok(Some(Protector { id, data }))
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

/// Load a policy map from disk
pub fn load_policy_map(id: &PolicyKeyId) -> Result<PolicyMap> {
    let dir = &keystore_dirs().policies;
    let policy_file = dir.join(id.to_string());
    if !dir.exists() || !policy_file.exists() {
        return Ok(HashMap::new());
    }

    let policy = match fs::OpenOptions::new().read(true).open(policy_file) {
        Ok(f) => serde_json::from_reader(f)
            .map_err(|e| anyhow!("Error reading data for policy {id}: {e}"))?,
        Err(e) => bail!("Error opening policy {id}: {e}"),
    };

    Ok(policy)
}

/// Save a policy map to disk
fn save_policy_map(id: &PolicyKeyId, policy_map: &PolicyMap) -> Result<()> {
    let path = &keystore_dirs().policies;
    fs::create_dir_all(path)
        .map_err(|e| anyhow!("Failed to create {}: {e}", path.display()))?;
    let filename = path.join(id.to_string());
    let mut file = SafeFile::create(&filename)
        .map_err(|e| anyhow!("Failed to store policy key {id}: {e}"))?;
    serde_json::to_writer_pretty(&mut file, policy_map)?;
    file.write_all(b"\n")?;
    file.commit()?;
    Ok(())
}

/// Add a wrapped policy key to the key store
pub fn add_protector_to_policy(policy_id: &PolicyKeyId, protector_id: ProtectorId, key: WrappedPolicyKey) -> Result<()> {
    let mut policy_map = load_policy_map(policy_id)?;
    if policy_map.contains_key(&protector_id) {
        bail!("Trying to add a duplicate protector for a policy");
    };
    policy_map.insert(protector_id, key);
    save_policy_map(policy_id, &policy_map)
}

/// Remove a protected policy key from the key store
pub fn remove_protector_from_policy(policy_id: &PolicyKeyId, protector_id: &ProtectorId) -> Result<bool> {
    let mut policy_map = load_policy_map(policy_id)?;
    if policy_map.remove(protector_id).is_none() {
        return Ok(false);
    };
    save_policy_map(policy_id, &policy_map).and(Ok(true))
}

/// Removes a protector if it's not being used in any policy
pub fn remove_protector_if_unused(protector_id: &ProtectorId) -> Result<bool> {
    for policy_id in policy_key_ids()? {
        if load_policy_map(&policy_id)?.contains_key(protector_id) {
            return Ok(false);
        }
    }

    let filename = keystore_dirs().protectors.join(protector_id.to_string());
    Ok(fs::remove_file(&filename).and(Ok(true))?)
}

/// Get all protectors that can be used to unlock the policy key identified by `id`
pub fn get_protectors_for_policy(id: &PolicyKeyId) -> Result<Vec<ProtectedPolicyKey>> {
    let mut result = vec![];
    let policies = load_policy_map(id)?;
    for (protector_id, policy_key) in policies {
        // TODO if this fails it means that there's a policy
        // wrapped with a protector but the protector is
        // missing. We should report this.
        if let Some(protector) = load_protector(protector_id)? {
            result.push(ProtectedPolicyKey{ protector, policy_key });
        }
    }
    Ok(result)
}

/// Remove an encryption policy permanently from disk
pub fn remove_policy(id: &PolicyKeyId) -> Result<()> {
    let dir = &keystore_dirs().policies;
    let policy_file = dir.join(id.to_string());
    if !dir.exists() || !policy_file.exists() {
        bail!("Policy not found");
    }
    fs::remove_file(policy_file)?;
    Ok(())
}
