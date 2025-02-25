/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use crate::protector::{Protector, ProtectorId, ProtectedPolicyKey, WrappedPolicyKey};
use crate::fscrypt::PolicyKeyId;

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

/// This contains several instances of the same fscrypt policy key
/// wrapped with different protectors
type PolicyMap = HashMap<ProtectorId, WrappedPolicyKey>;

/// Load a protector from disk
fn load_protector(id: &ProtectorId) -> Result<Option<Protector>> {
    let dir = &keystore_dirs().protectors;
    let protector_file = dir.join(id.to_string());
    if !dir.exists() || !protector_file.exists() {
        return Ok(None);
    }

    let protector = match std::fs::OpenOptions::new().read(true).open(protector_file) {
        Ok(f) => serde_json::from_reader(f)
            .map_err(|e| anyhow!("Error reading data for protector {id}: {e}"))?,
        Err(e) => bail!("Error opening protector {id}: {e}"),
    };

    Ok(Some(protector))
}

/// Save a protector to disk
fn save_protector(id: &ProtectorId, prot: &Protector) -> Result<()> {
    let path = &keystore_dirs().protectors;
    std::fs::create_dir_all(path)
        .map_err(|e| anyhow!("Failed to create {}: {e}", path.display()))?;
    let filename = path.join(id.to_string());
    // TODO: create a temporary file first, then rename
    let mut file = std::fs::File::create(filename)
        .map_err(|e| anyhow!("Failed to store protector {id}: {e}"))?;
    serde_json::to_writer_pretty(&file, prot)?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Load a policy map from disk
fn load_policy_map(id: &PolicyKeyId) -> Result<PolicyMap> {
    let dir = &keystore_dirs().policies;
    let policy_file = dir.join(id.to_string());
    if !dir.exists() || !policy_file.exists() {
        return Ok(HashMap::new());
    }

    let policy = match std::fs::OpenOptions::new().read(true).open(policy_file) {
        Ok(f) => serde_json::from_reader(f)
            .map_err(|e| anyhow!("Error reading data for policy {id}: {e}"))?,
        Err(e) => bail!("Error opening policy {id}: {e}"),
    };

    Ok(policy)
}

/// Save a policy map to disk
fn save_policy_map(id: &PolicyKeyId, policy_map: &PolicyMap) -> Result<()> {
    let path = &keystore_dirs().policies;
    std::fs::create_dir_all(path)
        .map_err(|e| anyhow!("Failed to create {}: {e}", path.display()))?;
    let filename = path.join(id.to_string());
    // TODO: create a temporary file first, then rename
    let mut file = std::fs::File::create(filename)
        .map_err(|e| anyhow!("Failed to store policy key {id}: {e}"))?;
    serde_json::to_writer_pretty(&file, policy_map)?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Add a protected policy key to the key store
pub fn add_protector_to_policy(policy_id: &PolicyKeyId, protected_key: ProtectedPolicyKey) -> Result<()> {
    let mut policy_map = load_policy_map(policy_id)?;
    if policy_map.contains_key(&protected_key.protector_id) {
        bail!("Trying to add a duplicate protector for a policy");
    };
    policy_map.insert(protected_key.protector_id, protected_key.policy_key);
    save_policy_map(policy_id, &policy_map)
}

/// Add a protector to the key store
pub fn add_protector(id: &ProtectorId, prot: &Protector, overwrite: bool) -> Result<()> {
    if !overwrite {
        let path = keystore_dirs().protectors.join(id.to_string());
        if path.exists() {
            bail!("Trying to overwrite an existing protector");
        }
    }
    save_protector(id, prot)
}

/// Get all protectors that can be used to unlock the policy key identified by `id`
pub fn get_protectors_for_policy(id: &PolicyKeyId) -> Result<Vec<ProtectedPolicyKey>> {
    let mut result = vec![];
    let policies = load_policy_map(id)?;
    for (protector_id, policy_key) in policies {
        // TODO if this fails it means that there's a policy
        // wrapped with a protector but the protector is
        // missing. We should report this.
        if let Some(protector) = load_protector(&protector_id)? {
            result.push(ProtectedPolicyKey{ protector_id, protector, policy_key });
        }
    }
    Ok(result)
}
