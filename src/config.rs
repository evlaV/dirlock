
use anyhow::{anyhow, bail, Result};
use serde::{Serialize, Deserialize};
use std::collections::{hash_map, HashMap};
use std::io::Write;
use std::sync::OnceLock;
use crate::protector::{Protector, ProtectorId, WrappedPolicyKey};
use crate::fscrypt::PolicyKeyId;

// If this variable is set use this config file instead of the default one
const CONFIG_FILE_ENV_VAR : &str = "FSCRYPT_RS_CONFIG";
const DEFAULT_CONFIG_FILE : &str = "/etc/fscrypt-rs.conf";

/// Get the config file name. Take it from CONFIG_FILE_ENV_VAR if set
fn config_file_name() -> &'static str {
    static FILE_NAME : OnceLock<String> = OnceLock::new();
    FILE_NAME.get_or_init(|| {
        std::env::var(CONFIG_FILE_ENV_VAR)
            .unwrap_or(String::from(DEFAULT_CONFIG_FILE))
    })
}

/// Main configuration of the app
#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    protectors: HashMap<ProtectorId, Protector>,
    policies: HashMap<PolicyKeyId, HashMap<ProtectorId, WrappedPolicyKey>>,
}

impl Config {
    /// Load the configuration from file, or get an empty one if the file does not exist
    pub fn new_from_file() -> Result<Self> {
        let cfg : Config = match std::fs::OpenOptions::new().read(true).open(config_file_name()) {
            Ok(f) => serde_json::from_reader(f).map_err(|e| anyhow!("Error parsing config file: {e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => bail!("Error opening config file: {e}"),
        };
        Ok(cfg)
    }

    /// Add a (wrapped) policy key together with the ID of the protector used to unwrap it
    pub fn add_policy(&mut self, policy_id: PolicyKeyId, protector_id: ProtectorId, policy: WrappedPolicyKey) -> Result<()> {
        if ! self.protectors.contains_key(&protector_id) {
            bail!("No available policy for that protector");
        }
        if let Some(policy_map) = self.policies.get_mut(&policy_id) {
            let hash_map::Entry::Vacant(e) = policy_map.entry(protector_id) else {
                bail!("Trying to add a duplicate protector for a policy");
            };
            e.insert(policy);
        } else {
            let policy_map = HashMap::from([(protector_id, policy)]);
            self.policies.insert(policy_id, policy_map);
        }
        Ok(())
    }

    /// Add a protector to the configuration
    pub fn add_protector(&mut self, id: ProtectorId, prot: Protector) -> Result<()> {
        let hash_map::Entry::Vacant(e) = self.protectors.entry(id) else {
            bail!("Trying to overwrite an existing protector");
        };
        e.insert(prot);
        Ok(())
    }

    /// Get all protectors that can be used to unlock the policy key identified by `id`
    pub fn get_protectors_for_policy(&self, id: &PolicyKeyId) -> Vec<(&ProtectorId, &Protector, &WrappedPolicyKey)> {
        let mut result = vec![];
        if let Some(policies) = self.policies.get(id) {
            for (protid, policy) in policies {
                // TODO if this fails it means that there's a policy
                // wrapped with a protector but the protector is
                // missing. We should report this.
                if let Some(prot) = self.protectors.get(protid) {
                    result.push((protid, prot, policy));
                }
            }
        }
        result
    }

    /// Write the configuration to disk
    pub fn save(&self) -> Result<()> {
        // TODO: Use a safe way to update the configuration file
        let mut file = std::fs::File::create(config_file_name())?;
        serde_json::to_writer_pretty(&file, &self)?;
        file.write_all(b"\n")?;
        Ok(())
    }
}
