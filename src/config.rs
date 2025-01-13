
use anyhow::{bail, Result};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::io::Write;
use std::sync::OnceLock;
use crate::protector::Protector;
use crate::fscrypt::KeyIdentifier;

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
    keys: HashMap<KeyIdentifier, Vec<Protector>>
}

impl Config {
    /// Load the configuration from file, or get an empty one if the file does not exist
    pub fn new_from_file() -> Result<Self> {
        let cfg : Config = match std::fs::OpenOptions::new().read(true).open(config_file_name()) {
            Ok(f) => serde_json::from_reader(f)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => bail!("Error opening config file: {}", e.to_string()),
        };
        Ok(cfg)
    }

    /// Add a protector for the given [`KeyIdentifier`]
    pub fn add_protector(&mut self, policy: &KeyIdentifier, prot: Protector) {
        if let Some(protlist) = self.keys.get_mut(policy) {
            protlist.push(prot);
        } else {
            let protlist = vec![prot];
            self.keys.insert(policy.clone(), protlist);
        }
    }

    /// Get the protector for the given [`KeyIdentifier`]
    /// TODO: this currently returns the first protector only
    pub fn get_protector(&self, policy: &KeyIdentifier) -> Option<&Protector> {
        if let Some(protlist) = self.keys.get(policy) {
            protlist.first()
        } else {
            None
        }
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
