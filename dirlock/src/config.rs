/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::{
    fs::File,
    io::{Error, ErrorKind},
    path::Path,
    path::PathBuf,
    sync::OnceLock,
};

const CONFIG_FILE_PATH:   &str = "/etc/dirlock.conf";
const DEFAULT_TPM2_TCTI: &str = "device:/dev/tpm0";
// If this variable is set use this keystore dir instead of the default one
const KEYSTORE_DIR_ENV_VAR : &str = "DIRLOCK_KEYSTORE";
const DEFAULT_KEYSTORE_DIR : &str = "/var/lib/dirlock";

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "default_tpm2_tcti")]
    #[allow(dead_code)]
    tpm2_tcti: String,
    #[serde(default = "default_keystore_dir")]
    keystore_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            tpm2_tcti: default_tpm2_tcti(),
            keystore_dir: default_keystore_dir(),
        }
    }
}

fn default_tpm2_tcti() -> String {
    std::env::var("TPM2TOOLS_TCTI")
        .or_else(|_| std::env::var("TCTI"))
        .unwrap_or(String::from(DEFAULT_TPM2_TCTI))
}

fn default_keystore_dir() -> PathBuf {
    std::env::var(KEYSTORE_DIR_ENV_VAR)
        .unwrap_or(String::from(DEFAULT_KEYSTORE_DIR))
        .into()
}

impl Config {
    fn get() -> Result<&'static Config> {
        static GLOBAL_CONFIG : OnceLock<std::io::Result<Config>> = OnceLock::new();
        GLOBAL_CONFIG.get_or_init(|| {
            let file = PathBuf::from(CONFIG_FILE_PATH);
            if file.exists() {
                File::open(file)
                    .and_then(|f| serde_json::from_reader(f)
                              .map_err(|e| Error::new(ErrorKind::InvalidData, e)))
            } else {
                Ok(Config::default())
            }
        }).as_ref().map_err(|e| anyhow!("failed to read {CONFIG_FILE_PATH}: {e}"))
    }

    #[allow(dead_code)]
    pub fn tpm2_tcti() -> &'static str {
        Config::get().unwrap().tpm2_tcti.as_str()
    }

    pub fn keystore_dir() -> &'static Path {
        Config::get().unwrap().keystore_dir.as_path()
    }

    pub fn check() -> Result<()> {
        Config::get().and(Ok(()))
    }
}
