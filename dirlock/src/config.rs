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
    path::PathBuf,
    sync::OnceLock,
};

const CONFIG_FILE_PATH:   &str = "/etc/dirlock.conf";
const DEFAULT_TPM2_TCTI: &str = "device:/dev/tpm0";

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "default_tpm2_tcti")]
    #[allow(dead_code)]
    tpm2_tcti: String,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            tpm2_tcti: default_tpm2_tcti(),
        }
    }
}

fn default_tpm2_tcti() -> String {
    std::env::var("TPM2TOOLS_TCTI")
        .or_else(|_| std::env::var("TCTI"))
        .unwrap_or(String::from(DEFAULT_TPM2_TCTI))
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

    pub fn check() -> Result<()> {
        Config::get().and(Ok(()))
    }
}
