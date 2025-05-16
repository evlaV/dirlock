/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;
use std::sync::OnceLock;

const CONFIG_FILE_PATH:   &str = "/etc/dirlock.conf";
const DEFAULT_TPM2_TCTI: &str = "device:/dev/tpm0";

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "default_tpm2_tcti")]
    tpm2_tcti: String,
}

fn default_tpm2_tcti() -> String {
    std::env::var("TPM2TOOLS_TCTI")
        .or_else(|_| std::env::var("TCTI"))
        .unwrap_or(String::from(DEFAULT_TPM2_TCTI))
}

impl Config {
    fn get() -> Result<&'static Config> {
        static GLOBAL_CONFIG : OnceLock<Result<Config, String>> = OnceLock::new();
        GLOBAL_CONFIG.get_or_init(|| {
            let file = PathBuf::from(CONFIG_FILE_PATH);
            if file.exists() {
                File::open(file)
                    .map_err(|e| format!("{e}"))
                    .and_then(|f| serde_json::from_reader(f).map_err(|e| format!("{e}")))
                    .map_err(|e| format!("Error reading {CONFIG_FILE_PATH}: {e}"))
            } else {
                Ok(Config { tpm2_tcti: default_tpm2_tcti() })
            }
        }).as_ref().map_err(|e| anyhow!(e))
    }

    pub fn tpm2_tcti() -> Result<&'static str> {
        Config::get().map(|c| c.tpm2_tcti.as_str())
    }
}
