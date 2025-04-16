/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, ensure, Result};
use std::num::NonZeroU32;
use std::path::PathBuf;
use super::ProtectorType;

const DEFAULT_TPM2_PATH: &str = "/dev/tpm0";

/// Available options for protectors
pub enum ProtectorOpts {
    Tpm2(Tpm2Opts),
    Password(PasswordOpts),
}


#[derive(Default)]
pub struct PasswordOpts {
    pub kdf_iter: Option<NonZeroU32>,
    pub name: Option<String>,
}


/// Options for TPM2 protectors
pub struct Tpm2Opts {
    pub path: String, // tcti_ldr::DeviceConfig wants str and not Path
    pub kdf_iter: Option<NonZeroU32>,
    pub name: Option<String>,
}

impl Default for Tpm2Opts {
    fn default() -> Tpm2Opts {
        Tpm2Opts { path: DEFAULT_TPM2_PATH.to_string(), kdf_iter: None, name: None }
    }
}


/// A builder for [`ProtectorOpts`]
#[derive(Default)]
pub struct ProtectorOptsBuilder {
    ptype: Option<ProtectorType>,
    tpm2_device: Option<PathBuf>,
    kdf_iter: Option<NonZeroU32>,
    name: Option<String>,
}

impl ProtectorOptsBuilder {
    /// Create a new [`ProtectorOpts`] builder.
    pub fn new() -> ProtectorOptsBuilder {
        ProtectorOptsBuilder::default()
    }

    /// Sets the type of the protector
    pub fn with_type(mut self, ptype: Option<ProtectorType>) -> Self {
        self.ptype = ptype;
        self
    }

    /// Sets the type of the protector
    pub fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// Sets the path of the TPM2 device (default: "/dev/tpm0")
    pub fn with_tpm2_device(mut self, path: Option<PathBuf>) -> Self {
        self.tpm2_device = path;
        self
    }

    /// Sets the number of iterations used in the KDF
    pub fn with_kdf_iter(mut self, iter: Option<NonZeroU32>) -> Self {
        self.kdf_iter = iter;
        self
    }

    /// Builds the [`ProtectorOpts`].
    ///
    /// # Errors
    /// Returns an error if some options are missing or invalid
    pub fn build(self) -> Result<ProtectorOpts> {
        let ptype = self.ptype.unwrap_or(ProtectorType::Password);
        if let Some(name) = &self.name {
            if name.len() > 64 {
                bail!("Protector name too long");
            }
        }
        match ptype {
            ProtectorType::Tpm2 => {
                let path = if let Some(p) = self.tpm2_device {
                    p.to_str()
                        .ok_or_else(|| anyhow!("Invalid TPM path: {}", p.display()))?
                        .to_string()
                } else {
                    DEFAULT_TPM2_PATH.to_string()
                };
                Ok(ProtectorOpts::Tpm2(Tpm2Opts {
                    path,
                    kdf_iter: self.kdf_iter,
                    name: self.name,
                }))
            },
            ProtectorType::Password => {
                ensure!(self.tpm2_device.is_none(), "TPM2 device set for password protector");
                Ok(ProtectorOpts::Password(PasswordOpts {
                    kdf_iter: self.kdf_iter,
                    name: self.name,
                }))
            },
        }
    }
}
