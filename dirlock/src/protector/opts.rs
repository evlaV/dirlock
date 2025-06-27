/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, Result};
use std::num::NonZeroU32;
use super::ProtectorType;

pub const PROTECTOR_NAME_MAX_LEN: usize = 128;

/// Available options for protectors
pub enum ProtectorOpts {
    Fido2(Fido2Opts),
    Tpm2(Tpm2Opts),
    Password(PasswordOpts),
}

impl ProtectorOpts {
    pub fn get_type(&self) -> ProtectorType {
        match self {
            ProtectorOpts::Fido2(_) => ProtectorType::Fido2,
            ProtectorOpts::Tpm2(_) => ProtectorType::Tpm2,
            ProtectorOpts::Password(_) => ProtectorType::Password,
        }
    }
}


/// Options for password protectors
pub struct PasswordOpts {
    pub kdf_iter: Option<NonZeroU32>,
    pub name: String,
}


/// Options for TPM2 protectors
pub struct Tpm2Opts {
    pub kdf_iter: Option<NonZeroU32>,
    pub name: String,
    pub tpm2_tcti: Option<String>,
}


/// Options for FIDO2 protectors
pub struct Fido2Opts {
    pub name: String,
}

/// A builder for [`ProtectorOpts`]
#[derive(Default)]
pub struct ProtectorOptsBuilder {
    ptype: Option<ProtectorType>,
    kdf_iter: Option<NonZeroU32>,
    name: String,
    tpm2_tcti: Option<String>,
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
    pub fn with_name(mut self, name: String) -> Self {
        self.name = name.as_str().trim().to_string();
        self
    }

    /// Sets the number of iterations used in the KDF
    pub fn with_kdf_iter(mut self, iter: Option<NonZeroU32>) -> Self {
        self.kdf_iter = iter;
        self
    }

    /// Sets the TPM2 TCTI configuration string
    pub fn with_tpm2_tcti(mut self, tpm2_tcti: Option<String>) -> Self {
        self.tpm2_tcti = tpm2_tcti;
        self
    }

    /// Builds the [`ProtectorOpts`].
    ///
    /// # Errors
    /// Returns an error if some options are missing or invalid
    pub fn build(self) -> Result<ProtectorOpts> {
        let ptype = self.ptype.unwrap_or(ProtectorType::Password);
        if self.name.is_empty() {
            bail!("Protector name not set");
        }
        if self.name.len() > PROTECTOR_NAME_MAX_LEN {
            bail!("Protector name too long");
        }
        if self.tpm2_tcti.is_some() && ptype != ProtectorType::Tpm2 {
            bail!("The TCTI configuration is only for TPM2 protectors");
        }
        if self.kdf_iter.is_some() && ptype == ProtectorType::Fido2 {
            bail!("FIDO2 protectors don't support KDF options");
        }
        match ptype {
            ProtectorType::Tpm2 => {
                Ok(ProtectorOpts::Tpm2(Tpm2Opts {
                    kdf_iter: self.kdf_iter,
                    tpm2_tcti: self.tpm2_tcti,
                    name: self.name,
                }))
            },
            ProtectorType::Password => {
                Ok(ProtectorOpts::Password(PasswordOpts {
                    kdf_iter: self.kdf_iter,
                    name: self.name,
                }))
            },
            ProtectorType::Fido2 => {
                Ok(ProtectorOpts::Fido2(Fido2Opts {
                    name: self.name,
                }))
            },
        }
    }
}
