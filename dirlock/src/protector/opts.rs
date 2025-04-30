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
    Tpm2(Tpm2Opts),
    Password(PasswordOpts),
}


/// Options for password protectors
#[derive(Default)]
pub struct PasswordOpts {
    pub kdf_iter: Option<NonZeroU32>,
    pub name: String,
}


/// Options for TPM2 protectors
pub struct Tpm2Opts {
    pub kdf_iter: Option<NonZeroU32>,
    pub name: String,
}


/// A builder for [`ProtectorOpts`]
#[derive(Default)]
pub struct ProtectorOptsBuilder {
    ptype: Option<ProtectorType>,
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
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
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
        let Some(name) = self.name else {
            bail!("Protector name not set");
        };
        if name.len() > PROTECTOR_NAME_MAX_LEN {
            bail!("Protector name too long");
        }
        match ptype {
            ProtectorType::Tpm2 => {
                Ok(ProtectorOpts::Tpm2(Tpm2Opts {
                    kdf_iter: self.kdf_iter,
                    name
                }))
            },
            ProtectorType::Password => {
                Ok(ProtectorOpts::Password(PasswordOpts {
                    kdf_iter: self.kdf_iter,
                    name
                }))
            },
        }
    }
}
