
use anyhow::{anyhow, ensure, Result};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
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
}


/// Options for TPM2 protectors
pub struct Tpm2Opts {
    pub path: String, // tcti_ldr::DeviceConfig wants str and not Path
    pub kdf_iter: Option<NonZeroU32>,
}

impl Default for Tpm2Opts {
    fn default() -> Tpm2Opts {
        Tpm2Opts { path: DEFAULT_TPM2_PATH.to_string(), kdf_iter: None }
    }
}


/// A builder for [`ProtectorOpts`]
#[derive(Default)]
pub struct ProtectorOptsBuilder {
    ptype: Option<ProtectorType>,
    tpm2_device: Option<PathBuf>,
    kdf_iter: Option<NonZeroU32>,
}

impl ProtectorOptsBuilder {
    /// Create a new [`ProtectorOpts`] builder.
    pub fn new() -> ProtectorOptsBuilder {
        ProtectorOptsBuilder::default()
    }

    /// Sets the type of the protector
    pub fn with_type(mut self, ptype: ProtectorType) -> Self {
        self.ptype = Some(ptype);
        self
    }

    /// Sets the path of the TPM2 device (default: "/dev/tpm0")
    pub fn with_tpm2_device(mut self, path: &Path) -> Self {
        self.tpm2_device = Some(PathBuf::from(path));
        self
    }

    /// Sets the number of iterations used in the KDF
    pub fn with_kdf_iter(mut self, iter: NonZeroU32) -> Self {
        self.kdf_iter = Some(iter);
        self
    }

    /// Builds the [`ProtectorOpts`].
    ///
    /// # Errors
    /// Returns an error some options are missing or invalid
    pub fn build(self) -> Result<ProtectorOpts> {
        let ptype = self.ptype.unwrap_or(ProtectorType::Password);
        match ptype {
            ProtectorType::Tpm2 => {
                let path = if let Some(p) = self.tpm2_device {
                    p.to_str()
                        .ok_or_else(|| anyhow!("Invalid TPM path: {}", p.display()))?
                        .to_string()
                } else {
                    DEFAULT_TPM2_PATH.to_string()
                };
                Ok(ProtectorOpts::Tpm2(Tpm2Opts { path, kdf_iter: self.kdf_iter }))
            },
            ProtectorType::Password => {
                ensure!(self.tpm2_device.is_none(), "TPM2 device set for password protector");
                Ok(ProtectorOpts::Password(PasswordOpts { kdf_iter: self.kdf_iter }))
            },
        }
    }
}
