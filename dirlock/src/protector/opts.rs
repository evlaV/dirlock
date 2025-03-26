
use anyhow::{anyhow, bail, ensure, Result};
use std::path::{Path, PathBuf};

const DEFAULT_TPM2_PATH: &str = "/dev/tpm0";

/// Available options for protectors
pub enum ProtectorOpts {
    Tpm2(Tpm2Opts),
    Password,
}


/// Options for TPM2 protectors
pub struct Tpm2Opts {
    pub path: String, // tcti_ldr::DeviceConfig wants str and not Path
}

impl Default for Tpm2Opts {
    fn default() -> Tpm2Opts {
        Tpm2Opts { path: DEFAULT_TPM2_PATH.to_string() }
    }
}


/// A builder for [`ProtectorOpts`]
#[derive(Default)]
pub struct ProtectorOptsBuilder {
    ptype: Option<String>,
    tpm2_device: Option<PathBuf>
}

impl ProtectorOptsBuilder {
    /// Create a new [`ProtectorOpts`] builder.
    pub fn new() -> ProtectorOptsBuilder {
        ProtectorOptsBuilder::default()
    }

    /// Sets the type of the protector ("password", "tpm2", ...)
    pub fn with_type(mut self, ptype: &str) -> Self {
        self.ptype = Some(ptype.to_string());
        self
    }

    /// Sets the path of the TPM2 device (default: "/dev/tpm0")
    pub fn with_tpm2_device(mut self, path: &Path) -> Self {
        self.tpm2_device = Some(PathBuf::from(path));
        self
    }

    /// Builds the [`ProtectorOpts`].
    ///
    /// # Errors
    /// Returns an error some options are missing or invalid
    pub fn build(self) -> Result<ProtectorOpts> {
        let ptype = self.ptype.unwrap_or(String::from("password"));
        match ptype.as_str() {
            "tpm2" => {
                let path = if let Some(p) = self.tpm2_device {
                    p.to_str()
                        .ok_or_else(|| anyhow!("Invalid TPM path: {}", p.display()))?
                        .to_string()
                } else {
                    DEFAULT_TPM2_PATH.to_string()
                };
                Ok(ProtectorOpts::Tpm2(Tpm2Opts { path }))
            },
            "password" => {
                ensure!(self.tpm2_device.is_none(), "TPM2 device set for password protector");
                Ok(ProtectorOpts::Password)
            },
            x => bail!("Unknown protector type {x}"),
        }
    }
}
