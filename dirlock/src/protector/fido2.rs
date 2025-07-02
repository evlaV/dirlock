/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, Result};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};

#[cfg(feature = "fido2")]
use {
    anyhow::anyhow,
    crate::crypto::Aes256Key,
    fido2_rs::{
        assertion::AssertRequest,
        credentials::{
            CoseType,
            Credential,
            Extensions,
            Opt,
        },
        device::{Device, DeviceList},
        error::Error,
    },
    libfido2_sys::{
        FIDO_ERR_ACTION_TIMEOUT,
        FIDO_ERR_PIN_AUTH_BLOCKED,
        FIDO_ERR_PIN_INVALID,
        FIDO_ERR_UNSUPPORTED_OPTION,
        FIDO_ERR_UP_REQUIRED,
    },
    rand::{RngCore, rngs::OsRng},
    std::borrow::Cow,
    std::io::IsTerminal,
};

use crate::{
    crypto::{
        AesIv,
        Hmac,
        Salt,
    },
    protector::{
        ProtectorKey,
        PROTECTOR_KEY_LEN,
        opts::Fido2Opts,
    },
};

#[cfg(feature = "fido2")]
const RELYING_PARTY_ID: &str = "cloud.steamos.dirlock";

/// A [`Protector`] that wraps a [`ProtectorKey`] using a FIDO2 token
#[serde_as]
#[derive(Serialize, Deserialize, Default)]
pub struct Fido2Protector {
    pub name: String,
    #[serde_as(as = "Base64")]
    credential: Vec<u8>,
    salt: Salt,
    rp: String,
    pub(super) pin: bool,
    // We don't have a 'up' setting because hmac-secret always requires it
    #[serde_as(as = "Base64")]
    wrapped_key: [u8; PROTECTOR_KEY_LEN],
    iv: AesIv,
    hmac: Hmac,
}


#[cfg(not(feature = "fido2"))]
impl Fido2Protector {
    pub fn new(_opts: Fido2Opts, _prot_key: ProtectorKey, _pass: &[u8]) -> Result<Self> {
        bail!("FIDO2 support is disabled");
    }

    pub fn unwrap_key(&self, _pass: &[u8]) -> Result<Option<ProtectorKey>> {
        bail!("FIDO2 support is disabled");
    }

    pub fn is_available(&self) -> bool {
        false
    }

    pub fn get_prompt(&self) -> Result<String, String> {
        Err(String::from("FIDO2 support is disabled"))
    }
}

#[cfg(not(feature = "fido2"))]
pub fn check_device_available() -> Result<()> {
    bail!("FIDO2 support is disabled");
}

#[cfg(feature = "fido2")]
impl Fido2Protector {
    /// Creates a new [`Fido2Protector`]
    pub fn new(opts: Fido2Opts, mut prot_key: ProtectorKey, pass: &[u8]) -> Result<Self> {
        // Get the first FIDO2 token that supports hmac-secret
        let dev = get_fido2_device(None)?;

        // Create a new credential
        let mut cred = Credential::new();
        cred.set_client_data_hash([0u8; 32])?;
        cred.set_rp(RELYING_PARTY_ID, RELYING_PARTY_ID)?;
        cred.set_user("dirlock", "dirlock", None, None)?;
        cred.set_extension(Extensions::HMAC_SECRET)?;
        cred.set_cose_type(CoseType::ES256)?;

        if std::io::stdout().is_terminal() {
            println!("Confirm presence on the FIDO2 token to generate a credential");
        }

        let Cow::Borrowed(pin) = String::from_utf8_lossy(pass) else {
            bail!("The FIDO2 PIN is not a valid string");
        };
        match dev.make_credential(&mut cred, Some(pin)) {
            Ok(_) => (),
            Err(Error::Fido(e)) => return Err(parse_fido2_error(e)),
            Err(e) => bail!("Error creating FIDO2 protector: {e}"),
        }

        let mut salt = Salt::default();
        OsRng.fill_bytes(&mut salt.0);

        let mut prot = Fido2Protector {
            name: opts.name,
            credential: Vec::from(cred.id()),
            salt,
            rp: String::from(RELYING_PARTY_ID),
            pin: opts.use_pin.unwrap_or(true),
            ..Default::default()
        };

        if std::io::stdout().is_terminal() {
            println!("Confirm presence on the FIDO2 token to continue");
        }

        // The encryption key is the result of the hmac-secret operation
        let Some(enc_key) = prot.hmac_secret(&dev, prot.pin.then_some(pin))? else {
            bail!("Error getting secret from the FIDO2 token");
        };

        // Use the encryption key to wrap the protector key
        OsRng.fill_bytes(&mut prot.iv.0);
        prot.hmac = enc_key.encrypt(&prot.iv, prot_key.secret_mut());
        prot.wrapped_key = *prot_key.secret();

        Ok(prot)
    }

    /// Unwraps a [`ProtectorKey`] with a FIDO2 token.
    pub fn unwrap_key(&self, pass: &[u8]) -> Result<Option<ProtectorKey>> {
        let dev = get_fido2_device(Some(&self.credential))?;
        // TODO: the caller always has to provide a PIN even if we don't use it
        let pin = if self.pin {
            let Cow::Borrowed(s) = String::from_utf8_lossy(pass) else {
                bail!("The FIDO2 PIN is not a valid string");
            };
            Some(s)
        } else {
            None
        };
        match self.hmac_secret(&dev, pin)? {
            Some(dec_key) => {
                let mut prot_key = ProtectorKey::from(&self.wrapped_key);
                if dec_key.decrypt(&self.iv, &self.hmac, prot_key.secret_mut()) {
                    Ok(Some(prot_key))
                } else {
                    // This means that the key that we got from the
                    // token cannot unwrap the protector key.
                    // It should never happen.
                    bail!("Unexpected failure unlocking protector with FIDO2 token");
                }
            },
            None => Ok(None),
        }
    }

    /// Returns whether the protector is available to be used
    pub fn is_available(&self) -> bool {
        get_fido2_device(Some(&self.credential)).is_ok()
    }

    /// Returns the prompt, or an error message if the FIDO2 token is not available or usable
    pub fn get_prompt(&self) -> Result<String, String> {
        match get_fido2_device(Some(&self.credential)) {
            Ok(_) => if self.pin {
                Ok(String::from("Enter FIDO2 PIN and confirm presence on the token"))
            } else {
                Ok(String::from("Confirm presence on the FIDO2 token"))
            },
            Err(e) => Err(e.to_string()),
        }
    }

    /// Gets an [`Aes256Key`] from the token using the hmac-secret extension
    fn hmac_secret(&self, dev: &Device, pin: Option<&str>) -> Result<Option<Aes256Key>> {
        let mut req = AssertRequest::new();
        req.set_client_data_hash([0u8; 32])?;
        req.set_rp(&self.rp)?;
        req.set_allow_credential(&self.credential)?;
        req.set_extensions(Extensions::HMAC_SECRET)?;
        req.set_hmac_salt(&self.salt.0)?;
        assert_eq!(self.pin, pin.is_some());

        match dev.get_assertion(req, pin) {
            Ok(assertions) => {
                if let Some(assertion) = assertions.iter().next() {
                    let hmac_secret = assertion.hmac_secret();
                    // The CTAP standard specifies that hmac-secret uses HMAC-SHA-256
                    // so the result should always be 32 bytes long.
                    // https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html
                    if let Ok(key) = Aes256Key::try_from(hmac_secret) {
                        return Ok(Some(key));
                    }
                }
                bail!("No valid secret received from FIDO2 token");
            },
            Err(Error::Fido(e)) if e.code == FIDO_ERR_PIN_INVALID => Ok(None),
            Err(Error::Fido(e)) => Err(parse_fido2_error(e)),
            Err(x) => bail!("{x}"),
        }
    }
}

#[cfg(feature = "fido2")]
pub fn check_device_available() -> Result<()> {
    let _ = get_fido2_device(None)?;
    Ok(())
}

/// Finds the FIDO2 token with the provided credential (if set)
#[cfg(feature = "fido2")]
pub(super) fn get_fido2_device(cred: Option<&[u8]>) -> Result<Device> {
    let devices = DeviceList::list_devices(16);

    if devices.len() == 0 {
        bail!("No FIDO2 token found");
    }

    for dev_info in devices {
        let dev = dev_info.open()?;
        if let Some(cred) = cred {
            // If we have a credential then look for the token that has it
            let mut req = AssertRequest::new();
            req.set_client_data_hash([0u8; 32])?;
            req.set_rp(RELYING_PARTY_ID)?;
            req.set_allow_credential(cred)?;
            req.set_up(Opt::False)?;
            if dev.get_assertion(req, None).is_ok() {
                return Ok(dev);
            }
        } else if dev.info()?.extensions().contains(&"hmac-secret") {
            // If we don't have a credential yet then look for
            // the first token that supports hmac-secret
            return Ok(dev);
        }
    }

    if cred.is_some() {
        bail!("No FIDO2 token found with the requested credential");
    } else {
        bail!("No FIDO2 token found supporting the hmac-secret extension");
    }
}

#[cfg(feature = "fido2")]
fn parse_fido2_error(err: fido2_rs::error::FidoError) -> anyhow::Error {
    let msg = match err.code {
        FIDO_ERR_PIN_INVALID => "Invalid FIDO2 PIN",
        FIDO_ERR_PIN_AUTH_BLOCKED => "FIDO2 token blocked, remove and reinsert it",
        FIDO_ERR_ACTION_TIMEOUT => "FIDO2 timeout (user didn't interact with the token)",
        FIDO_ERR_UNSUPPORTED_OPTION => "Unsupported FIDO2 options",
        FIDO_ERR_UP_REQUIRED => "User presence required",
        _ => return anyhow!("{err}"),
    };
    anyhow!(msg)
}
