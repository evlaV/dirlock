/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::Result;
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};
use crate::kdf::{Kdf, Pbkdf2};

use crate::{
    crypto::{
        Aes256Key,
        AesIv,
        Hmac,
        Salt,
    },
    protector::{
        ProtectorBackend,
        ProtectorKey,
        ProtectorType,
        PROTECTOR_KEY_LEN,
        opts::PasswordOpts,
    },
};

#[cfg(doc)]
use crate::protector::Protector;

/// A [`Protector`] that wraps a [`ProtectorKey`] with a password
#[serde_as]
#[derive(Serialize, Deserialize, Default)]
pub struct PasswordProtector {
    name: String,
    #[serde_as(as = "Base64")]
    wrapped_key: [u8; PROTECTOR_KEY_LEN],
    iv: AesIv,
    salt: Salt,
    hmac: Hmac,
    kdf: Kdf,
}

impl PasswordProtector {
    /// Creates a new [`PasswordProtector`] that wraps a [`ProtectorKey`] with a password.
    pub fn new(opts: PasswordOpts, prot_key: ProtectorKey, pass: &[u8]) -> Result<Self> {
        let kdf = if let Some(kdf_iter) = opts.kdf_iter {
            Kdf::Pbkdf2(Pbkdf2::new(kdf_iter.into()))
        } else {
            Kdf::default()
        };
        let mut prot = PasswordProtector { kdf, name: opts.name, ..Default::default() };
        prot.wrap_key(prot_key, pass)?;
        Ok(prot)
    }

    #[cfg(test)]
    /// Change the name of the protector. This is only used in tests.
    pub(crate) fn set_name(&mut self, name: String) {
        self.name = name;
    }
}

impl ProtectorBackend for PasswordProtector {
    fn get_name(&self) -> &str { &self.name }
    fn get_type(&self) -> ProtectorType { ProtectorType::Password }
    fn can_change_password(&self) -> bool { true }
    fn needs_password(&self) -> bool { true }
    fn is_available(&self) -> bool { true }

    fn get_prompt(&self) -> Result<String, String> {
        Ok(String::from("Enter password"))
    }

    /// Wraps `prot_key` with `pass`. This generates new random values for IV and Salt.
    fn wrap_key(&mut self, mut prot_key: ProtectorKey, pass: &[u8]) -> Result<()> {
        self.iv.randomize();
        self.salt.randomize();
        let enc_key = Aes256Key::new_from_password(pass, &self.salt, &self.kdf);
        self.hmac = enc_key.encrypt(&self.iv, prot_key.secret_mut());
        self.wrapped_key = *prot_key.secret();
        Ok(())
    }

    /// Unwraps a [`ProtectorKey`] with a password.
    fn unwrap_key(&self, pass: &[u8]) -> Result<Option<ProtectorKey>> {
        let mut prot_key = ProtectorKey::from(&self.wrapped_key);
        let key = Aes256Key::new_from_password(pass, &self.salt, &self.kdf);
        if key.decrypt(&self.iv, &self.hmac, prot_key.secret_mut()) {
            Ok(Some(prot_key))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{bail, Result};
    use crate::protector::{ProtectorBackend, ProtectorData};

    #[test]
    fn test_json_password_protector() -> Result<()> {
        // This tests that the JSON serialization of a protector works as expected
        let json = r#"
            {
              "type": "password",
              "name": "test",
              "wrapped_key": "4Z1w+VcIU69wj4kpu19mU4M7GL47H+TFGhMIstIjbAY=",
              "iv": "T9OvGtzCRyMEHkENhC4QoA==",
              "salt": "5UUzonBVMfJ6bZ0to37fwD9P2wM0JhT45L2Jeq9oUPw=",
              "hmac": "CjrxTlDGNdcfrFLEW2g/tBtoBiEHj82b85KsPvXZiQ4=",
              "kdf": {
                "type": "pbkdf2",
                "iterations": 50
              }
            }"#;

        let prot = match serde_json::from_str::<ProtectorData>(json) {
            Ok(ProtectorData::Password(p)) => p,
            _ => bail!("Error creating protector from JSON data"),
        };

        assert!(prot.unwrap_key(b"1234")?.is_some(), "Failed to unwrap key with password protector");
        Ok(())
    }
}
