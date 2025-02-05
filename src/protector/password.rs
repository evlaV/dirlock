
use anyhow::Result;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};

use crate::{
    protector::{
        Aes256Key,
        AesIv,
        Hmac,
        ProtectorKey,
        Salt,
        PROTECTOR_KEY_LEN,
        aes_dec,
        aes_enc,
    },
};

/// A [`Protector`] that wraps a [`ProtectorKey`] with a password
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct PasswordProtector {
    #[serde_as(as = "Base64")]
    wrapped_key: [u8; PROTECTOR_KEY_LEN],
    iv: AesIv,
    salt: Salt,
    hmac: Hmac,
}

impl PasswordProtector {
    /// Creates a new [`PasswordProtector`] that wraps a [`ProtectorKey`] with a password.
    pub fn new(mut raw_key: ProtectorKey, pass: &str) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut iv = AesIv::default();
        rng.try_fill_bytes(&mut iv.0)?;
        let mut salt = Salt::default();
        rng.try_fill_bytes(&mut salt.0)?;
        let key = Aes256Key::new_from_password(pass, &salt);
        let hmac = aes_enc(&key, &iv, &mut raw_key.0);
        Ok(PasswordProtector{ wrapped_key: raw_key.0, iv, salt, hmac })
    }

    /// Unwraps a [`ProtectorKey`] with a password.
    pub fn decrypt(&self, pass: &str) -> Option<ProtectorKey> {
        let mut raw_key = ProtectorKey::from(&self.wrapped_key);
        let key = Aes256Key::new_from_password(pass, &self.salt);
        if aes_dec(&key, &self.iv, &self.hmac, &mut raw_key.0) {
            Some(raw_key)
        } else {
            None
        }
    }
}
