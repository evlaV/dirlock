
use anyhow::Result;
use rand::RngCore;
use serde::{Serialize, Deserialize};

use crate::{
    protector::{
        Aes256Key,
        AesIv,
        Hmac,
        ProtectorKey,
        Salt,
        WrappedProtectorKey,
        aes_dec,
        aes_enc,
    },
};

/// A [`Protector`] that wraps a [`ProtectorKey`] with a password
#[derive(Serialize, Deserialize)]
pub struct PasswordProtector {
    wrapped_key: WrappedProtectorKey,
    iv: AesIv,
    salt: Salt,
    hmac: Hmac,
}

impl PasswordProtector {
    /// Creates a new [`PasswordProtector`] that wraps a [`ProtectorKey`] with a password.
    pub fn new(raw_key: ProtectorKey, pass: &str) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut prot = PasswordProtector {
            wrapped_key: WrappedProtectorKey(raw_key.0),
            iv: AesIv::default(),
            salt: Salt::default(),
            hmac: Hmac::default()
        };
        rng.try_fill_bytes(&mut prot.iv.0)?;
        rng.try_fill_bytes(&mut prot.salt.0)?;
        let key = Aes256Key::new_from_password(pass, &prot.salt);
        prot.hmac = aes_enc(&key, &prot.iv, &mut prot.wrapped_key.0);
        Ok(prot)
    }

    /// Unwraps a [`ProtectorKey`] with a password.
    pub fn decrypt(&self, pass: &str) -> Option<ProtectorKey> {
        let mut raw_key = ProtectorKey(self.wrapped_key.0);
        let key = Aes256Key::new_from_password(pass, &self.salt);
        if aes_dec(&key, &self.iv, &self.hmac, &mut raw_key.0) {
            Some(raw_key)
        } else {
            None
        }
    }
}
