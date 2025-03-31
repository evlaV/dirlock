/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};
use crate::kdf::Kdf;

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
    kdf: Kdf,
}

impl PasswordProtector {
    /// Creates a new [`PasswordProtector`] that wraps a [`ProtectorKey`] with a password.
    pub fn new(mut raw_key: ProtectorKey, pass: &[u8]) -> Self {
        let mut iv = AesIv::default();
        OsRng.fill_bytes(&mut iv.0);
        let mut salt = Salt::default();
        OsRng.fill_bytes(&mut salt.0);
        let kdf = Kdf::default();
        let key = Aes256Key::new_from_password(pass, &salt, &kdf);
        let hmac = aes_enc(&key, &iv, raw_key.secret_mut());
        PasswordProtector{ wrapped_key: *raw_key.secret(), iv, salt, hmac, kdf }
    }

    /// Unwraps a [`ProtectorKey`] with a password.
    pub fn unwrap_key(&self, pass: &[u8]) -> Option<ProtectorKey> {
        let mut raw_key = ProtectorKey::from(&self.wrapped_key);
        let key = Aes256Key::new_from_password(pass, &self.salt, &self.kdf);
        if aes_dec(&key, &self.iv, &self.hmac, raw_key.secret_mut()) {
            Some(raw_key)
        } else {
            None
        }
    }

    /// Changes the password of this protector
    pub fn change_pass(&mut self, pass: &[u8], newpass: &[u8]) -> bool {
        if let Some(raw_key) = self.unwrap_key(pass) {
            *self = PasswordProtector::new(raw_key, newpass);
            true
        } else {
            false
        }
    }
}
