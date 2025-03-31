/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};
use crate::kdf::{Kdf, Pbkdf2};

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
        opts::PasswordOpts,
    },
};

/// A [`Protector`] that wraps a [`ProtectorKey`] with a password
#[serde_as]
#[derive(Serialize, Deserialize, Default)]
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
    pub fn new(opts: PasswordOpts, prot_key: ProtectorKey, pass: &[u8]) -> Self {
        let kdf = if let Some(kdf_iter) = opts.kdf_iter {
            Kdf::Pbkdf2(Pbkdf2::new(kdf_iter.into()))
        } else {
            Kdf::default()
        };
        let mut prot = PasswordProtector { kdf, ..Default::default() };
        prot.wrap_key(prot_key, pass);
        prot
    }

    /// Wraps `prot_key` with `pass`. This generates new random values for IV and Salt.
    fn wrap_key(&mut self, mut prot_key: ProtectorKey, pass: &[u8]) {
        OsRng.fill_bytes(&mut self.iv.0);
        OsRng.fill_bytes(&mut self.salt.0);
        let enc_key = Aes256Key::new_from_password(pass, &self.salt, &self.kdf);
        self.hmac = aes_enc(&enc_key, &self.iv, prot_key.secret_mut());
        self.wrapped_key = *prot_key.secret();
    }

    /// Unwraps a [`ProtectorKey`] with a password.
    pub fn unwrap_key(&self, pass: &[u8]) -> Option<ProtectorKey> {
        let mut prot_key = ProtectorKey::from(&self.wrapped_key);
        let key = Aes256Key::new_from_password(pass, &self.salt, &self.kdf);
        if aes_dec(&key, &self.iv, &self.hmac, prot_key.secret_mut()) {
            Some(prot_key)
        } else {
            None
        }
    }

    /// Changes the password of this protector
    pub fn change_pass(&mut self, pass: &[u8], newpass: &[u8]) -> bool {
        if let Some(prot_key) = self.unwrap_key(pass) {
            self.wrap_key(prot_key, newpass);
            true
        } else {
            false
        }
    }
}
