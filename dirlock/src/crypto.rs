/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use crate::kdf::Kdf;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};
use sha2::Sha256;

const AES_IV_LEN: usize = 16;
const HMAC_LEN: usize = 32;
const SALT_LEN: usize = 32;

/// A key for AES-256 encryption
#[derive(Default, zeroize::ZeroizeOnDrop, Clone)]
pub struct Aes256Key(Box<[u8; 32]>);

impl From<&[u8; 32]> for Aes256Key {
    fn from(src: &[u8; 32]) -> Self {
        Aes256Key(Box::new(*src))
    }
}

impl Aes256Key {
    /// Return a reference to the data
    pub fn secret(&self) -> &[u8; 32] {
        self.0.as_ref()
    }

    /// Return a mutable reference to the data
    pub fn secret_mut(&mut self) -> &mut [u8; 32] {
        self.0.as_mut()
    }

    /// Generates a new, random key
    pub fn new_random() -> Self {
        let mut key = Aes256Key::default();
        OsRng.fill_bytes(key.secret_mut());
        key
    }

    /// Generates a new key from `pass` and `salt` using a KDF
    pub fn new_from_password(pass: &[u8], salt: &Salt, kdf: &Kdf) -> Self {
        let mut key = Aes256Key::default();
        kdf.derive(pass, &salt.0, key.secret_mut());
        key
    }

    /// Stretches this key into two new keys of the same size using HKDF
    fn stretch<'a>(&self, buffer: &'a mut [u8; 64]) -> (&'a [u8; 32], &'a [u8; 32]) {
        // Run HKDF-expand to get a 512-bit key
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, self.secret());
        hkdf.expand(&[], buffer).unwrap();
        // Split the generated key in two
        let k1 : &[u8; 32] = buffer[ 0..32].try_into().unwrap();
        let k2 : &[u8; 32] = buffer[32..64].try_into().unwrap();
        (k1, k2)
    }

    /// Encrypts `data` using this key and `iv`, returns an Hmac
    pub fn encrypt(&self, iv: &AesIv, data: &mut [u8]) -> Hmac {
        // Stretch the original key to get the encryption and the authentication key
        let mut buffer = zeroize::Zeroizing::new([0u8; 64]);
        let (enc_key, auth_key) = self.stretch(&mut buffer);

        // Encrypt the data
        let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(enc_key.into(), &iv.0.into());
        cipher.apply_keystream(data);

        // Calculate the MAC of the encrypted data and return it
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(auth_key).unwrap();
        mac.update(&iv.0);
        mac.update(data);
        Hmac(mac.finalize().into_bytes().into())
    }

    /// Decrypts `data` using this key and `iv`, returns whether the HMAC is valid
    pub fn decrypt(&self, iv: &AesIv, expected_hmac: &Hmac, data: &mut [u8]) -> bool {
        // Stretch the original key to get the encryption and authentication keys
        let mut buffer = zeroize::Zeroizing::new([0u8; 64]);
        let (enc_key, auth_key) = self.stretch(&mut buffer);

        // Calculate the MAC of the encrypted data and return if it's not correct
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(auth_key).unwrap();
        mac.update(&iv.0);
        mac.update(data);
        if hmac::digest::CtOutput::new(expected_hmac.0.into()) != mac.finalize() {
            return false;
        }

        // Decrypt the data
        let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(enc_key.into(), &iv.0.into());
        cipher.apply_keystream(data);
        true
    }
}

#[serde_as]
#[derive(Default, Serialize, Deserialize)]
pub struct AesIv(
    #[serde_as(as = "Base64")]
    pub [u8; AES_IV_LEN]
);

#[serde_as]
#[derive(PartialEq, Default, Serialize, Deserialize)]
pub struct Hmac(
    #[serde_as(as = "Base64")]
    pub [u8; HMAC_LEN]
);

#[serde_as]
#[derive(Default, Serialize, Deserialize)]
pub struct Salt(
    #[serde_as(as = "Base64")]
    pub [u8; SALT_LEN]
);
