
use anyhow::{ensure, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use base64::prelude::*;
use crate::fscrypt::{RawKey, KEY_LEN};

/// A byte array containing a wrapped key, used internally by a [`Protector`].
#[derive(Serialize, Deserialize, Clone)]
#[serde(try_from = "String", into = "String")]
struct WrappedKey(pub [u8; KEY_LEN]);
type Salt = WrappedKey;

impl Default for WrappedKey {
    /// Returns an array containing only zeroes.
    fn default() -> Self {
        Self([0u8; KEY_LEN])
    }
}

impl TryFrom<&str> for WrappedKey {
    type Error = anyhow::Error;
    /// Creates a [`WrappedKey`] from a base64-encoded string.
    fn try_from(s: &str) -> Result<Self> {
        let mut ret = WrappedKey::default();
        let size = BASE64_STANDARD.decode_slice(s, &mut ret.0)?;
        ensure!(size == KEY_LEN, "Incorrect length when decoding base64 data");
        Ok(ret)
    }
}

impl TryFrom<String> for WrappedKey {
    type Error = anyhow::Error;
    /// Create a key identifier from an hex string
    fn try_from(s: String) -> Result<Self> {
        Self::try_from(s.as_str())
    }
}

impl From<WrappedKey> for String {
    /// Converts a [`WrappedKey`] into a base64-encoded string.
    fn from(k: WrappedKey) -> String {
        BASE64_STANDARD.encode(k.0)
    }
}



/// A wrapped [`RawKey`] using one of several available methods
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Protector {
    /// The key is wrapped with a password.
    Password(PasswordProtector)
}

impl Protector {
    /// Unwraps the key using a password
    pub fn decrypt(&self, pass: &[u8]) -> RawKey {
        match self {
            Protector::Password(p) => p.decrypt(pass)
        }
    }
}


/// A [`Protector`] that wraps a [`RawKey`] with a password
#[derive(Serialize, Deserialize)]
pub struct PasswordProtector {
    encrypted_key: WrappedKey,
    salt: Salt,
}

impl PasswordProtector {
    /// Creates a new [`PasswordProtector`] that wraps `raw_key` with a password.
    pub fn new(raw_key: &RawKey, pass: &[u8]) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut prot = PasswordProtector {
            encrypted_key: WrappedKey(raw_key.0),
            salt: WrappedKey::default(),
        };
        rng.try_fill_bytes(&mut prot.salt.0)?;
        aes_enc_dec(pass, &prot.salt.0, &mut prot.encrypted_key.0);
        Ok(prot)
    }

    /// Unwraps a [`RawKey`] with a password.
    pub fn decrypt(&self, pass: &[u8]) -> RawKey {
        let mut raw_key = RawKey(self.encrypted_key.0);
        aes_enc_dec(pass, &self.salt.0, &mut raw_key.0);
        raw_key
    }
}


/// Encrypts / decrypts `data` using `key` and `salt`
fn aes_enc_dec(key: &[u8], salt: &[u8; KEY_LEN], data: &mut [u8; KEY_LEN]) {
    let iterations = 65535;
    let iv = [0u8; 16];

    let mut enckey = zeroize::Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<sha2::Sha512>(key, salt, iterations, &mut enckey[..]);

    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(enckey.as_ref().into(), &iv.into());
    cipher.apply_keystream(data);
}
