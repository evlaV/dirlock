
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, hex::Hex, base64::Base64};
use sha2::{Digest, Sha256, Sha512};
use zeroize;

use crate::fscrypt::PolicyKey;

pub use password::PasswordProtector as PasswordProtector;
pub use policy::WrappedPolicyKey as WrappedPolicyKey;
pub mod password;
pub mod policy;

const PROTECTOR_KEY_LEN: usize = 32;
const PROTECTOR_ID_LEN: usize = 8;
const AES_IV_LEN: usize = 16;
const HMAC_LEN: usize = 32;
const SALT_LEN: usize = 32;

/// A raw encryption key used to unwrap the master [`PolicyKey`]
/// used by fscrypt.
#[derive(Default)]
pub struct ProtectorKey([u8; PROTECTOR_KEY_LEN]);
type Aes256Key = ProtectorKey;

impl Drop for ProtectorKey {
    /// Wipes the key safely from memory on drop.
    fn drop(&mut self) {
        unsafe { zeroize::zeroize_flat_type(self) }
    }
}

impl ProtectorKey {
    /// Generates a new, random key
    pub fn new_random() -> Self {
        let mut rng = rand::thread_rng();
        let mut key = ProtectorKey::default();
        rng.try_fill_bytes(&mut key.0).unwrap();
        key
    }

    /// Generates a new key from `pass` and `salt` using a KDF
    pub(self) fn new_from_password(pass: &str, salt: &Salt) -> Self {
        let iterations = 65535;
        let mut key = ProtectorKey::default();
        pbkdf2_hmac::<sha2::Sha512>(pass.as_bytes(), &salt.0, iterations, &mut key.0);
        key
    }

    /// Calculates the ID of this key
    ///
    /// The ID is calculated by applying SHA512 twice and getting the first 8 bytes
    /// <https://github.com/google/fscrypt/blob/v0.3.5/crypto/crypto.go#L176>
    pub fn get_id(&self) -> ProtectorId {
        let hash = Sha512::digest(Sha512::digest(self.0));
        ProtectorId(hash[0..PROTECTOR_ID_LEN].try_into().unwrap())
    }
}

#[serde_as]
#[derive(Eq, PartialEq, Clone, Hash, Default, Serialize, Deserialize, derive_more::Display)]
#[display("{}", hex::encode(_0))]
pub struct ProtectorId(
    #[serde_as(as = "Hex")]
    [u8; PROTECTOR_ID_LEN]
);

#[serde_as]
#[derive(Default, Serialize, Deserialize)]
struct WrappedProtectorKey(
    #[serde_as(as = "Base64")]
    [u8; PROTECTOR_KEY_LEN]
);

#[serde_as]
#[derive(Default, Serialize, Deserialize)]
struct AesIv(
    #[serde_as(as = "Base64")]
    [u8; AES_IV_LEN]
);

#[serde_as]
#[derive(PartialEq, Default, Serialize, Deserialize)]
struct Hmac(
    #[serde_as(as = "Base64")]
    [u8; HMAC_LEN]
);

#[serde_as]
#[derive(Default, Serialize, Deserialize)]
struct Salt(
    #[serde_as(as = "Base64")]
    [u8; SALT_LEN]
);

/// A wrapped [`PolicyKey`] using one of several available methods
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Protector {
    /// The key is wrapped with a password.
    Password(PasswordProtector)
}

impl Protector {
    /// Unwraps the key using a password
    pub fn decrypt(&self, policy: &WrappedPolicyKey, pass: &str) -> Option<PolicyKey> {
        if let Some(protector_key) = match self {
            Protector::Password(p) => p.decrypt(pass)
        } {
            policy.decrypt(protector_key)
        } else {
            None
        }
    }
}

/// Stretches a 256-bit key into two new keys of the same size using HKDF
fn stretch_key<'a>(key: &Aes256Key, buffer: &'a mut [u8; 64]) -> (&'a [u8; 32], &'a [u8; 32]) {
    // Run HKDF-expand to get a 512-bit key
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &key.0);
    hkdf.expand(&[], buffer).unwrap();
    // Split the generated key in two
    let k1 : &[u8; 32] = buffer[ 0..32].try_into().unwrap();
    let k2 : &[u8; 32] = buffer[32..64].try_into().unwrap();
    (k1, k2)
}

/// Decrypts `data` using `key` and `iv`, returns whether the HMAC is valid
fn aes_dec(key: &Aes256Key, iv: &AesIv, expected_hmac: &Hmac, data: &mut [u8]) -> bool {
    // Stretch the original key to get the encryption and authentication keys
    let mut buffer = zeroize::Zeroizing::new([0u8; 64]);
    let (enc_key, auth_key) = stretch_key(key, &mut buffer);

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

/// Encrypts `data` using `key` and `iv`, returns an Hmac
fn aes_enc(key: &Aes256Key, iv: &AesIv, data: &mut [u8]) -> Hmac {
    // Stretch the original key to get the encryption and the authentication key
    let mut buffer = zeroize::Zeroizing::new([0u8; 64]);
    let (enc_key, auth_key) = stretch_key(key, &mut buffer);

    // Encrypt the data
    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(enc_key.into(), &iv.0.into());
    cipher.apply_keystream(data);

    // Calculate the MAC of the encrypted data and return it
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(auth_key).unwrap();
    mac.update(&iv.0);
    mac.update(data);
    Hmac(mac.finalize().into_bytes().into())
}
