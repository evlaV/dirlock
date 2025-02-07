
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, hex::Hex, base64::Base64};
use sha2::{Digest, Sha256, Sha512};

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
#[derive(Default, zeroize::ZeroizeOnDrop)]
pub struct ProtectorKey([u8; PROTECTOR_KEY_LEN]);
type Aes256Key = ProtectorKey;

impl From<&[u8; PROTECTOR_KEY_LEN]> for ProtectorKey {
    fn from(src: &[u8; PROTECTOR_KEY_LEN]) -> Self {
        ProtectorKey(*src)
    }
}

impl ProtectorKey {
    /// Generates a new, random key
    pub fn new_random() -> Self {
        let mut key = ProtectorKey::default();
        OsRng.fill_bytes(&mut key.0);
        key
    }

    /// Generates a new key from `pass` and `salt` using a KDF
    pub(self) fn new_from_password(pass: &[u8], salt: &Salt) -> Self {
        let iterations = 65535;
        let mut key = ProtectorKey::default();
        pbkdf2_hmac::<sha2::Sha512>(pass, &salt.0, iterations, &mut key.0);
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
    pub fn decrypt(&self, policy: &WrappedPolicyKey, pass: &[u8]) -> Option<PolicyKey> {
        if let Some(protector_key) = match self {
            Protector::Password(p) => p.decrypt(pass)
        } {
            policy.decrypt(protector_key)
        } else {
            None
        }
    }

    /// Unwraps the key using a password
    pub fn change_pass(&mut self, pass: &[u8], newpass: &[u8]) -> bool {
        match self {
            Protector::Password(p) => p.change_pass(pass, newpass)
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


#[cfg(test)]
mod tests {
    use anyhow::Result;
    use crate::fscrypt::PolicyKeyId;
    use super::*;

    // This is a helper type since ProtectorKey does not have a serializer
    #[serde_as]
    #[derive(Debug, Deserialize, PartialEq)]
    struct BitArray256(
        #[serde_as(as = "Base64")]
        [u8; 32]
    );

    // This is a helper type since PolicyKey does not have a serializer
    #[serde_as]
    #[derive(Debug, Deserialize, PartialEq)]
    struct BitArray512(
        #[serde_as(as = "Base64")]
        [u8; 64]
    );

    const PROTECTOR_KEY_DATA: &[[&str; 6]] = &[
        [
            "45f662760f9a4ee4", // ID
            "2FMmSpoV5SoreFC2vqDgVw==", // IV
            "5mmWzSlLlmMeACLeQGjueAzClQH0P+ZXGBMKPC8EbOk=", // HMAC
            "eCkomUM5GyEuOpmsCBR1+OJkPhUwstuM59+nI/XWvdw=", // Wrapped protector key
            "IjjRXA2vIOeOZy4pBnfU9DB/zi6bvTTCVR5bKiXrZsw=", // Unwrapped protector key
            "KbSmbBRnA/E/mqLreBVb7yLo2XBB5chiF416bRI25x8=", // Encryption key
        ],
        [
            "91ddfbffd352f2db", // ID
            "XXM7ZdAKDkuQhNYLzluw4Q==", // IV
            "wWqgvGPp5N9LOogXK3yDl0uSP+QxiHQUNX8glmbIrnM=", // HMAC
            "xdeQppsQOvzUhrpJy3Hzs0asVSwW6D5lay0QLDJWPt4=", // Wrapped protector key
            "DSU3OyAf1GJOk7hy0krrbozW1IaojzGoTEV7AWh9tbI=", // Unwrapped protector key
            "z8Yik+aTR31ui7bEr3LsLXTZZ1x4dqv1DPsjrOZByXU=", // Encryption key
        ],
        [
            "e92131b080789be0", // ID
            "I4OGz0Vud4BIRDoykvXlIw==", // IV
            "DiRTZn0cEcHXYhkFEsXPR+CAyQb3+FhiR9nrk1Oe+7g=", // HMAC
            "hMuNheZAX6p2Hy4Yb2zlYos4UKWf2O+DGbTxEDaYokU=", // Wrapped protector key
            "Vxex6JJqg6vmLdsIdzAMSnOYtbRE6wt6Zh5XyV7kXP8=", // Unwrapped protector key
            "xQ5ajPBjJZIQjbv1X0P13QKVJJrel/FHSsSLvwqQOBc=", // Encryption key
        ],
    ];

    const POLICY_KEY_DATA: &[[&str; 6]] = &[
        [
            "44296e317ea4901bb65e63fa18b3ef3f", // ID
            "yhIyp2REHf4irH5b0KZPVA==", // IV
            "jiBUrJsnewWefawjeS85gicTZ040lSWNf0Eqtr2nD5g=", // HMAC
            "gZNSLR4Xt5eQ9AbhAgGi+Uw6irG9cTraCuzyO9JLyBewOvymt/ow2a4oxOJGaBeLntmdFtnLUrzHMp6eKeCcHw==", // Wrapped policy key
            "yFKWvJeTHRltW9AvYeMoN8yVHaiIsvAlBE+EZ4w01kzDun6JQtDoitrkVVILUAYDlnCqWI4GcjmO/VFCafQ+ZA==", // Unwrapped policy key
            "IjjRXA2vIOeOZy4pBnfU9DB/zi6bvTTCVR5bKiXrZsw=", // Encryption key
        ],
        [
            "44296e317ea4901bb65e63fa18b3ef3f", // ID
            "cWD2v3TnrIT5z7AE+A5V+Q==", // IV
            "IFDOTmqLRSSs914PocEixJHKznwM0o6BPBylYNUoxXY=", // HMAC
            "sPlza3l9W93hEnOX+ijajody7cMmoRJYx7XTCezXs15Qemyc3ze6b9ARVYTKbZVIHz21PEmLryTodJjP0M0MPw==", // Wrapped policy key
            "yFKWvJeTHRltW9AvYeMoN8yVHaiIsvAlBE+EZ4w01kzDun6JQtDoitrkVVILUAYDlnCqWI4GcjmO/VFCafQ+ZA==", // Unwrapped policy key
            "DSU3OyAf1GJOk7hy0krrbozW1IaojzGoTEV7AWh9tbI=", // Encryption key
        ],
        [
            "2facace02c557629f5d12345d679bbf4", // ID
            "WW33jPn8IIwk9Wjxicm/Yw==", // IV
            "qJaEBSat4SQbeKXzaCBps9t2VZyNlRxF3ftx4dQrTB4=", // HMAC
            "8/CE6xXRqr73fV5jQxNOhrmJIBl3j30b1xpZqOc70yZFEl8WdZGc6C19Ft76yUNHHhMGi48bTbQyFJWFtWai9A==", // Wrapped policy key
            "/bRzVPF8E3/2TAcpvPRutVjv+R2u/cuZ0/OqW597obFeM/09FQnngRgXCWVX2BeRB37ltjgUxiQz+mhh7rP16g==", // Unwrapped policy key
            "Od+GTt0t3Z6mlxWHGcnFHlXKPf88wcWlihfa3y3p0Lg=", // Encryption key
        ],
    ];

    fn decode<T>(s: &str) -> T
    where
        T: for <'a> serde::de::Deserialize<'a>
    {
        let json_str = format!("\"{}\"", s);
        serde_json::from_str::<T>(&json_str).expect(&format!("Error decoding {s}"))
    }

    #[test]
    fn test_protector_key() -> Result<()> {
        for key in PROTECTOR_KEY_DATA {
            let protector_id = decode::<ProtectorId>(key[0]);
            let aes_iv = decode::<AesIv>(key[1]);
            let hmac = decode::<Hmac>(key[2]);
            let wrapped_key = decode::<BitArray256>(key[3]);
            let unwrapped_key = decode::<BitArray256>(key[4]);
            let enc_key = Aes256Key::from(&decode::<BitArray256>(key[5]).0);

            // Start with the wrapped key
            let mut data = BitArray256(wrapped_key.0);
            // Unwrap it and validate the HMAC
            assert!(aes_dec(&enc_key, &aes_iv, &hmac, &mut data.0), "HMAC validation failed");
            // Check the key we just unwrapped
            assert_eq!(data, unwrapped_key, "Unwrapped key doesn't match the expected value");
            // Check the key ID
            assert_eq!(ProtectorKey::from(&data.0).get_id().0, protector_id.0, "Protector ID doesn't match the expected value");
            // Wrap the key again and validate the HMAC
            assert_eq!(aes_enc(&enc_key, &aes_iv, &mut data.0).0, hmac.0, "HMAC validation failed");
            // Check the key we just wrapped
            assert_eq!(data, wrapped_key, "Wrapped key doesn't match the expected value");
        }

        Ok(())
    }

    #[test]
    fn test_policy_key() -> Result<()> {
        for key in POLICY_KEY_DATA {
            let policy_id = decode::<PolicyKeyId>(key[0]);
            let aes_iv = decode::<AesIv>(key[1]);
            let hmac = decode::<Hmac>(key[2]);
            let wrapped_key = decode::<BitArray512>(key[3]);
            let unwrapped_key = decode::<BitArray512>(key[4]);
            let enc_key = Aes256Key::from(&decode::<BitArray256>(key[5]).0);

            // Start with the wrapped key
            let mut data = BitArray512(wrapped_key.0);
            // Unwrap it and validate the HMAC
            assert!(aes_dec(&enc_key, &aes_iv, &hmac, &mut data.0), "HMAC validation failed");
            // Check the key we just unwrapped
            assert_eq!(data, unwrapped_key, "Unwrapped key doesn't match the expected value");
            // Check the key ID
            assert_eq!(PolicyKey::from(&data.0).get_id(), policy_id, "Policy ID doesn't match the expected value");
            // Wrap the key again and validate the HMAC
            assert_eq!(aes_enc(&enc_key, &aes_iv, &mut data.0).0, hmac.0, "HMAC validation failed");
            // Check the key we just wrapped
            assert_eq!(data, wrapped_key, "Wrapped key doesn't match the expected value");
        }

        Ok(())
    }
}
