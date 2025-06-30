/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, Result};
use opts::ProtectorOpts;
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, hex::Hex};
use sha2::{Digest, Sha512};
use std::cmp;
use std::fmt;

use crate::crypto::{
    Aes256Key,
    Salt,
};
use crate::policy::{
    PolicyKey,
    WrappedPolicyKey,
};

pub use fido2::Fido2Protector as Fido2Protector;
pub use password::PasswordProtector as PasswordProtector;
pub use tpm2::Tpm2Protector as Tpm2Protector;
pub mod fido2;
pub mod password;
pub mod tpm2;
pub mod opts;

const PROTECTOR_KEY_LEN: usize = 32;
const PROTECTOR_ID_LEN: usize = 8;

/// A raw encryption key used to unwrap the master [`PolicyKey`]
/// used by fscrypt.
#[derive(Clone)]
pub struct ProtectorKey(Aes256Key);

impl From<&[u8; PROTECTOR_KEY_LEN]> for ProtectorKey {
    fn from(src: &[u8; PROTECTOR_KEY_LEN]) -> Self {
        ProtectorKey(Aes256Key::from(src))
    }
}

impl ProtectorKey {
    /// Return a reference to the data
    pub fn secret(&self) -> &[u8; PROTECTOR_KEY_LEN] {
        self.0.secret()
    }

    /// Return a mutable reference to the data
    pub fn secret_mut(&mut self) -> &mut [u8; PROTECTOR_KEY_LEN] {
        self.0.secret_mut()
    }

    /// Return a reference to the [`Aes256Key`]
    pub fn key(&self) -> &Aes256Key {
        &self.0
    }

    /// Generates a new, random key
    pub fn new_random() -> Self {
        ProtectorKey(Aes256Key::new_random())
    }

    /// Calculates the ID of this key
    ///
    /// The ID is calculated by applying SHA512 twice and getting the first 8 bytes
    /// <https://github.com/google/fscrypt/blob/v0.3.5/crypto/crypto.go#L176>
    pub fn get_id(&self) -> ProtectorId {
        let hash = Sha512::digest(Sha512::digest(self.secret()));
        ProtectorId(hash[0..PROTECTOR_ID_LEN].try_into().unwrap())
    }
}

#[serde_as]
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Hash, Default, Serialize, Deserialize, derive_more::Display)]
#[display("{}", hex::encode(_0))]
pub struct ProtectorId(
    #[serde_as(as = "Hex")]
    [u8; PROTECTOR_ID_LEN]
);

impl std::str::FromStr for ProtectorId {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut ret = ProtectorId::default();
        hex::decode_to_slice(s, &mut ret.0)
            .map_err(|_| anyhow!("Invalid protector ID: {s}"))?;
        Ok(ret)
    }
}


/// A wrapped [`PolicyKey`] together with a [`Protector`] that can unwrap it
pub struct ProtectedPolicyKey {
    pub protector: Protector,
    pub policy_key: WrappedPolicyKey,
}


/// An enum of the existing protector types
// The order is used to decide which protector to use first in the
// cases where the user didn't select a specific one (notably PAM).
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProtectorType {
    Fido2,
    Tpm2,
    Password,
}

const PROTECTOR_TYPE_NAMES: &[(&str, ProtectorType, &str)] = &[
    ("fido2", ProtectorType::Fido2, "FIDO2 PIN"),
    ("password", ProtectorType::Password, "password"),
    ("tpm2", ProtectorType::Tpm2, "TPM2 PIN"),
];

impl fmt::Display for ProtectorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = PROTECTOR_TYPE_NAMES.iter()
            .find(|x| &x.1 == self)
            .map(|x| x.0)
            .unwrap();
        write!(f, "{name}")
    }
}

impl std::str::FromStr for ProtectorType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        PROTECTOR_TYPE_NAMES.iter()
            .find(|x| x.0 == s)
            .map(|x| x.1)
            .ok_or(anyhow!("Unknown protector type '{s}'. Available types: {}",
                           PROTECTOR_TYPE_NAMES.iter()
                           .map(|x| x.0)
                           .collect::<Vec<_>>().join(", ")))
    }
}

impl ProtectorType {
    pub fn credential_name(&self) -> &'static str {
        PROTECTOR_TYPE_NAMES.iter()
            .find(|x| &x.1 == self)
            .map(|x| x.2)
            .unwrap()
    }
}


/// A wrapped [`ProtectorKey`] using one of several available methods
pub struct Protector {
    pub id: ProtectorId,
    pub(crate) data: ProtectorData,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum ProtectorData {
    /// The key is wrapped by a FIDO2 token.
    Fido2(Fido2Protector),
    /// The key is wrapped with a password.
    Password(PasswordProtector),
    /// The key is wrapped by the TPM.
    Tpm2(Tpm2Protector),
}

impl Protector {
    pub fn new(opts: ProtectorOpts, raw_key: ProtectorKey, pass: &[u8]) -> Result<Self> {
        let id = raw_key.get_id();
        let data = match opts {
            ProtectorOpts::Password(pw_opts) => ProtectorData::Password(PasswordProtector::new(pw_opts,raw_key, pass)),
            ProtectorOpts::Tpm2(tpm2_opts) => ProtectorData::Tpm2(Tpm2Protector::new(tpm2_opts, raw_key, pass)?),
            ProtectorOpts::Fido2(fido2_opts) => ProtectorData::Fido2(Fido2Protector::new(fido2_opts, raw_key, pass)?),
        };
        Ok(Protector { id, data })
    }

    /// Unwraps this protector's [`ProtectorKey`] using a password
    pub fn unwrap_key(&self, pass: &[u8]) -> Result<Option<ProtectorKey>> {
        match &self.data {
            ProtectorData::Password(p) => Ok(p.unwrap_key(pass)),
            ProtectorData::Tpm2(p) => p.unwrap_key(pass),
            ProtectorData::Fido2(p) => p.unwrap_key(pass),
        }
    }

    /// Unwraps a [`PolicyKey`] using this protector's key
    pub fn unwrap_policy_key(&self, policy: &WrappedPolicyKey, pass: &[u8]) -> Result<Option<PolicyKey>> {
        Ok(self.unwrap_key(pass)?.and_then(|k| policy.unwrap_key(&k)))
    }

    /// Wraps this protector's [`ProtectorKey`] again using a new password
    pub fn wrap_key(&mut self, key: ProtectorKey, pass: &[u8]) -> Result<()> {
        if key.get_id() != self.id {
            bail!("This key doesn't belong to this protector");
        }
        match self.data {
            ProtectorData::Password(ref mut p) => p.wrap_key(key, pass),
            ProtectorData::Tpm2(ref mut p) => p.wrap_key(key, pass)?,
            ProtectorData::Fido2(_) => bail!("Cannot change the PIN of the FIDO2 token"),
        }
        Ok(())
    }

    /// Gets the name of this protector
    pub fn get_name(&self) -> &str {
        match &self.data {
            ProtectorData::Password(p) => &p.name,
            ProtectorData::Tpm2(p) => &p.name,
            ProtectorData::Fido2(p) => &p.name,
        }
    }

    /// Gets the type of this protector
    pub fn get_type(&self) -> ProtectorType {
        match self.data {
            ProtectorData::Password(_) => ProtectorType::Password,
            ProtectorData::Tpm2(_) => ProtectorType::Tpm2,
            ProtectorData::Fido2(_) => ProtectorType::Fido2,
        }
    }

    /// Returns the text used to prompt the user for a password or PIN
    ///
    /// # Errors
    /// Returns the string message to show to the user if the protector cannot be used
    pub fn get_prompt(&self) -> Result<String, String> {
        match &self.data {
            ProtectorData::Password(_) => Ok(String::from("Enter password")),
            ProtectorData::Tpm2(p) => p.get_prompt(),
            ProtectorData::Fido2(p) => p.get_prompt(),
        }
    }

    /// Returns whether the protector can change its PIN / password
    pub fn can_change_password(&self) -> bool {
        match &self.data {
            ProtectorData::Password(_) => true,
            ProtectorData::Tpm2(_) => true,
            ProtectorData::Fido2(_) => false,
        }
    }

    /// Returns whether the protector needs a PIN / password to unlock its key
    pub fn needs_password(&self) -> bool {
        match &self.data {
            ProtectorData::Password(_) => true,
            ProtectorData::Tpm2(_) => true,
            ProtectorData::Fido2(p) => p.pin,
        }
    }

    /// Returns whether the protector is available to be used
    pub fn is_available(&self) -> bool {
        match &self.data {
            ProtectorData::Password(_) => true,
            ProtectorData::Tpm2(_) => true,
            ProtectorData::Fido2(p) => p.is_available(),
        }
    }
}

impl cmp::Ord for Protector {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.get_type().cmp(&other.get_type()) {
            cmp::Ordering::Equal => self.id.cmp(&other.id),
            x => x,
        }
    }
}

impl cmp::PartialOrd for Protector {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::PartialEq for Protector {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl cmp::Eq for Protector { }



#[cfg(test)]
mod tests {
    use crate::crypto::{AesIv, Hmac};
    use crate::fscrypt::PolicyKeyId;
    use opts::ProtectorOptsBuilder;
    use rand::{RngCore, rngs::OsRng};
    use serde_with::{serde_as, base64::Base64};
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
            assert!(enc_key.decrypt(&aes_iv, &hmac, &mut data.0), "HMAC validation failed");
            // Check the key we just unwrapped
            assert_eq!(data, unwrapped_key, "Unwrapped key doesn't match the expected value");
            // Check the key ID
            assert_eq!(ProtectorKey::from(&data.0).get_id().0, protector_id.0, "Protector ID doesn't match the expected value");
            // Wrap the key again and validate the HMAC
            assert_eq!(enc_key.encrypt(&aes_iv, &mut data.0).0, hmac.0, "HMAC validation failed");
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
            assert!(enc_key.decrypt(&aes_iv, &hmac, &mut data.0), "HMAC validation failed");
            // Check the key we just unwrapped
            assert_eq!(data, unwrapped_key, "Unwrapped key doesn't match the expected value");
            // Check the key ID
            assert_eq!(PolicyKey::from(&data.0).get_id(), policy_id, "Policy ID doesn't match the expected value");
            // Wrap the key again and validate the HMAC
            assert_eq!(enc_key.encrypt(&aes_iv, &mut data.0).0, hmac.0, "HMAC validation failed");
            // Check the key we just wrapped
            assert_eq!(data, wrapped_key, "Wrapped key doesn't match the expected value");
        }

        Ok(())
    }

    #[test]
    fn test_protectors() -> Result<()> {
        let tpm = tpm2::tests::Swtpm::new(7982)?;
        for t in PROTECTOR_TYPE_NAMES {
            let ptype = t.1;

            // Test the ProtectorType API and the PROTECTOR_TYPE_NAMES array
            assert_eq!(ptype.to_string(), t.0);
            assert!   (ptype == str::parse(t.0).unwrap());
            assert_eq!(ptype.credential_name(), t.2);

            if ptype == ProtectorType::Tpm2 && cfg!(not(feature = "tpm2")) {
                continue;
            }

            // We don't have tests for Fido2 protectors yet
            if ptype == ProtectorType::Fido2 {
                continue;
            }

            let tcti_conf = match ptype {
                ProtectorType::Tpm2 => Some(tpm.tcti_conf().to_string()),
                _ => None
            };

            for i in 1..=5 {
                // Use a different password in each iteration
                let mut pass = vec![0u8; 8 + i];
                OsRng.fill_bytes(&mut pass);

                // Change the number of iterations in each test.
                let opts = ProtectorOptsBuilder::new()
                    .with_type(Some(ptype))
                    .with_kdf_iter(std::num::NonZeroU32::new((i * 50) as u32))
                    .with_name(format!("test {i}, type {ptype}"))
                    .with_tpm2_tcti(tcti_conf.clone())
                    .build().unwrap();

                // Generate random keys to wrap
                let protkey = ProtectorKey::new_random();
                let polkey = PolicyKey::new_random();
                let wrapped_polkey = WrappedPolicyKey::new(polkey.clone(), &protkey);

                // Create a protector
                let mut prot = Protector::new(opts, protkey.clone(), &pass).unwrap();
                assert!(ptype == prot.get_type());

                // Unwrap the protector key and compare the results
                let result = prot.unwrap_key(&pass)?;
                assert!(result.is_some(), "Failed to unwrap key with protector {}", prot.get_name());
                assert_eq!(protkey.secret(), result.unwrap().secret(),
                           "Unexpected result when unwrapping key with protector {}", prot.get_name());

                // Wrap the protector key again with a different password
                let mut pass2 = pass.clone();
                pass2.push(b'A');
                prot.wrap_key(protkey, &pass2).unwrap();

                // Unwrap the policy key and compare the results
                let result = prot.unwrap_policy_key(&wrapped_polkey, &pass2)?;
                assert!(result.is_some(), "Failed to unwrap policy key with protector {}", prot.get_name());
                assert_eq!(polkey.secret(), result.unwrap().secret(),
                           "Unexpected result when unwrapping policy key with protector {}", prot.get_name());

                // Test that invalid passwords (the original password in this case) are also handled correctly.
                assert!(prot.unwrap_key(&pass)?.is_none());
                assert!(prot.unwrap_policy_key(&wrapped_polkey, &pass)?.is_none());
            }
        }
        Ok(())
    }
}
