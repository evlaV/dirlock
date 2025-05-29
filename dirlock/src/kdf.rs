/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use pbkdf2::pbkdf2_hmac;
use serde::{Serialize, Deserialize};

/// A key derivation function
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Kdf {
    Pbkdf2(Pbkdf2),
}

impl Default for Kdf {
    /// Get the default KDF
    fn default() -> Self {
        Self::Pbkdf2(Pbkdf2::default())
    }
}

impl Kdf {
    /// Derive a password using a salt
    pub fn derive(&self, pass: &[u8], salt: &[u8], result: &mut [u8]) {
        match self {
            Kdf::Pbkdf2(f) => f.derive(pass, salt, result)
        }
    }
}


/// The PBKDF2 key derivation function.
///
/// This uses HMAC-SHA512 as its pseudorandom function.
#[derive(Serialize, Deserialize)]
pub struct Pbkdf2 {
    iterations: u32,
}

impl Default for Pbkdf2 {
    /// Create a PBKDF2 with the default parameters
    fn default() -> Self {
        Self { iterations: 1000000 }
    }
}

impl Pbkdf2 {
    pub fn new(iterations: u32) -> Self {
        Self { iterations }
    }

    /// Derive a password using a salt
    pub fn derive(&self, pass: &[u8], salt: &[u8], result: &mut [u8]) {
        pbkdf2_hmac::<sha2::Sha512>(pass, salt, self.iterations, result);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use base64::prelude::*;
    use super::Pbkdf2;

    const PBKDF2_DATA: &[[&str; 5]] = &[
        [
            "1234", // password
            "vdntwBKZ5ahXJly/1wNhyZzYKS13byCW22Lt/YQgMQE=", // salt
            "65535", // iterations
            "32", // output length
            "RMHUPAZRCII9HBuA3LvxcUWrdChXqS5J46tOBmNJQkM=", // expected result
        ],
        [
            "3rogOH9HcseUlJP0n2NcYpA7KIcxEtPq", // password
            "zDF2am9A9I3TxPCRuNeTwnbmMtfK9Tgq53Gl8e0fDek=", // salt
            "1000000", // iterations
            "64", // output length
            "ZMmGN7V7qj+qtzgZYCtUnaTnX3ICAqAP6rIJvWaEceNVilaWKQ3PofHtie8tRrYOtwVpWxaIbD2SZkyL9QXwlQ==", // expected result
        ],
        [
            "aPQ8jMpc", // password
            "Ig35AsUoPr8=", // salt
            "50", // iterations
            "16", // output length
            "ZdPyXwhKywPAihNOjJtQqg==", // expected result
        ],
    ];

    #[test]
    fn test_pbkdf2() -> Result<()> {
        for item in PBKDF2_DATA {
            let pass = item[0].as_bytes();
            let salt = BASE64_STANDARD.decode(item[1]).unwrap();
            let iter = str::parse(item[2]).unwrap();
            let len = str::parse(item[3]).unwrap();
            let expected = BASE64_STANDARD.decode(item[4]).unwrap();

            let mut result = vec![0u8; len];

            let kdf = Pbkdf2::new(iter);
            kdf.derive(pass, &salt, &mut result);
            assert_eq!(result, expected, "PBKDF2 output doesn't match the expected value");
        }

        Ok(())
    }
}
