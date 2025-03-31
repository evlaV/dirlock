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
pub(crate) enum Kdf {
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


/// The PBKDF2 key derivation function using.
///
/// This uses HMAC-SHA512 as its pseudorandom function.
#[derive(Serialize, Deserialize)]
pub(crate) struct Pbkdf2 {
    iterations: u32,
}

impl Default for Pbkdf2 {
    /// Create a PBKDF2 with the default parameters
    fn default() -> Self {
        Self { iterations: 65535 }
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
