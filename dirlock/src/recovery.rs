/*
 * Copyright © 2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, Result};

use crate::{
    modhex,
    protector::ProtectorKey,
};

/// A recovery key is just a random protector key meant to be entered
/// directly by the user. We display it using modhex encoding.
#[derive(derive_more::Display)]
#[display("{}", modhex::encode(_0.secret()))]
pub struct RecoveryKey(ProtectorKey);

impl RecoveryKey {
    pub fn new_random() -> Self {
        RecoveryKey(ProtectorKey::new_random())
    }

    /// `bytes` contain the modhex-encoded recovery key.
    pub fn from_ascii_bytes(bytes: &[u8]) -> Result<Self> {
        let mut key = ProtectorKey::default();
        modhex::decode_ascii_bytes_into(bytes, key.secret_mut())
            .map_err(|e| anyhow!("Invalid recovery key: {e}"))?;
        Ok(RecoveryKey(key))
    }

    pub fn protector_key(&self) -> &ProtectorKey {
        &self.0
    }

    pub fn into_protector_key(self) -> ProtectorKey {
        self.0
    }
}
