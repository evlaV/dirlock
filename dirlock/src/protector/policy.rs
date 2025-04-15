/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};

use crate::{
    fscrypt::{
        POLICY_KEY_LEN,
        PolicyKey,
    },
    protector::{
        ProtectorKey,
    },
    crypto::{
        AesIv,
        Hmac,
    },
};

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct WrappedPolicyKey {
    #[serde_as(as = "Base64")]
    wrapped_key: [u8; POLICY_KEY_LEN],
    iv: AesIv,
    hmac: Hmac,
}

impl WrappedPolicyKey {
    /// Creates a new [`WrappedPolicyKey`] that wraps a [`PolicyKey`] with a [`ProtectorKey`]
    pub fn new(mut raw_key: PolicyKey, protector_key: &ProtectorKey) -> Self {
        let mut iv = AesIv::default();
        OsRng.fill_bytes(&mut iv.0);
        let hmac = protector_key.0.encrypt(&iv, raw_key.secret_mut());
        WrappedPolicyKey{ wrapped_key: *raw_key.secret(), iv, hmac }
    }

    /// Unwraps a [`PolicyKey`] with a [`ProtectorKey`]
    pub fn unwrap_key(&self, protector_key: ProtectorKey) -> Option<PolicyKey> {
        let mut raw_key = PolicyKey::from(&self.wrapped_key);
        if protector_key.0.decrypt(&self.iv, &self.hmac, raw_key.secret_mut()) {
            Some(raw_key)
        } else {
            None
        }
    }
}
