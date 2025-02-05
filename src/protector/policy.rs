
use anyhow::Result;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};

use crate::{
    fscrypt::{
        POLICY_KEY_LEN,
        PolicyKey,
    },
    protector::{
        AesIv,
        Hmac,
        ProtectorKey,
        aes_dec,
        aes_enc,
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
    pub fn new(raw_key: PolicyKey, protector_key: &ProtectorKey) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut prot = WrappedPolicyKey {
            wrapped_key: *raw_key.as_ref(),
            iv: AesIv::default(),
            hmac: Hmac::default(),
        };
        rng.try_fill_bytes(&mut prot.iv.0)?;
        prot.hmac = aes_enc(protector_key, &prot.iv, &mut prot.wrapped_key);
        Ok(prot)
    }

    /// Unwraps a [`PolicyKey`] with a [`ProtectorKey`]
    pub fn decrypt(&self, protector_key: ProtectorKey) -> Option<PolicyKey> {
        let mut raw_key = PolicyKey::from(&self.wrapped_key);
        if aes_dec(&protector_key, &self.iv, &self.hmac, raw_key.as_mut()) {
            Some(raw_key)
        } else {
            None
        }
    }
}
