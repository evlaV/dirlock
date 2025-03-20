/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, Result};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};

#[cfg(feature = "tpm2")]
use {
    anyhow::anyhow,
    rand::{RngCore, rngs::OsRng},
    std::fmt,
    tss_esapi::{
        Context,
        TctiNameConf,
        attributes::ObjectAttributesBuilder,
        constants::{
            CapabilityType,
            PropertyTag,
            tss,
        },
        handles::{
            KeyHandle,
            ObjectHandle,
        },
        interface_types::{
            algorithm::{
                HashingAlgorithm,
                PublicAlgorithm,
            },
            ecc::EccCurve,
            resource_handles::Hierarchy,
        },
        structures::{
            Auth,
            CapabilityData,
            Digest,
            EccPoint,
            EccScheme,
            KeyDerivationFunctionScheme,
            KeyedHashScheme,
            Private,
            Public,
            PublicBuffer,
            PublicBuilder,
            PublicEccParameters,
            PublicKeyedHashParameters,
            SensitiveData,
            SymmetricDefinitionObject,
        },
        tcti_ldr::DeviceConfig,
        traits::{Marshall, UnMarshall},
    },
    tss_esapi_sys::TPM2B_PRIVATE,
};

use crate::{
    protector::{
        ProtectorKey,
        Salt,
    },
};

/// A [`Protector`] that wraps a [`ProtectorKey`] using a TPM
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Tpm2Protector {
    #[serde_as(as = "Base64")]
    public: Vec<u8>,
    #[serde_as(as = "Base64")]
    private: Vec<u8>,
    salt: Salt,
}

// Stub used when the tpm2 feature is disabled
#[cfg(not(feature = "tpm2"))]
impl Tpm2Protector {
    pub fn new(_raw_key: ProtectorKey, _pass: &[u8]) -> Result<Self> {
        bail!("TPM support is disabled");
    }

    pub fn unwrap_key(&self, _pass: &[u8]) -> Result<Option<ProtectorKey>> {
        bail!("TPM support is disabled");
    }

    pub fn change_pass(&mut self, _pass: &[u8], _newpass: &[u8]) -> bool {
        false
    }
}

#[cfg(feature = "tpm2")]
impl Tpm2Protector {
    /// Creates a new [`Tpm2Protector`] that wraps a [`ProtectorKey`] with a password.
    pub fn new(raw_key: ProtectorKey, pass: &[u8]) -> Result<Self> {
        let mut ctx = Context::new(TctiNameConf::Device(DeviceConfig::default()))
            .map_err(|e| anyhow!("Unable to access the TPM: {e}"))?;
        let primary_key = create_primary_key(&mut ctx)?;
        let mut salt = Salt::default();
        OsRng.fill_bytes(&mut salt.0);
        let auth = derive_auth_value(pass, &salt);
        let (public, private) = seal_data(ctx, primary_key, raw_key.secret(), auth)?;
        let result = Tpm2Protector {
            public: PublicBuffer::try_from(public)?.marshall()?,
            private: tpm_private_marshall(private)?,
            salt
        };
        Ok(result)
    }

    /// Unwraps a [`ProtectorKey`] with a password.
    pub fn unwrap_key(&self, pass: &[u8]) -> Result<Option<ProtectorKey>> {
        let mut ctx = Context::new(TctiNameConf::Device(DeviceConfig::default()))
            .map_err(|e| anyhow!("Unable to access the TPM: {e}"))?;
        let primary_key = create_primary_key(&mut ctx)?;
        let public = Public::try_from(PublicBuffer::unmarshall(&self.public)?)?;
        let private = tpm_private_unmarshall(&self.private)?;
        let auth = derive_auth_value(pass, &self.salt);
        let Ok(data) = unseal_data(ctx, primary_key, public, private, auth) else {
            return Ok(None);
        };
        let raw_data : &[u8; 32] = data.value().try_into()?;
        Ok(Some(ProtectorKey::from(raw_data)))
    }

    /// Changes the password of this protector
    pub fn change_pass(&mut self, pass: &[u8], newpass: &[u8]) -> bool {
        if let Ok(Some(raw_key)) = self.unwrap_key(pass) {
            if let Ok(newprot) = Tpm2Protector::new(raw_key, newpass) {
                *self = newprot;
                return true;
            }
        }
        false
    }
}

/// Marshall the Private struct into a vector
///
/// We do this manually because this version of tss-esapi does not
/// have direct API for that.
#[cfg(feature = "tpm2")]
fn tpm_private_marshall(data: Private) -> Result<Vec<u8>> {
    const BUFFER_SIZE: usize = size_of::<TPM2B_PRIVATE>();

    // The result goes here
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut offset = 0;

    let ret = unsafe { tss_esapi_sys::Tss2_MU_TPM2B_PRIVATE_Marshal(
        &TPM2B_PRIVATE::from(data),
        buffer.as_mut_ptr(),
        BUFFER_SIZE.try_into()?,
        &mut offset,
    )};

    if ret != tss::TPM2_RC_SUCCESS {
        bail!("Error marshalling the TPM-sealed data");
    }

    buffer.truncate(offset.try_into()?);

    Ok(buffer)
}

/// Unmarshall a Private struct from a vector
///
/// We do this manually because this version of tss-esapi does not
/// have direct API for that.
#[cfg(feature = "tpm2")]
fn tpm_private_unmarshall(data: &[u8]) -> Result<Private> {
    let mut tpm2b_priv = TPM2B_PRIVATE::default();
    let mut offset = 0;

    let ret = unsafe { tss_esapi_sys::Tss2_MU_TPM2B_PRIVATE_Unmarshal(
        data.as_ptr(),
        data.len().try_into()?,
        &mut offset,
        &mut tpm2b_priv,
    )};

    if ret != tss::TPM2_RC_SUCCESS {
        bail!("Error unmarshalling the TPM-sealed data");
    }

    Ok(Private::try_from(tpm2b_priv)?)
}

/// Derive a TPM authentication value from a password and a salt
#[cfg(feature = "tpm2")]
fn derive_auth_value(pass: &[u8], salt: &Salt) -> Auth {
    let iterations = 65535;
    let mut data = zeroize::Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pass, &salt.0, iterations, data.as_mut());
    Auth::try_from(data.as_ref()).unwrap()
}

/// Create the primary key that we'll use to encrypt the actual data.
///
/// This function will always return the same key as long as the
/// provided parameters don't change and the TPM is not reset.
#[cfg(feature = "tpm2")]
fn create_primary_key(ctx: &mut Context) -> Result<KeyHandle> {
    // "TCG TPM v2.0 Provisioning Guidance" version 1.0, revision 1.0
    // https://trustedcomputinggroup.org/resource/tcg-tpm-v2-0-provisioning-guidance/

    // "TCG EK Credential Profile For TPM Family 2.0; Level 0" version 2.6
    // https://trustedcomputinggroup.org/resource/http-trustedcomputinggroup-org-wp-content-uploads-tcg-ek-credential-profile-v-2-5-r2_published-pdf/

    // "TCG EK Credential Profile" section B.4 (attributes shared by all templates),
    // with changes specified in "TCG TPM v2.0 Provisioning Guidance" section 7.5.1:
    // "set the userWithAuth bit, clear the adminWithPolicy bit, and set the noDA bit".
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_admin_with_policy(false)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;

    // "TCG EK Credential Profile" section B.4
    // Template H-2: ECC NIST P256 (Storage)
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(PublicEccParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
            EccScheme::Null,
            EccCurve::NistP256,
            KeyDerivationFunctionScheme::Null,
        ))
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?;

    let result = ctx.execute_with_nullauth_session(|c| {
        c.create_primary(Hierarchy::Owner, public, None, None, None, None)
    })?;

    Ok(result.key_handle)
}

/// Seal data using the given primary key. Access to that data is protected with a password and a salt.
#[cfg(feature = "tpm2")]
fn seal_data(mut ctx: Context, primary_key: KeyHandle, data: &[u8], auth: Auth) -> Result<(Public, Private)> {
    let sensitive = SensitiveData::try_from(data)?;

    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true) // TODO: clear this bit once we use a policy for authentication
        .build()?;

    // The way to seal data is with a KeyedHash object with a null hash scheme.
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()?;

    let sealed = ctx.execute_with_nullauth_session(|c| {
        c.create(primary_key, public, Some(auth), Some(sensitive), None, None)
    })?;

    Ok((sealed.out_public, sealed.out_private))
}

/// Unseal data previously sealed with the given primary key.
#[cfg(feature = "tpm2")]
fn unseal_data(mut ctx: Context, primary_key: KeyHandle, sealed_pub: Public, sealed_priv: Private, auth: Auth) -> Result<SensitiveData> {
    let unsealed = ctx.execute_with_nullauth_session(|c| {
        let obj : ObjectHandle = c.load(primary_key, sealed_priv, sealed_pub)?.into();
        c.tr_set_auth(obj, auth)?;
        c.unseal(obj)
    })?;

    Ok(unsealed)
}

#[cfg(feature = "tpm2")]
pub struct TpmStatus {
    pub manufacturer: String,
    pub lockout_counter: u32,
    pub max_auth_fail: u32,
    pub lockout_interval: u32,
}

#[cfg(feature = "tpm2")]
impl fmt::Display for TpmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Manufacturer: {}\n\
                   Lockout counter: {} / {}\n\
                   Counter decreased every {} seconds",
               self.manufacturer,
               self.lockout_counter,
               self.max_auth_fail,
               self.lockout_interval)
    }
}

#[cfg(feature = "tpm2")]
pub fn get_status() -> Result<TpmStatus> {
    use PropertyTag::*;

    let mut ctx = Context::new(TctiNameConf::Device(DeviceConfig::default()))
        .map_err(|e| anyhow!("Unable to access the TPM: {e}"))?;

    let manufacturer = if let Some(val) = ctx.get_tpm_property(Manufacturer)? {
        val.to_be_bytes().iter()
            .filter(|x| **x != 0)
            .map(|x| char::from(*x))
            .collect()
    } else {
        String::from("Unknown")
    };

    let caps = ctx.get_capability(CapabilityType::TpmProperties, tss::TPM2_PT_LOCKOUT_COUNTER, 4)?;

    if let (CapabilityData::TpmProperties(data), _) = caps {
        let props = [LockoutCounter, MaxAuthFail, LockoutInterval];
        let values : Vec<_> = props.iter()
            .filter_map(|p| data.find(*p))
            .map(|p| p.value())
            .collect();

        if props.len() == values.len() {
            return Ok(TpmStatus {
                manufacturer,
                lockout_counter: values[0],
                max_auth_fail: values[1],
                lockout_interval: values[2],
            });
        }
    }

    Err(anyhow!("Error getting the status of the TPM"))
}

#[cfg(not(feature = "tpm2"))]
pub fn get_status() -> Result<&'static str> {
    Ok("TPM support not enabled")
}
