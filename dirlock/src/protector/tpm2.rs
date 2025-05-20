/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, Result};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, base64::Base64};
use crate::kdf::Kdf;

#[cfg(feature = "tpm2")]
use {
    anyhow::anyhow,
    crate::config::Config,
    crate::kdf::Pbkdf2,
    rand::{RngCore, rngs::OsRng},
    std::cell::OnceCell,
    std::str::FromStr,
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
        traits::{Marshall, UnMarshall},
    },
    tss_esapi_sys::TPM2B_PRIVATE,
};

use crate::{
    protector::{
        ProtectorKey,
        Salt,
        opts::Tpm2Opts,
    },
};

#[cfg(doc)]
use crate::protector::Protector;

/// A [`Protector`] that wraps a [`ProtectorKey`] using a TPM
#[serde_as]
#[derive(Serialize, Deserialize, Default)]
pub struct Tpm2Protector {
    pub name: String,
    #[serde_as(as = "Base64")]
    public: Vec<u8>,
    #[serde_as(as = "Base64")]
    private: Vec<u8>,
    salt: Salt,
    kdf: Kdf,
    #[serde(skip)]
    #[cfg(feature = "tpm2")]
    tcti: OnceCell<String>,
}

// Stub used when the tpm2 feature is disabled
#[cfg(not(feature = "tpm2"))]
impl Tpm2Protector {
    pub fn new(_opts: Tpm2Opts, _raw_key: ProtectorKey, _pass: &[u8]) -> Result<Self> {
        bail!("TPM support is disabled");
    }

    pub fn wrap_key(&mut self, _prot_key: ProtectorKey, _pass: &[u8]) -> Result<()> {
        bail!("TPM support is disabled");
    }

    pub fn unwrap_key(&self, _pass: &[u8]) -> Result<Option<ProtectorKey>> {
        bail!("TPM support is disabled");
    }

    pub fn get_prompt(&self) -> Result<String, String> {
        Err(String::from("TPM support is disabled"))
    }
}

#[cfg(feature = "tpm2")]
impl Tpm2Protector {
    /// Creates a new [`Tpm2Protector`] that wraps a [`ProtectorKey`] with a password.
    pub fn new(opts: Tpm2Opts, prot_key: ProtectorKey, pass: &[u8]) -> Result<Self> {
        let kdf = if let Some(kdf_iter) = opts.kdf_iter {
            Kdf::Pbkdf2(Pbkdf2::new(kdf_iter.into()))
        } else {
            Kdf::default()
        };
        let tcti = match opts.tpm2_tcti {
            Some(c) => OnceCell::from(c),
            None => OnceCell::new(),
        };
        let mut prot = Tpm2Protector { kdf, name: opts.name, tcti, ..Default::default() };
        prot.wrap_key(prot_key, pass)?;
        Ok(prot)
    }

    /// Wraps `prot_key` with `pass`. This generates a new random Salt.
    pub fn wrap_key(&mut self, prot_key: ProtectorKey, pass: &[u8]) -> Result<()> {
        let mut ctx = self.create_context()?;
        let primary_key = create_primary_key(&mut ctx)?;
        let mut salt = Salt::default();
        OsRng.fill_bytes(&mut salt.0);
        let auth = derive_auth_value(pass, &salt, &self.kdf);
        let (public, private) = {
            let (pb, pv) = seal_data(ctx, primary_key, prot_key.secret(), auth)?;
            let public = PublicBuffer::try_from(pb)?.marshall()?;
            let private = tpm_private_marshall(pv)?;
            (public, private)
        };
        self.salt = salt;
        self.public = public;
        self.private = private;
        Ok(())
    }

    /// Unwraps a [`ProtectorKey`] with a password.
    pub fn unwrap_key(&self, pass: &[u8]) -> Result<Option<ProtectorKey>> {
        let mut ctx = self.create_context()?;
        let primary_key = create_primary_key(&mut ctx)?;
        let public = Public::try_from(PublicBuffer::unmarshall(&self.public)?)?;
        let private = tpm_private_unmarshall(&self.private)?;
        let auth = derive_auth_value(pass, &self.salt, &self.kdf);
        let Ok(data) = unseal_data(ctx, primary_key, public, private, auth) else {
            return Ok(None);
        };
        let raw_data : &[u8; 32] = data.value().try_into()?;
        Ok(Some(ProtectorKey::from(raw_data)))
    }

    /// Returns the prompt, or an error message if the TPM is not usable
    pub fn get_prompt(&self) -> Result<String, String> {
        let s = self.get_tcti_conf()
            .and_then(|c| get_status(Some(c)))
            .map_err(|_| String::from("Error connecting to the TPM"))?;
        let retries = s.max_auth_fail - s.lockout_counter;
        if retries == 0 {
            Err(format!("The TPM is locked, wait up to {} seconds before trying again",
                        s.lockout_interval))
        } else if retries < 10 {
            Ok(format!("Enter TPM2 PIN ({retries} retries left)"))
        } else {
            Ok(String::from("Enter TPM2 PIN"))
        }
    }

    /// Gets (and initializes if necessary) the TCTI conf string
    fn get_tcti_conf(&self) -> Result<&str> {
        match self.tcti.get() {
            Some(s) => Ok(s),
            None => {
                let tcti = Config::tpm2_tcti()?;
                self.tcti.set(tcti.to_string()).unwrap();
                Ok(tcti)
            }
        }
    }

    /// Creates a new Context
    fn create_context(&self) -> Result<Context> {
        let tcti = self.get_tcti_conf()?;
        Context::new(TctiNameConf::from_str(tcti)?)
            .map_err(|e| anyhow!("Unable to access the TPM at {tcti}: {e}"))
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
fn derive_auth_value(pass: &[u8], salt: &Salt, kdf: &Kdf) -> Auth {
    let mut data = zeroize::Zeroizing::new([0u8; 64]);
    kdf.derive(pass, &salt.0, data.as_mut());
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
    pub tcti: String,
    pub manufacturer: String,
    pub lockout_counter: u32,
    pub max_auth_fail: u32,
    pub lockout_interval: u32,
    pub in_lockout: bool,
}

#[cfg(feature = "tpm2")]
pub fn get_status(tcti_conf: Option<&str>) -> Result<TpmStatus> {
    use PropertyTag::*;

    let tcti = match tcti_conf {
        Some(s) => s,
        _ => Config::tpm2_tcti()?,
    };
    let mut ctx = Context::new(TctiNameConf::from_str(tcti)?)?;

    let perm = ctx.get_tpm_property(Permanent)?.unwrap_or(0);
    let manufacturer = if let Some(val) = ctx.get_tpm_property(Manufacturer)? {
        val.to_be_bytes().iter()      // Read bytes in big-endian order
            .filter(|x| **x != 0)     // Remove null bytes
            .map(|x| char::from(*x))  // Convert them to chars
            .collect()
    } else {
        String::from("Unknown")
    };

    let caps = ctx.get_capability(CapabilityType::TpmProperties, tss::TPM2_PT_LOCKOUT_COUNTER, 3)?;

    if let (CapabilityData::TpmProperties(data), _) = caps {
        let props = [LockoutCounter, MaxAuthFail, LockoutInterval];
        let values : Vec<_> = props.iter()
            .filter_map(|p| data.find(*p))
            .map(|p| p.value())
            .collect();

        if props.len() == values.len() {
            return Ok(TpmStatus {
                tcti: tcti.to_string(),
                manufacturer,
                lockout_counter: values[0],
                max_auth_fail: values[1],
                lockout_interval: values[2],
                in_lockout: (perm & tss::TPMA_PERMANENT_INLOCKOUT) != 0,
            });
        }
    }

    Err(anyhow!("Error getting the status of the TPM"))
}

#[cfg(test)]
#[cfg(not(feature = "tpm2"))]
pub mod tests {
    use anyhow::Result;
    pub struct Swtpm {}

    impl Swtpm {
        pub fn new(_port: u16) -> Result<Self> {
            Ok(Swtpm{})
        }
        pub fn tcti_conf(&self) -> String {
            String::new()
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tpm2")]
pub mod tests {
    use base64::prelude::*;
    use crate::protector::ProtectorData;
    use super::*;

    // Create the swtpm with the same initial state so the tests are reproducible.
    const SWTPM_INITIAL_STATE: &str = "\
        AgEACgAAAAAFIwABAAAFEwADqzZHIwADAAPJ6mQxAAEAAAB4AAAAAQAAAAEAAAABAAAAAQAAAAEA\
        AAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAA\
        AAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAA\
        AQAADAAAAADAAAABAAAAAIAAAACAAAAAAQAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAJ+\
        AAAABAAAAAQAAAAYAAAAGAAAABEAAAAAAAAABQAAAAMAAABAAAAAAwAAAAMAAAADAAAABwAAAAEA\
        AAABAAAKeAAABAAAAAgAAAAEAAAABAAAArLAAAAACAAAABAAAABAAAAAQAAAAAYAAAAMAAAAAQAA\
        AAgAAACAAAAAQAAAAgAAAQABAAAAAQAAAAEAAAAAAAAEAAAAIAAAAABAAAAABAAAAAEAAAAAAAAA\
        AQAAAAAAAAABAAAAAQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAABAAAAAAAAAAAAAAAA\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        AAAAAQAAAAQSITRDAAQAABAAEAAQAAAAAAAAAAAAAAAAAEBTpXUIkd8lZVmn3L/lYwbhJSkHZ+1L\
        aZuLzWYl5aP5eC/LSXIv1QGuMosuBu0rRIirtP6EHM/DQB3aWimUux3sAECGdCEOmCPQ63Qbfcn1\
        /qRQNKEbSfYHJttZmHVP8nX7B1EMrCyMm4vrMPnqj5JHGxyqER+0R+ySj4JqSEyBc2anAEAd4W69\
        jBHTFc6FldubFHMqlBKdlJrzH5yJeouFi8mtOluE37uxz0KJqYStD7jdSqlz7WVGhp6eskUcdcZE\
        OZFvAECVpjGu9OmVNyNYQHUVNC+7uMx7y/M7WzMMpF4ro9Gbm+jb0m0gLtn4KLqzADbgx8gN9ykZ\
        KfPf3uEHSnIkr5h7AEC8Frt/W1nqDH0A6646+897s3qBGRWqk+Ef2lbE64qmOtIxW4U/9HiNqgbA\
        Q9yO7Enay9g5Gu9H5VoDzCOqKSXWAECSORpHK/YYTjz4A4Yj/axdWpNsDILsU4jokiwmTncmBD1T\
        k7V5Ae+P8I2lUBD+ht4/720bQrTdEW0x0Fj11K22AAAAAAAAAAEAAAABAQARAAIXa+YmAAEAAQAQ\
        AAABAAAAAAAEAAQD////AAsD////AAwD////AA0D////AA4AIAAAAAAAAAAAAAAAAAAAAAAAAAAf\
        AAACWAAAA+gB//8ADgAAAIAAAAAAAAAAAAAAAA0AAAAAAAAAAAAAAAAgGRAjABY2NgQAAAABAQAl\
        AAAABAAEA////wALA////wAMA////wANA////wEABgEBAQEAAAACVmV4hwABAAAAAAAAVxUBAAJv\
        6D6hAAEAAAAAAAAABEdCUkQAMAYb5DqqOGDKEYcSbyGfN/FGgn5KS5vx+qJLX3B3o7YBYKlVaGor\
        MDy8xuzOK+NINAAEAAAAAAAAAAAAAAAAAAAAAAEAAAEAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        AAEAAAACU0b+qwABAAACAAAAAAABAAAAAglPIsMAAQAAAAAAApzAAAAAAAAAAAAAAAAAAQAAAQAA\
        qzZHIw==";

    pub struct Swtpm {
        dir: tempdir::TempDir,
        port: u16,
    }

    impl Swtpm {
        pub fn new(port: u16) -> Result<Self> {
            let dir = tempdir::TempDir::new("swtpm")?;
            let path = dir.path().to_str()
                .expect("Error creating temporary dir for swtpm");
            let tpm_state_file = dir.path().join("tpm2-00.permall");
            let tpm_state = BASE64_STANDARD.decode(SWTPM_INITIAL_STATE)?;
            std::fs::write(tpm_state_file, tpm_state)?;
            let status = std::process::Command::new("swtpm")
                .arg("socket")
                .arg("--daemon")
                .arg("--tpm2")
                .args(["--flags", "startup-clear"])
                .args(["--tpmstate", &format!("dir={path}")])
                .args(["--pid", &format!("file={path}/pid")])
                .args(["--server", &format!("type=tcp,port={port}")])
                .args(["--ctrl", &format!("type=tcp,port={}", port + 1)])
                .status()
                .expect("Failed to run swtpm");
            assert!(status.success(), "Error starting swtpm");
            Ok(Swtpm{dir, port})
        }

        pub fn tcti_conf(&self) -> String {
            format!("swtpm:host=localhost,port={}", self.port)
        }
    }

    impl Drop for Swtpm {
        fn drop(&mut self) {
            let pidfile = self.dir.path().join("pid");
            _ = std::process::Command::new("pkill")
                .arg("-F")
                .arg(pidfile)
                .status()
                .expect("Error killing swtpm");
        }
    }

    #[test]
    fn test_tpm() -> Result<()> {
        crate::init();

        let json = r#"
            {
              "type": "tpm2",
              "name": "test",
              "public": "AC4ACAALAAAAUgAAABAAIJ5/c4jAMSqZJy+WdOmYZEvTHzySYb7q64RjAGB4HnIq",
              "private": "AJ4AIJaH4Zd1POY4nm3fOSoKcIrumK1UY+G+7rK77lT7P2xCABDygTzPRBEgaAm4DRLgtgD6BiKcV4idSdDI+powZcfHfisIA+WwugPEeNgLBg6AJzOEPQIGeGKiXshl4QyVMorsDTZIzTnXHiVmA3AtT8ZuUqyqjolmUzbITsI82uSL5e4EaHiNBR/Un/38lI48DMtfQMOqcGC0b9JHAQ==",
              "salt": "neeZ+2/7a0TWr2IgLEvUBOb9mqpyt5CDjzovHpi0sJ4=",
              "kdf": {
                "type": "pbkdf2",
                "iterations": 5
              }
            }"#;

        let tpm = Swtpm::new(7976)?;
        let prot = match serde_json::from_str::<ProtectorData>(json) {
            Ok(ProtectorData::Tpm2(p)) => p,
            _ => bail!("Error creating protector from JSON data"),
        };
        prot.tcti.set(tpm.tcti_conf()).unwrap();
        assert!(prot.unwrap_key(b"1234").unwrap().is_some());
        assert!(prot.unwrap_key(b"wrongpw").unwrap().is_none());
        let status = get_status(prot.get_tcti_conf().ok())?;
        // Check that the dictionary attack parameters match the expected values
        assert_eq!(status.lockout_counter, 1);
        assert_eq!(status.max_auth_fail, 31);
        assert_eq!(status.lockout_interval, 600);
        Ok(())
    }
}
