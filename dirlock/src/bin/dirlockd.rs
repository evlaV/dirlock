/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail};
use serde::Serialize;
use zbus::fdo::Result;
use zbus::fdo::Error;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use zbus::{
    fdo::DBusProxy,
    interface,
    zvariant::{self, Value},
};
use dirlock::{
    DirStatus,
    ProtectedPolicyKey,
    fscrypt::{
        self,
        PolicyKeyId,
    },
    keystore,
    protector::{
        Protector,
        ProtectorId,
        ProtectorType,
        opts::ProtectorOptsBuilder,
    },
};

struct Manager {
    _proxy: DBusProxy<'static>,
}

/// This is the D-Bus API version of [`DirStatus`]
#[derive(Serialize, zvariant::Type)]
struct DbusDirStatus(HashMap<&'static str, Value<'static>>);

impl From<DirStatus> for DbusDirStatus {
    fn from(dir_status: DirStatus) -> Self {
        let status_str = Value::from(dir_status.name());
        let DirStatus::Encrypted(d) = &dir_status else {
            return DbusDirStatus(HashMap::from([("status", status_str)]));
        };
        let prots : Vec<_> = d.protectors.iter()
            .map(|p| Value::from(DbusProtectorData::from(p).0))
            .collect();
        DbusDirStatus(HashMap::from([
            ("status", status_str),
            ("policy", Value::from(d.policy.keyid.to_string())),
            ("protectors", Value::from(&prots)),
        ]))
    }
}

/// This is the D-Bus API version of [`Protector`]
#[derive(Serialize, zvariant::Type)]
struct DbusProtectorData(HashMap<&'static str, Value<'static>>);

impl From<&Protector> for DbusProtectorData {
    fn from(p: &Protector) -> Self {
        let data = HashMap::from([
            ("id", Value::from(p.id.to_string())),
            ("type", Value::from(p.get_type().to_string())),
            ("name", Value::from(p.get_name().to_string())),
            ("needs-password", Value::from(p.needs_password())),
        ]);
        DbusProtectorData(data)
    }
}

impl From<&ProtectedPolicyKey> for DbusProtectorData {
    fn from(p: &ProtectedPolicyKey) -> Self {
        DbusProtectorData::from(&p.protector)
    }
}

/// This contains the data of a set of policies.
/// It maps the policy id to a list of protectors.
#[derive(Serialize, zvariant::Type)]
struct DbusPolicyData(HashMap<String, Vec<DbusProtectorData>>);

/// Lock a directory
fn do_lock_dir(dir: &Path) -> anyhow::Result<()> {
    let encrypted_dir = match dirlock::open_dir(dir, keystore()) {
        Ok(DirStatus::Encrypted(d)) if d.key_status == fscrypt::KeyStatus::Absent =>
            Err(anyhow!("Already locked")),
        Ok(DirStatus::Encrypted(d)) => Ok(d),
        Ok(x) => Err(anyhow!("{}", x.error_msg())),
        Err(e) => Err(e),
    }?;

    encrypted_dir.lock(fscrypt::RemoveKeyUsers::CurrentUser)
        .and(Ok(())) // TODO: check removal status flags
}

/// Unlock a directory
fn do_unlock_dir(
    dir: &Path,
    pass: &str,
    protector_id: &str,
) -> anyhow::Result<()> {
    let protector_id = ProtectorId::from_str(protector_id)?;

    let encrypted_dir = match dirlock::open_dir(dir, keystore()) {
        Ok(DirStatus::Encrypted(d)) if d.key_status == fscrypt::KeyStatus::Present =>
            Err(anyhow!("Already unlocked")),
        Ok(DirStatus::Encrypted(d)) => Ok(d),
        Ok(x) => Err(anyhow!("{}", x.error_msg())),
        Err(e) => Err(e),
    }?;

    if encrypted_dir.unlock(pass.as_bytes(), &protector_id)? {
        Ok(())
    } else {
        bail!("Authentication failed")
    }
}

/// Verify the password of a protector (without unlocking anything)
fn do_verify_protector_password(
    pass: &str,
    protector_id: &str,
) -> anyhow::Result<bool> {
    ProtectorId::from_str(protector_id)
        .and_then(|id| keystore().load_protector(id).map_err(|e| e.into()))
        .and_then(|prot| prot.unwrap_key(pass.as_bytes()))
        .map(|key| key.is_some())
}

/// Change the password of a protector
fn do_change_protector_password(
    pass: &str,
    newpass: &str,
    protector_id: &str,
) -> anyhow::Result<()> {
    if pass == newpass {
        bail!("The old and new passwords are identical");
    }

    let ks = keystore();

    let mut prot = ProtectorId::from_str(protector_id)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))?;

    prot.unwrap_key(pass.as_bytes())
        .and_then(|k| k.ok_or_else(|| anyhow!("Invalid password")))
        .and_then(|key| dirlock::wrap_and_save_protector_key(&mut prot, key, newpass.as_bytes(), ks))
}

/// Get the encryption status of a directory
fn do_get_dir_status(
    dir: &Path,
) -> anyhow::Result<DbusDirStatus> {
    dirlock::open_dir(dir, keystore()).map(DbusDirStatus::from)
}

/// Encrypt a directory using an existing protector
fn do_encrypt_dir(
    dir: &Path,
    pass: &str,
    protector_id: &str,
) -> anyhow::Result<String> {
    let ks = keystore();
    let protector_id = ProtectorId::from_str(protector_id)?;
    let protector = ks.load_protector(protector_id)?;

    match dirlock::open_dir(dir, ks)? {
        DirStatus::Unencrypted => (),
        x => bail!("{}", x.error_msg()),
    }

    let key = match protector.unwrap_key(pass.as_bytes())? {
        Some(k) => k,
        None => bail!("Authentication failed"),
    };

    let keyid = dirlock::encrypt_dir(dir, &protector, key, ks)?;
    Ok(keyid.to_string())
}

/// Create a new protector
fn do_create_protector(
    ptype: &str,
    name: &str,
    pass: &str,
) -> anyhow::Result<String> {
    let ptype = ProtectorType::from_str(ptype)
        .map_err(|_| anyhow!("Unknown protector type"))?;

    let (prot, _) = ProtectorOptsBuilder::new()
        .with_type(Some(ptype))
        .with_name(name.to_string())
        .build()
        .and_then(|opts| {
            let create = dirlock::CreateOpts::CreateAndSave;
            dirlock::create_protector(opts, pass.as_bytes(), create, keystore())
        })
        .map_err(|e| anyhow!("Error creating protector: {e}"))?;

    Ok(prot.id.to_string())
}

/// Remove a protector. It must be unused.
fn do_remove_protector(protector_id: &str) -> anyhow::Result<()> {
    let id = ProtectorId::from_str(protector_id)?;
    if ! keystore().remove_protector_if_unused(&id)? {
        bail!("Protector {protector_id} is still being used");
    }
    Ok(())
}

/// Get a protector
fn do_get_protector(id: ProtectorId) -> anyhow::Result<DbusProtectorData> {
    let ks = keystore();
    let Ok(prot) = ks.load_protector(id) else {
        bail!("Error reading protector {id}");
    };
    Ok(DbusProtectorData::from(&prot))
}

/// Get all existing protectors
fn do_get_all_protectors() -> anyhow::Result<Vec<DbusProtectorData>> {
    let ks = keystore();
    let prot_ids = ks.protector_ids()
        .map_err(|e| anyhow!("Error getting list of protectors: {e}"))?;

    let mut prots = vec![];
    for id in prot_ids {
        prots.push(do_get_protector(id)?);
    }
    Ok(prots)
}

/// Get all existing policies
fn do_get_all_policies() -> anyhow::Result<DbusPolicyData> {
    let mut result = HashMap::new();
    let ks = keystore();
    for id in ks.policy_key_ids()? {
        let (prots, unusable) = ks.get_protectors_for_policy(&id)?;
        if ! unusable.is_empty() {
            bail!("Error reading protectors for policy {id}");
        }
        let prots = prots.iter().map(DbusProtectorData::from).collect();
        result.insert(id.to_string(), prots);
    }
    Ok(DbusPolicyData(result))
}

/// Add a protector to an encryption policy
fn do_add_protector_to_policy(
    policy: &str,
    protector: &str,
    protector_pass: &str,
    unlock_with: &str,
    unlock_with_pass: &str,
) -> anyhow::Result<()> {
    let ks = keystore();
    let policy_id = PolicyKeyId::from_str(policy)?;
    let protector = ProtectorId::from_str(protector)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))?;
    let unlock_with = ProtectorId::from_str(unlock_with)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))?;

    let mut policy = ks.load_policy_data(&policy_id)?;
    let Some(wrapped_policy_key) = policy.keys.get(&unlock_with.id) else {
        bail!("Policy {policy_id} cannot be unlocked with protector {}", unlock_with.id);
    };

    let Some(protector_key) = protector.unwrap_key(protector_pass.as_bytes())? else {
        bail!("Invalid {} for protector {}", protector.get_type().credential_name(), protector.id);
    };

    let Some(policy_key) = unlock_with.unwrap_policy_key(wrapped_policy_key, unlock_with_pass.as_bytes())? else {
        bail!("Invalid {} for protector {}", unlock_with.get_type().credential_name(), unlock_with.id);
    };

    policy.add_protector(&protector_key, policy_key)?;
    keystore().save_policy_data(&policy)?;

    Ok(())
}

/// Remove a protector from an encryption policy
fn do_remove_protector_from_policy(
    policy: &str,
    protector: &str,
) -> anyhow::Result<()> {
    let policy_id = PolicyKeyId::from_str(policy)?;
    let protector_id = ProtectorId::from_str(protector)?;
    let ks = keystore();
    let mut policy = ks.load_policy_data(&policy_id)?;
    if ! policy.keys.contains_key(&protector_id) {
        bail!("Protector {} is not used in this policy", protector_id);
    }
    if policy.keys.len() == 1 {
        bail!("Cannot remove the last protector");
    }
    policy.remove_protector(&protector_id)?;
    ks.save_policy_data(&policy)?;

    Ok(())
}

/// D-Bus API
#[interface(name = "com.valvesoftware.Dirlock")]
impl Manager {
    async fn lock_dir(
        &self,
        dir: &Path
    ) -> Result<()> {
        do_lock_dir(dir)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn unlock_dir(
        &self,
        dir: &Path,
        pass: &str,
        protector_id: &str,
    ) -> Result<()> {
        do_unlock_dir(dir, pass, protector_id)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn verify_protector_password(
        &self,
        pass: &str,
        protector_id: &str,
    ) -> Result<bool> {
        do_verify_protector_password(pass, protector_id)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn change_protector_password(
        &self,
        pass: &str,
        newpass: &str,
        protector_id: &str,
    ) -> Result<()> {
        do_change_protector_password(pass, newpass, protector_id)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn get_dir_status(
        &mut self,
        dir: &Path,
    ) -> Result<DbusDirStatus> {
        do_get_dir_status(dir)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn encrypt_dir(
        &mut self,
        dir: &Path,
        pass: &str,
        protector_id: &str,
    ) -> Result<String> {
        do_encrypt_dir(dir, pass, protector_id)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn create_protector(
        &mut self,
        ptype: &str,
        name: &str,
        pass: &str,
    ) -> Result<String> {
        do_create_protector(ptype, name, pass)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn remove_protector(
        &mut self,
        protector_id: &str,
    ) -> Result<()> {
        do_remove_protector(protector_id)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn get_all_protectors(&self) -> Result<Vec<DbusProtectorData>> {
        do_get_all_protectors()
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn get_all_policies(&self) -> Result<DbusPolicyData> {
        do_get_all_policies()
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn get_protector(&self, id: &str) -> Result<DbusProtectorData> {
        ProtectorId::from_str(id)
            .and_then(do_get_protector)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn add_protector_to_policy(
        &self,
        policy: &str,
        protector: &str,
        protector_pass: &str,
        unlock_with: &str,
        unlock_with_pass: &str,
    ) -> Result<()> {
        do_add_protector_to_policy(policy, protector, protector_pass, unlock_with, unlock_with_pass)
            .map_err(|e| Error::Failed(e.to_string()))
    }

    async fn remove_protector_from_policy(
        &self,
        policy: &str,
        protector: &str,
    ) -> Result<()> {
        do_remove_protector_from_policy(policy, protector)
            .map_err(|e| Error::Failed(e.to_string()))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dirlock::init()?;
    let builder = zbus::connection::Builder::session()?;
    let conn = builder.name("com.valvesoftware.Dirlock")?
        .build()
        .await?;
    let proxy = DBusProxy::new(&conn).await?;
    let manager = Manager { _proxy: proxy };

    conn.object_server()
        .at("/com/valvesoftware/Dirlock", manager)
        .await?;

    std::future::pending::<()>().await;

    Ok(())
}
