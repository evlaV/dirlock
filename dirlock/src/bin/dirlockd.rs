/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail};
use zbus::fdo::Result;
use zbus::fdo::Error;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use zbus::{interface, fdo::DBusProxy, zvariant::Value};
use dirlock::{
    DirStatus,
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

/// In the D-Bus API a [`Protector`] is just a map with the important
/// public attributes (ID, type, name, etc.).
type DbusProtectorData = HashMap<&'static str, Value<'static>>;

fn get_dbus_protector_data(p: &Protector) -> DbusProtectorData {
    HashMap::from([
        ("id", Value::from(p.id.to_string())),
        ("type", Value::from(p.get_type().to_string())),
        ("name", Value::from(p.get_name().to_string())),
        ("needs-password", Value::from(p.needs_password())),
    ])
}

/// Lock a directory
fn do_lock_dir(dir: &Path) -> anyhow::Result<()> {
    let encrypted_dir = match dirlock::open_dir(dir) {
        Ok(DirStatus::Encrypted(d)) if d.key_status == fscrypt::KeyStatus::Absent =>
            Err(anyhow!("Already locked")),
        Ok(DirStatus::Encrypted(d)) => Ok(d),
        Ok(x) => Err(anyhow!("{x}")),
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

    let encrypted_dir = match dirlock::open_dir(dir) {
        Ok(DirStatus::Encrypted(d)) if d.key_status == fscrypt::KeyStatus::Present =>
            Err(anyhow!("Already unlocked")),
        Ok(DirStatus::Encrypted(d)) => Ok(d),
        Ok(x) => Err(anyhow!("{x}")),
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
        .and_then(|id| dirlock::get_protector_by_id(id).map_err(|e| e.into()))
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

    let mut prot = ProtectorId::from_str(protector_id)
        .and_then(|id| dirlock::get_protector_by_id(id).map_err(|e| e.into()))?;

    prot.unwrap_key(pass.as_bytes())
        .and_then(|k| k.ok_or_else(|| anyhow!("Invalid password")))
        .and_then(|key| dirlock::wrap_and_save_protector_key(&mut prot, key, newpass.as_bytes()))
}

/// Get the encryption status of a directory
fn do_get_dir_status(
    dir: &Path,
) -> anyhow::Result<(&'static str, String, Vec<DbusProtectorData>)> {
    use dirlock::DirStatus::*;
    use dirlock::fscrypt::KeyStatus::*;

    let dir_status = dirlock::open_dir(dir)?;

    // TODO detect when the filesystem does not support encryption
    let status = match &dir_status {
        Unencrypted => "unencrypted",
        Encrypted(d) => match d.key_status {
            Absent => "locked",
            Present => "unlocked",
            IncompletelyRemoved => "partially-locked",
        },
        KeyMissing => "key-missing",
        Unsupported => "unsupported",
    };

    if let Encrypted(d) = dir_status {
        let keyid = d.policy.keyid.to_string();
        let prots : Vec<_> = d.protectors
            .iter()
            .map(|p| get_dbus_protector_data(&p.protector))
            .collect();
        Ok((status, keyid, prots))
    } else {
        Ok((status, String::new(), vec![]))
    }
}

/// Encrypt a directory using an existing protector
fn do_encrypt_dir(
    dir: &Path,
    pass: &str,
    protector_id: &str,
) -> anyhow::Result<String> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let protector = dirlock::get_protector_by_id(protector_id)?;

    match dirlock::open_dir(dir)? {
        DirStatus::Unencrypted => (),
        x => bail!("{x}"),
    }

    let key = match protector.unwrap_key(pass.as_bytes())? {
        Some(k) => k,
        None => bail!("Authentication failed"),
    };

    let keyid = dirlock::encrypt_dir(dir, key)?;
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
            let create = dirlock::CreateProtector::CreateAndSave;
            dirlock::create_protector(opts, pass.as_bytes(), create)
        })
        .map_err(|e| anyhow!("Error creating protector: {e}"))?;

    Ok(prot.id.to_string())
}

/// Remove a protector. It must be unused.
fn do_remove_protector(protector_id: &str) -> anyhow::Result<()> {
    let id = ProtectorId::from_str(protector_id)?;
    if ! keystore::remove_protector_if_unused(&id)? {
        bail!("Protector {protector_id} is still being used");
    }
    Ok(())
}

/// Get all existing protectors
fn do_get_protectors() -> anyhow::Result<Vec<DbusProtectorData>> {
    let prot_ids = keystore::protector_ids()
        .map_err(|e| anyhow!("Error getting list of protectors: {e}"))?;

    let mut prots = vec![];
    for id in prot_ids {
        match dirlock::get_protector_by_id(id) {
            Ok(prot) => prots.push(prot),
            _ => bail!("Error reading protector {id}"),
        }
    }

    Ok(prots.iter().map(get_dbus_protector_data).collect())
}

/// Add a protector to an encryption policy
fn do_add_protector_to_policy(
    policy: &str,
    protector: &str,
    protector_pass: &str,
    unlock_with: &str,
    unlock_with_pass: &str,
) -> anyhow::Result<()> {
    let policy_id = PolicyKeyId::from_str(policy)?;
    let protector = ProtectorId::from_str(protector)
        .and_then(|id| dirlock::get_protector_by_id(id).map_err(|e| e.into()))?;
    let unlock_with = ProtectorId::from_str(unlock_with)
        .and_then(|id| dirlock::get_protector_by_id(id).map_err(|e| e.into()))?;

    let policy_map = keystore::load_policy_map(&policy_id)?;
    let Some(wrapped_policy_key) = policy_map.get(&unlock_with.id) else {
        bail!("Policy {policy_id} cannot be unlocked with protector {}", unlock_with.id);
    };

    let Some(protector_key) = protector.unwrap_key(protector_pass.as_bytes())? else {
        bail!("Invalid {} for protector {}", protector.get_type().credential_name(), protector.id);
    };

    let Some(policy_key) = unlock_with.unwrap_policy_key(wrapped_policy_key, unlock_with_pass.as_bytes())? else {
        bail!("Invalid {} for protector {}", unlock_with.get_type().credential_name(), unlock_with.id);
    };

    dirlock::wrap_and_save_policy_key(protector_key, policy_key)?;

    Ok(())
}

/// Remove a protector from an encryption policy
fn do_remove_protector_from_policy(
    policy: &str,
    protector: &str,
) -> anyhow::Result<()> {
    let policy_id = PolicyKeyId::from_str(policy)?;
    let protector_id = ProtectorId::from_str(protector)?;
    let policy_map = keystore::load_policy_map(&policy_id)?;
    if ! policy_map.contains_key(&protector_id) {
        bail!("Protector {} is not used in this policy", protector_id);
    }
    if policy_map.len() == 1 {
        bail!("Cannot remove the last protector");
    }
    keystore::remove_protector_from_policy(&policy_id, &protector_id)?;

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
    ) -> Result<(&'static str, String, Vec<DbusProtectorData>)> {
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

    async fn get_protectors(&self) -> Result<Vec<DbusProtectorData>> {
        do_get_protectors()
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
