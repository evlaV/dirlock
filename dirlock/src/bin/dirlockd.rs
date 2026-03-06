/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail};
use serde::Serialize;
use zbus::fdo::Result;
use zbus::fdo::Error;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use zbus::{
    interface,
    object_server::InterfaceRef,
    object_server::SignalEmitter,
    zvariant::{self, Value},
};
use dirlock::{
    DirStatus,
    EncryptedDir,
    Keystore,
    LockState,
    ProtectedPolicyKey,
    convert::ConvertJob,
    fscrypt::{
        self,
        PolicyKeyId,
    },
    protector::{
        Protector,
        ProtectorId,
        ProtectorType,
        opts::ProtectorOptsBuilder,
    },
    recovery::RecoveryKey,
};

const DIRLOCK_DBUS_PATH: &str = "/com/valvesoftware/Dirlock1";
const DIRLOCK_DBUS_SERVICE: &str = "com.valvesoftware.Dirlock1";

/// Events sent by background tasks to the main thread
enum Event {
    JobFinished(u32),
}

/// Global state of the dirlock D-Bus daemon
struct DirlockDaemon {
    jobs: HashMap<u32, Arc<ConvertJob>>,
    last_jobid: u32,
    tx: mpsc::Sender<Event>,
    ks: Keystore,
}

/// Convert a Result into a zbus::fdo::Result
trait IntoDbusResult<T> {
    fn into_dbus(self) -> zbus::fdo::Result<T>;
}

impl<T> IntoDbusResult<T> for anyhow::Result<T> {
    fn into_dbus(self) -> zbus::fdo::Result<T> {
        self.map_err(|e| Error::Failed(e.to_string()))
    }
}

/// When running tests, default to 1 KDF iteration in order to make
/// them faster.
fn get_kdf_iter(val: Option<NonZeroU32>) -> Option<NonZeroU32> {
    if cfg!(test) && val.is_none() {
        NonZeroU32::new(1)
    } else {
        val
    }
}

/// Extract a required string value from an a{sv} options dict
fn get_str(options: &HashMap<String, Value<'_>>, key: &str) -> zbus::fdo::Result<String> {
    match options.get(key) {
        Some(Value::Str(s)) => Ok(s.to_string()),
        Some(_) => Err(Error::InvalidArgs(format!("'{key}' must be a string"))),
        None => Err(Error::InvalidArgs(format!("Missing required option '{key}'"))),
    }
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
            ("has-recovery-key", Value::from(d.recovery.is_some())),
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
fn do_lock_dir(dir: &Path, ks: &Keystore) -> anyhow::Result<()> {
    let encrypted_dir = EncryptedDir::open(dir, ks, LockState::Unlocked)?;
    encrypted_dir.lock(fscrypt::RemoveKeyUsers::CurrentUser)
        .and(Ok(())) // TODO: check removal status flags
}

/// Unlock a directory
fn do_unlock_dir(
    dir: &Path,
    pass: &str,
    protector_id: &str,
    ks: &Keystore,
) -> anyhow::Result<()> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let encrypted_dir = EncryptedDir::open(dir, ks, LockState::Locked)?;

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
    ks: &Keystore,
) -> anyhow::Result<bool> {
    ProtectorId::from_str(protector_id)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))
        .and_then(|prot| prot.unwrap_key(pass.as_bytes()))
        .map(|key| key.is_some())
}

/// Change the password of a protector
fn do_change_protector_password(
    pass: &str,
    newpass: &str,
    protector_id: &str,
    ks: &Keystore,
) -> anyhow::Result<()> {
    if pass == newpass {
        bail!("The old and new passwords are identical");
    }

    let mut prot = ProtectorId::from_str(protector_id)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))?;

    if ! dirlock::update_protector_password(&mut prot, pass.as_bytes(), newpass.as_bytes(), ks)? {
        bail!("Invalid password");
    }
    Ok(())
}

/// Get the encryption status of a directory
fn do_get_dir_status(
    dir: &Path,
    ks: &Keystore,
) -> anyhow::Result<DbusDirStatus> {
    dirlock::open_dir(dir, ks).map(DbusDirStatus::from)
}

/// Encrypt a directory using an existing protector
fn do_encrypt_dir(
    dir: &Path,
    pass: &str,
    protector_id: &str,
    ks: &Keystore,
) -> anyhow::Result<String> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let protector = ks.load_protector(protector_id)?;

    dirlock::ensure_unencrypted(dir, ks)?;

    let key = match protector.unwrap_key(pass.as_bytes())? {
        Some(k) => k,
        None => bail!("Authentication failed"),
    };

    let keyid = dirlock::encrypt_dir(dir, &protector, key, ks)?;
    Ok(keyid.to_string())
}

/// Convert a directory using an existing protector
fn do_convert_dir(
    dir: &Path,
    pass: &str,
    protector_id: &str,
    ks: &Keystore,
) -> anyhow::Result<ConvertJob> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let protector = ks.load_protector(protector_id)?;

    dirlock::ensure_unencrypted(dir, ks)?;

    let key = match protector.unwrap_key(pass.as_bytes())? {
        Some(k) => k,
        None => bail!("Authentication failed"),
    };

    ConvertJob::start(dir, &protector, key, ks)
}

/// Create a new protector
fn do_create_protector(
    ptype: &str,
    name: &str,
    pass: &str,
    ks: &Keystore,
) -> anyhow::Result<String> {
    let ptype = ProtectorType::from_str(ptype)
        .map_err(|_| anyhow!("Unknown protector type"))?;

    let (prot, _) = ProtectorOptsBuilder::new()
        .with_type(Some(ptype))
        .with_name(name.to_string())
        .with_kdf_iter(get_kdf_iter(None))
        .build()
        .and_then(|opts| {
            let create = dirlock::CreateOpts::CreateAndSave;
            dirlock::create_protector(opts, pass.as_bytes(), create, ks)
        })
        .map_err(|e| anyhow!("Error creating protector: {e}"))?;

    Ok(prot.id.to_string())
}

/// Remove a protector. It must be unused.
fn do_remove_protector(protector_id: &str, ks: &Keystore) -> anyhow::Result<()> {
    let id = ProtectorId::from_str(protector_id)?;
    if ! ks.remove_protector_if_unused(&id)? {
        bail!("Protector {protector_id} is still being used");
    }
    Ok(())
}

/// Get a protector
fn do_get_protector(id: ProtectorId, ks: &Keystore) -> anyhow::Result<DbusProtectorData> {
    let Ok(prot) = ks.load_protector(id) else {
        bail!("Error reading protector {id}");
    };
    Ok(DbusProtectorData::from(&prot))
}

/// Get all existing protectors
fn do_get_all_protectors(ks: &Keystore) -> anyhow::Result<Vec<DbusProtectorData>> {
    let prot_ids = ks.protector_ids()
        .map_err(|e| anyhow!("Error getting list of protectors: {e}"))?;

    let mut prots = vec![];
    for id in prot_ids {
        prots.push(do_get_protector(id, ks)?);
    }
    Ok(prots)
}

/// Get all existing policies
fn do_get_all_policies(ks: &Keystore) -> anyhow::Result<DbusPolicyData> {
    let mut result = HashMap::new();
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
    ks: &Keystore,
) -> anyhow::Result<()> {
    let policy_id = PolicyKeyId::from_str(policy)?;
    let protector = ProtectorId::from_str(protector)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))?;
    let unlock_with = ProtectorId::from_str(unlock_with)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))?;

    let Some(protector_key) = protector.unwrap_key(protector_pass.as_bytes())? else {
        bail!("Invalid {} for protector {}", protector.get_type().credential_name(), protector.id);
    };

    dirlock::add_protector_to_policy(&policy_id, &protector_key, &unlock_with, unlock_with_pass.as_bytes(), ks)
}

/// Add a recovery key to an encrypted directory
fn do_recovery_add(
    dir: &Path,
    protector_id: &str,
    pass: &str,
    ks: &Keystore,
) -> anyhow::Result<String> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let mut encrypted_dir = EncryptedDir::open(dir, ks, LockState::Any)?;

    if encrypted_dir.recovery.is_some() {
        bail!("This directory already has a recovery key");
    }

    let prot = encrypted_dir.get_protector_by_id(&protector_id)?;
    let Some(protkey) = prot.unwrap_key(pass.as_bytes())? else {
        bail!("Authentication failed");
    };

    let recovery = encrypted_dir.add_recovery_key(&protkey)?;
    Ok(recovery.to_string())
}

/// Remove the recovery key from an encrypted directory
fn do_recovery_remove(dir: &Path, ks: &Keystore) -> anyhow::Result<()> {
    match dirlock::open_dir(dir, ks)? {
        DirStatus::Encrypted(mut d) => d.remove_recovery_key(),
        x => bail!("{}", x.error_msg()),
    }
}

/// Restore keystore access to a directory using its recovery key
fn do_recovery_restore(
    dir: &Path,
    recovery_key_str: &str,
    protector_id: &str,
    pass: &str,
    ks: &Keystore,
) -> anyhow::Result<()> {
    let encrypted_dir = EncryptedDir::open(dir, ks, LockState::Any)?;

    let Some(recovery) = &encrypted_dir.recovery else {
        bail!("This directory does not have a recovery key");
    };

    let Ok(recovery_key) = RecoveryKey::from_ascii_bytes(recovery_key_str.as_bytes()) else {
        bail!("Invalid recovery key");
    };

    let Some(master_key) = recovery.unwrap_key(recovery_key.protector_key()) else {
        bail!("Wrong recovery key");
    };

    let protector_id = ProtectorId::from_str(protector_id)?;
    if encrypted_dir.get_protector_by_id(&protector_id).is_ok() {
        bail!("This directory is already protected with that protector");
    }

    let protector = ks.load_protector(protector_id)?;
    let Some(protector_key) = protector.unwrap_key(pass.as_bytes())? else {
        bail!("Authentication failed");
    };

    dirlock::protect_policy_key(&protector, &protector_key, master_key, ks)?;
    Ok(())
}

/// Remove a protector from an encryption policy
fn do_remove_protector_from_policy(
    policy: &str,
    protector: &str,
    ks: &Keystore,
) -> anyhow::Result<()> {
    let policy_id = PolicyKeyId::from_str(policy)?;
    let protector_id = ProtectorId::from_str(protector)?;
    dirlock::remove_protector_from_policy(&policy_id, &protector_id, ks)
}

impl DirlockDaemon {
    /// Handle events sent by background tasks
    async fn handle_event(&mut self, emitter: &SignalEmitter<'_>, ev: Event) -> zbus::Result<()> {
        match ev {
            Event::JobFinished(jobid) => {
                let Some(job) = self.jobs.remove(&jobid) else {
                    return Err(zbus::Error::Failure(format!("Job {jobid} not found")));
                };
                match Arc::into_inner(job).unwrap().commit() {
                    Ok(keyid) => Self::job_finished(emitter, jobid, keyid.to_string()).await,
                    Err(e) => Self::job_failed(emitter, jobid, e.to_string()).await,
                }
            }
        }
    }
}

/// D-Bus API
#[interface(name = "com.valvesoftware.Dirlock1")]
impl DirlockDaemon {
    async fn lock_dir(
        &self,
        dir: &Path
    ) -> Result<()> {
        do_lock_dir(dir, &self.ks).into_dbus()
    }

    async fn unlock_dir(
        &self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let pass = get_str(&options, "password")?;
        let protector = get_str(&options, "protector")?;
        do_unlock_dir(dir, &pass, &protector, &self.ks).into_dbus()
    }

    async fn verify_protector_password(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<bool> {
        let pass = get_str(&options, "password")?;
        let protector = get_str(&options, "protector")?;
        do_verify_protector_password(&pass, &protector, &self.ks).into_dbus()
    }

    async fn change_protector_password(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let pass = get_str(&options, "old-password")?;
        let newpass = get_str(&options, "new-password")?;
        let protector = get_str(&options, "protector")?;
        do_change_protector_password(&pass, &newpass, &protector, &self.ks).into_dbus()
    }

    async fn get_dir_status(
        &self,
        dir: &Path,
    ) -> Result<DbusDirStatus> {
        do_get_dir_status(dir, &self.ks).into_dbus()
    }

    async fn encrypt_dir(
        &self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
    ) -> Result<String> {
        let pass = get_str(&options, "password")?;
        let protector = get_str(&options, "protector")?;
        do_encrypt_dir(dir, &pass, &protector, &self.ks).into_dbus()
    }

    async fn convert_dir(
        &mut self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
        #[zbus(signal_emitter)]
        emitter: SignalEmitter<'_>,
    ) -> Result<u32> {
        let pass = get_str(&options, "password")?;
        let protector = get_str(&options, "protector")?;
        // Create a new ConvertJob and store it in self.jobs
        let job = do_convert_dir(dir, &pass, &protector, &self.ks)
            .map(Arc::new)
            .into_dbus()?;
        self.last_jobid += 1;
        let jobid = self.last_jobid;
        self.jobs.insert(jobid, job.clone());

        // Launch a task that reports the status of the job
        let emitter = emitter.into_owned();
        let tx = self.tx.clone();
        tokio::task::spawn(async move {
            let duration = std::time::Duration::new(2, 0);
            let mut progress = 0;
            while ! job.is_finished() {
                tokio::time::sleep(duration).await;
                let new_progress = job.progress();
                if new_progress > progress {
                    progress = new_progress;
                    _ = Self::job_progress(&emitter, jobid, progress).await;
                }
            }
            // Once the job is finished, drop this reference and emit
            // the JobFinished signal.
            _ = job.wait();
            drop(job);
            _ = tx.send(Event::JobFinished(jobid)).await;
        });

        // Return the job ID to the caller
        Ok(jobid)
    }

    async fn cancel_job(
        &self,
        jobn: u32,
    ) -> Result<()> {
        match self.jobs.get(&jobn) {
            Some(job) => job.cancel().into_dbus(),
            None => Err(Error::Failed(format!("Job {jobn} not found"))),
        }
    }

    async fn job_status(
        &self,
        jobn: u32,
    ) -> Result<i32> {
        match self.jobs.get(&jobn) {
            Some(job) => Ok(job.progress()),
            None => Err(Error::Failed(format!("Job {jobn} not found"))),
        }
    }

    #[zbus(signal)]
    async fn job_finished(e: &SignalEmitter<'_>, jobid: u32, keyid: String) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn job_failed(e: &SignalEmitter<'_>, jobid: u32, error: String) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn job_progress(e: &SignalEmitter<'_>, jobid: u32, progress: i32) -> zbus::Result<()>;

    async fn create_protector(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<String> {
        let ptype = get_str(&options, "type")?;
        let name = get_str(&options, "name")?;
        let pass = get_str(&options, "password")?;
        do_create_protector(&ptype, &name, &pass, &self.ks).into_dbus()
    }

    async fn remove_protector(
        &self,
        protector_id: &str,
    ) -> Result<()> {
        do_remove_protector(protector_id, &self.ks).into_dbus()
    }

    async fn get_all_protectors(&self) -> Result<Vec<DbusProtectorData>> {
        do_get_all_protectors(&self.ks).into_dbus()
    }

    async fn get_all_policies(&self) -> Result<DbusPolicyData> {
        do_get_all_policies(&self.ks).into_dbus()
    }

    async fn get_protector(&self, id: &str) -> Result<DbusProtectorData> {
        ProtectorId::from_str(id)
            .and_then(|protid| do_get_protector(protid, &self.ks))
            .into_dbus()
    }

    async fn add_protector_to_policy(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let policy = get_str(&options, "policy")?;
        let protector = get_str(&options, "protector")?;
        let protector_pass = get_str(&options, "protector-password")?;
        let unlock_with = get_str(&options, "unlock-with")?;
        let unlock_with_pass = get_str(&options, "unlock-with-password")?;
        do_add_protector_to_policy(&policy, &protector, &protector_pass, &unlock_with, &unlock_with_pass, &self.ks)
            .into_dbus()
    }

    async fn remove_protector_from_policy(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let policy = get_str(&options, "policy")?;
        let protector = get_str(&options, "protector")?;
        do_remove_protector_from_policy(&policy, &protector, &self.ks)
            .into_dbus()
    }

    async fn recovery_add(
        &self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
    ) -> Result<String> {
        let protector = get_str(&options, "protector")?;
        let pass = get_str(&options, "password")?;
        do_recovery_add(dir, &protector, &pass, &self.ks).into_dbus()
    }

    async fn recovery_remove(
        &self,
        dir: &Path,
    ) -> Result<()> {
        do_recovery_remove(dir, &self.ks).into_dbus()
    }

    async fn recovery_restore(
        &self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let recovery_key = get_str(&options, "recovery-key")?;
        let protector = get_str(&options, "protector")?;
        let pass = get_str(&options, "password")?;
        do_recovery_restore(dir, &recovery_key, &protector, &pass, &self.ks).into_dbus()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dirlock::init()?;
    let (tx, mut rx) = mpsc::channel::<Event>(2);
    let builder = zbus::connection::Builder::session()?;
    let conn = builder.name(DIRLOCK_DBUS_SERVICE)?
        .build()
        .await?;
    let daemon = DirlockDaemon {
        jobs: HashMap::new(),
        last_jobid: 0,
        tx,
        ks: Keystore::default(),
    };

    conn.object_server()
        .at(DIRLOCK_DBUS_PATH, daemon)
        .await?;

    let iface : InterfaceRef<DirlockDaemon> =
        conn.object_server().interface(DIRLOCK_DBUS_PATH).await?;

    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        let r = tokio::select! {
            e = rx.recv() => match e {
                Some(ev) => {
                    let emitter = iface.signal_emitter();
                    _ = iface.get_mut().await.handle_event(emitter, ev).await;
                    Ok(())
                },
                None => Err(anyhow!("Event channel unexpectedly closed")),
            },
            _ = tokio::signal::ctrl_c() => {
                eprintln!("Got SIGINT, shutting down");
                break Ok(());
            },
            _ = sigquit.recv() => Err(anyhow!("Got SIGQUIT")),
            e = sigterm.recv() => match e {
                Some(()) => {
                    eprintln!("Got SIGTERM, shutting down");
                    break Ok(());
                }
                None => Err(anyhow!("SIGTERM pipe broke")),
            },
        };
        if r.is_err() {
            break r;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use dirlock::dbus_proxy::Dirlock1Proxy;
    use tempdir::TempDir;
    use zbus::zvariant::{OwnedValue, Value};

    /// Transform a list of key / value pairs from (&str, &str) into (&str, Value).
    /// Used to provide an `a{sv}` options dict to D-Bus methods.
    fn str_dict<'a, const N: usize>(pairs: [(&'a str, &'a str); N]) -> Vec<(&'a str, Value<'a>)> {
        pairs.iter().map(|&(k, v)| (k, Value::from(v))).collect()
    }

    /// Transform an options dict as returned by str_dict() into a
    /// HashMap with references to the values, as expected by the D-Bus proxy.
    fn as_opts<'a>(vals: &'a Vec<(&str, Value<'a>)>) -> HashMap<&'a str, &'a Value<'a>> {
        vals.iter().map(|(k, v)| (*k, v)).collect()
    }

    /// Get a string from a HashMap returned by the D-Bus proxy
    fn expect_str<'a>(map: &'a HashMap<String, OwnedValue>, key: &str) -> Result<&'a str> {
        match map.get(key).map(|k| &**k) {
            Some(Value::Str(s)) => Ok(s),
            Some(v) => bail!("Key {key}, expected string, got {v:?}"),
            None => bail!("Missing key {key}"),
        }
    }

    /// Get a bool from a HashMap returned by the D-Bus proxy
    fn expect_bool(map: &HashMap<String, OwnedValue>, key: &str) -> Result<bool> {
        match map.get(key).map(|k| &**k) {
            Some(Value::Bool(v)) => Ok(*v),
            Some(v) => bail!("Key {key}, expected bool, got {v:?}"),
            None => bail!("Missing key {key}"),
        }
    }

    /// Filesystem where to run the tests. It must support fscrypt.
    /// Set to 'skip' to skip these tests.
    const MNTPOINT_ENV_VAR: &str = "DIRLOCK_TEST_FS";

    fn get_mntpoint() -> Result<Option<PathBuf>> {
        match std::env::var(MNTPOINT_ENV_VAR) {
            Ok(x) if x == "skip" => Ok(None),
            Ok(x) => Ok(Some(PathBuf::from(x))),
            _ => bail!("Environment variable '{MNTPOINT_ENV_VAR}' not set"),
        }
    }

    /// Each test uses its own D-Bus service name so they can run in parallel.
    /// This is the sequence number used to generate that name.
    static TEST_SERVICE_SEQ: AtomicU32 = AtomicU32::new(0);

    /// A client/server pair for a single test.
    struct TestService {
        _keystore_dir: TempDir,
        _server_conn: zbus::Connection,
        client_conn: zbus::Connection,
        service_name: String,
    }

    impl TestService {
        /// Start a [`DirlockDaemon`] with a unique name.
        ///
        /// Returns a new [`TestService`].
        async fn start() -> Result<Self> {
            let _keystore_dir = TempDir::new("dirlock-dbus-test")?;
            let ks = Keystore::from_path(_keystore_dir.path());

            let n = TEST_SERVICE_SEQ.fetch_add(1, Ordering::Relaxed);
            let service_name = format!("{DIRLOCK_DBUS_SERVICE}Test{n}");

            let (tx, _) = tokio::sync::mpsc::channel::<Event>(2);
            let daemon = DirlockDaemon {
                jobs: HashMap::new(),
                last_jobid: 0,
                tx,
                ks,
            };

            let _server_conn = zbus::connection::Builder::session()?
                .name(service_name.as_str())?
                .serve_at(DIRLOCK_DBUS_PATH, daemon)?
                .build()
                .await?;

            let client_conn = zbus::connection::Builder::session()?
                .build()
                .await?;

            Ok(TestService { _keystore_dir, _server_conn, client_conn, service_name })
        }

        /// Build a proxy for the test service.
        async fn proxy(&self) -> zbus::Result<Dirlock1Proxy<'_>> {
            Dirlock1Proxy::builder(&self.client_conn)
                .destination(self.service_name.as_str())?
                .path(DIRLOCK_DBUS_PATH)?
                .build()
                .await
        }
    }

    #[tokio::test]
    async fn test_create_get_protector() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Test CreateProtector
        let id = proxy.create_protector(as_opts(&str_dict([
            ("type", "password"),
            ("name", "prot1"),
            ("password", "pass1"),
        ]))).await?;
        ProtectorId::from_str(&id)?;

        // Test GetProtector
        let prot = proxy.get_protector(&id).await?;
        assert_eq!(expect_str(&prot, "id")?, id);
        assert_eq!(expect_str(&prot, "type")?, "password");
        assert_eq!(expect_str(&prot, "name")?, "prot1");
        assert_eq!(expect_bool(&prot, "needs-password")?, true);
        assert_eq!(prot.len(), 4);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_protector_missing() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Non-existent protector
        assert!(proxy.get_protector("0000000000000000").await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_get_protector_wrong_id() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Invalid protector ID
        assert!(proxy.get_protector("0000").await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_create_protector_invalid_type() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        assert!(proxy.create_protector(as_opts(&str_dict([
            ("type", "no-such-type"),
            ("name", "prot1"),
            ("password", "pass1"),
        ]))).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_create_protector_missing_options() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        assert!(proxy.create_protector(as_opts(&str_dict([
            ("name", "prot1"),
            ("password", "pass1"),
        ]))).await.is_err());
        assert!(proxy.create_protector(as_opts(&str_dict([
            ("type", "password"),
            ("password", "pass1"),
        ]))).await.is_err());
        assert!(proxy.create_protector(as_opts(&str_dict([
            ("type", "password"),
            ("name", "prot1"),
        ]))).await.is_err());

        Ok(())
    }

    // Helper: create a password protector
    async fn create_test_protector(
        proxy: &Dirlock1Proxy<'_>,
        password: &str,
    ) -> Result<String> {
        let id = proxy.create_protector(as_opts(&str_dict([
            ("type", "password"),
            ("name", "test"),
            ("password", password),
        ]))).await?;

        // Verify the ID
        ProtectorId::from_str(&id)?;

        Ok(id)
    }

    // Helper: encrypt an empty directory
    async fn encrypt_test_dir(
        proxy: &Dirlock1Proxy<'_>,
        dir: &Path,
        prot_id: &str,
        password: &str,
    ) -> Result<String> {
        let policy_id = proxy.encrypt_dir(
            dir.to_str().unwrap(),
            as_opts(&str_dict([
                ("protector", &prot_id),
                ("password", password),
            ])),
        ).await?;

        // Verify the ID
        PolicyKeyId::from_str(&policy_id)?;

        Ok(policy_id)
    }

    #[tokio::test]
    async fn test_encrypt_dir() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create and encrypt an empty directory
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let prot_id = create_test_protector(&proxy, "pass1").await?;
        let policy_id = encrypt_test_dir(&proxy, dir.path(), &prot_id, "pass1").await?;

        // The directory should now be encrypted and unlocked
        let status = proxy.get_dir_status(&dir.path().to_str().unwrap()).await?;
        assert_eq!(expect_str(&status, "status")?, "unlocked");
        assert_eq!(expect_str(&status, "policy")?, policy_id);
        assert_eq!(expect_bool(&status, "has-recovery-key")?, false);
        assert_eq!(status.len(), 4); // Element 4 is the 'protectors' field

        // Lock the directory
        proxy.lock_dir(&dir.path().to_str().unwrap()).await?;
        let status = proxy.get_dir_status(&dir.path().to_str().unwrap()).await?;
        assert_eq!(expect_str(&status, "status")?, "locked");
        assert_eq!(expect_str(&status, "policy")?, policy_id);
        assert_eq!(expect_bool(&status, "has-recovery-key")?, false);
        assert_eq!(status.len(), 4); // Element 4 is the 'protectors' field

        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_dir_wrong_options() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create a directory and a protector
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let prot_id = create_test_protector(&proxy, "pass").await?;

        // Try to encrypt it with the wrong password
        assert!(encrypt_test_dir(&proxy, dir.path(), &prot_id, "wrong").await.is_err());

        // Try to encrypt it without setting the password
        assert!(proxy.encrypt_dir(
            dir.path().to_str().unwrap(),
            as_opts(&str_dict([
                ("protector", &prot_id),
            ])),
        ).await.is_err());

        // Try to encrypt it without setting the protector ID
        assert!(proxy.encrypt_dir(
            dir.path().to_str().unwrap(),
            as_opts(&str_dict([
                ("password", "pass"),
            ])),
        ).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_lock_unlock_dir() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create an empty directory and a protector
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let dir_str = dir.path().to_str().unwrap();
        let prot_id = create_test_protector(&proxy, "pass1").await?;

        let unlock_opts = str_dict([
            ("protector", &prot_id),
            ("password", "pass1"),
        ]);

        // You cannot lock or unlock an unencrypted directory
        assert!(proxy.lock_dir(dir_str).await.is_err());
        assert!(proxy.unlock_dir(dir_str, as_opts(&unlock_opts)).await.is_err());

        // Encrypt the directory
        let _ = encrypt_test_dir(&proxy, dir.path(), &prot_id, "pass1").await?;

        // You cannot unlock an already unlocked directory
        assert!(proxy.unlock_dir(dir_str, as_opts(&unlock_opts)).await.is_err());

        // Lock the directory
        proxy.lock_dir(dir_str).await?;

        // You cannot lock an already locked directory
        assert!(proxy.lock_dir(dir_str).await.is_err());

        // Unlock the directory
        proxy.unlock_dir(dir_str, as_opts(&unlock_opts)).await?;

        // Lock it again (in order to release the key from the kernel)
        proxy.lock_dir(dir_str).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_unlock_dir_wrong_options() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create an empty directory and a protector
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let dir_str = dir.path().to_str().unwrap();
        let prot_id = create_test_protector(&proxy, "pass1").await?;

        // Encrypt and lock the directory
        let _ = encrypt_test_dir(&proxy, dir.path(), &prot_id, "pass1").await?;
        proxy.lock_dir(dir_str).await?;

        // You cannot unlock a directory with the wrong password
        assert!(proxy.unlock_dir(
            dir_str,
            as_opts(&str_dict([
                ("protector", &prot_id),
                ("password", "wrong"),
            ]))).await.is_err());

        // You cannot unlock a directory with missing options
        assert!(proxy.unlock_dir(
            dir_str,
            as_opts(&str_dict([
                ("password", "pass1"),
            ]))).await.is_err());

        assert!(proxy.unlock_dir(
            dir_str,
            as_opts(&str_dict([
                ("protector", &prot_id),
            ]))).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_create_remove_protector() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let id = create_test_protector(&proxy, "pass1").await?;

        // Remove the protector
        proxy.remove_protector(&id).await?;

        // It should be gone now
        assert!(proxy.get_protector(&id).await.is_err());

        // Trying to remove a missing protector should fail
        assert!(proxy.remove_protector(&id).await.is_err());
        assert!(proxy.remove_protector("0000000000000000").await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_get_all_protectors() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create two protectors
        let id1 = proxy.create_protector(as_opts(&str_dict([
            ("type", "password"),
            ("name", "prot1"),
            ("password", "pass1"),
        ]))).await?;

        let id2 = proxy.create_protector(as_opts(&str_dict([
            ("type", "password"),
            ("name", "prot2"),
            ("password", "pass2"),
        ]))).await?;

        // Get all protectors, we should get two
        let prots = proxy.get_all_protectors().await?;
        assert_eq!(prots.len(), 2);

        // Find each protector by ID and check all fields
        let p1 = prots.iter().find(|p| expect_str(p, "id").unwrap() == id1).unwrap();
        assert_eq!(expect_str(p1, "type")?, "password");
        assert_eq!(expect_str(p1, "name")?, "prot1");
        assert_eq!(expect_bool(p1, "needs-password")?, true);
        assert_eq!(p1.len(), 4);

        let p2 = prots.iter().find(|p| expect_str(p, "id").unwrap() == id2).unwrap();
        assert_eq!(expect_str(p2, "type")?, "password");
        assert_eq!(expect_str(p2, "name")?, "prot2");
        assert_eq!(expect_bool(p2, "needs-password")?, true);
        assert_eq!(p2.len(), 4);

        // Remove one and check again
        proxy.remove_protector(&id1).await?;
        let prots = proxy.get_all_protectors().await?;
        assert_eq!(prots.len(), 1);
        assert_eq!(expect_str(&prots[0], "id")?, id2);
        assert_eq!(expect_str(&prots[0], "type")?, "password");
        assert_eq!(expect_str(&prots[0], "name")?, "prot2");
        assert_eq!(expect_bool(&prots[0], "needs-password")?, true);
        assert_eq!(prots[0].len(), 4);

        // Remove the last one
        proxy.remove_protector(&id2).await?;
        let prots = proxy.get_all_protectors().await?;
        assert!(prots.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_change_verify_protector_password() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let password = "pass1";
        let new_password = "pass2";
        let prot_id = create_test_protector(&proxy, password).await?;

        // Verify the correct password
        assert_eq!(proxy.verify_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", password),
        ]))).await?, true);

        // Verify the wrong password
        assert_eq!(proxy.verify_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", "wrong"),
        ]))).await?, false);

        // Change the password
        proxy.change_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
            ("old-password", password),
            ("new-password", new_password),
        ]))).await?;

        // Verify the new password works
        assert_eq!(proxy.verify_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", new_password),
        ]))).await?, true);

        // Verify the old password no longer works
        assert_eq!(proxy.verify_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", password),
        ]))).await?, false);

        Ok(())
    }

    #[tokio::test]
    async fn test_change_verify_protector_password_wrong_options() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let password = "pass1";
        let prot_id = create_test_protector(&proxy, password).await?;

        // Verify with missing options
        assert!(proxy.verify_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
        ]))).await.is_err());
        assert!(proxy.verify_protector_password(as_opts(&str_dict([
            ("password", password),
        ]))).await.is_err());

        // Change with the wrong old password
        assert!(proxy.change_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
            ("old-password", "wrong"),
            ("new-password", "something"),
        ]))).await.is_err());

        // Change with identical old and new passwords
        assert!(proxy.change_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
            ("old-password", password),
            ("new-password", password),
        ]))).await.is_err());

        // Change with missing options
        assert!(proxy.change_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
            ("old-password", password),
        ]))).await.is_err());
        assert!(proxy.change_protector_password(as_opts(&str_dict([
            ("protector", &prot_id),
            ("new-password", "something"),
        ]))).await.is_err());
        assert!(proxy.change_protector_password(as_opts(&str_dict([
            ("old-password", password),
            ("new-password", "something"),
        ]))).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_remove_protector_from_policy() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let pass1 = "pass1";
        let pass2 = "pass2";

        // Create two protectors and encrypt a directory with the first one
        let prot1_id = create_test_protector(&proxy, pass1).await?;
        let prot2_id = create_test_protector(&proxy, pass2).await?;
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let policy_id = encrypt_test_dir(&proxy, dir.path(), &prot1_id, pass1).await?;

        // The policy should have one protector
        let policies = proxy.get_all_policies().await?;
        assert_eq!(policies[&policy_id].len(), 1);
        assert_eq!(expect_str(&policies[&policy_id][0], "id")?, prot1_id);

        // Add prot2 to the policy
        proxy.add_protector_to_policy(as_opts(&str_dict([
            ("policy", &policy_id),
            ("protector", &prot2_id),
            ("protector-password", pass2),
            ("unlock-with", &prot1_id),
            ("unlock-with-password", pass1),
        ]))).await?;

        // The policy should now have two protectors
        let policies = proxy.get_all_policies().await?;
        assert_eq!(policies[&policy_id].len(), 2);

        // You cannot remove protectors that are being used in a policy
        assert!(proxy.remove_protector(&prot1_id).await.is_err());
        assert!(proxy.remove_protector(&prot2_id).await.is_err());

        // Remove prot1 from the policy
        proxy.remove_protector_from_policy(as_opts(&str_dict([
            ("policy", &policy_id),
            ("protector", &prot1_id),
        ]))).await?;

        // The policy should have only prot2
        let policies = proxy.get_all_policies().await?;
        assert_eq!(policies[&policy_id].len(), 1);
        assert_eq!(expect_str(&policies[&policy_id][0], "id")?, prot2_id);

        // Now it should be possible to remove prot1
        proxy.remove_protector(&prot1_id).await?;

        // Lock and unlock using prot2
        let dir_str = dir.path().to_str().unwrap();
        proxy.lock_dir(dir_str).await?;
        proxy.unlock_dir(dir_str, as_opts(&str_dict([
            ("protector", &prot2_id),
            ("password", pass2),
        ]))).await?;

        // Lock it again to release the key
        proxy.lock_dir(dir_str).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_add_remove_protector_from_policy_wrong_options() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let pass1 = "pass1";
        let pass2 = "pass2";

        // Create two protectors and encrypt a directory with the first one
        let prot1_id = create_test_protector(&proxy, pass1).await?;
        let prot2_id = create_test_protector(&proxy, pass2).await?;
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let policy_id = encrypt_test_dir(&proxy, dir.path(), &prot1_id, pass1).await?;

        // Add with wrong protector password
        assert!(proxy.add_protector_to_policy(as_opts(&str_dict([
            ("policy", &policy_id),
            ("protector", &prot2_id),
            ("protector-password", "wrong"),
            ("unlock-with", &prot1_id),
            ("unlock-with-password", pass1),
        ]))).await.is_err());

        // Add with wrong unlock-with password
        assert!(proxy.add_protector_to_policy(as_opts(&str_dict([
            ("policy", &policy_id),
            ("protector", &prot2_id),
            ("protector-password", pass2),
            ("unlock-with", &prot1_id),
            ("unlock-with-password", "wrong"),
        ]))).await.is_err());

        // Add with missing options
        assert!(proxy.add_protector_to_policy(as_opts(&str_dict([
            ("protector", &prot2_id),
            ("protector-password", pass2),
            ("unlock-with", &prot1_id),
            ("unlock-with-password", pass1),
        ]))).await.is_err());
        assert!(proxy.add_protector_to_policy(as_opts(&str_dict([
            ("policy", &policy_id),
            ("protector-password", pass2),
            ("unlock-with", &prot1_id),
            ("unlock-with-password", pass1),
        ]))).await.is_err());

        // Remove with missing options
        assert!(proxy.remove_protector_from_policy(as_opts(&str_dict([
            ("protector", &prot1_id),
        ]))).await.is_err());
        assert!(proxy.remove_protector_from_policy(as_opts(&str_dict([
            ("policy", &policy_id),
        ]))).await.is_err());

        // Cannot remove the last protector from a policy
        assert!(proxy.remove_protector_from_policy(as_opts(&str_dict([
            ("policy", &policy_id),
            ("protector", &prot1_id),
        ]))).await.is_err());

        // Lock to release the key
        proxy.lock_dir(dir.path().to_str().unwrap()).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_get_dir_status() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let dir_str = dir.path().to_str().unwrap();

        // An unencrypted directory
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "unencrypted");
        assert_eq!(status.len(), 1);

        // Encrypt the directory
        let prot_id = create_test_protector(&proxy, "pass1").await?;
        let policy_id = encrypt_test_dir(&proxy, dir.path(), &prot_id, "pass1").await?;

        // The directory should be encrypted and unlocked
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "unlocked");
        assert_eq!(expect_str(&status, "policy")?, policy_id);
        assert_eq!(expect_bool(&status, "has-recovery-key")?, false);
        assert_eq!(status.len(), 4); // Element 4 is the 'protectors' field

        // Check the protectors field
        let prots: Vec<HashMap<String, OwnedValue>> = status.get("protectors")
            .ok_or_else(|| anyhow!("Missing 'protectors'"))?
            .clone().try_into()?;
        assert_eq!(prots.len(), 1);
        assert_eq!(expect_str(&prots[0], "id")?, prot_id);
        assert_eq!(expect_str(&prots[0], "type")?, "password");
        assert_eq!(expect_str(&prots[0], "name")?, "test");
        assert_eq!(expect_bool(&prots[0], "needs-password")?, true);
        assert_eq!(prots[0].len(), 4);

        // Lock the directory
        proxy.lock_dir(dir_str).await?;

        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "locked");
        assert_eq!(expect_str(&status, "policy")?, policy_id);
        assert_eq!(expect_bool(&status, "has-recovery-key")?, false);
        assert_eq!(status.len(), 4); // Element 4 is the 'protectors' field

        Ok(())
    }
}
