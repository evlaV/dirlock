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
    LockState,
    ProtectedPolicyKey,
    convert::ConvertJob,
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
    recovery::RecoveryKey,
};

/// Events sent by background tasks to the main thread
enum Event {
    JobFinished(u32),
}

/// Global state of the dirlock D-Bus daemon
struct DirlockDaemon {
    jobs: HashMap<u32, Arc<ConvertJob>>,
    last_jobid: u32,
    tx: mpsc::Sender<Event>,
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
fn do_lock_dir(dir: &Path) -> anyhow::Result<()> {
    let encrypted_dir = EncryptedDir::open(dir, keystore(), LockState::Unlocked)?;
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
    let encrypted_dir = EncryptedDir::open(dir, keystore(), LockState::Locked)?;

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

    if ! dirlock::update_protector_password(&mut prot, pass.as_bytes(), newpass.as_bytes(), ks)? {
        bail!("Invalid password");
    }
    Ok(())
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
) -> anyhow::Result<ConvertJob> {
    let ks = keystore();
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
) -> anyhow::Result<String> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let mut encrypted_dir = EncryptedDir::open(dir, keystore(), LockState::Any)?;

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
fn do_recovery_remove(dir: &Path) -> anyhow::Result<()> {
    match dirlock::open_dir(dir, keystore())? {
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
) -> anyhow::Result<()> {
    let ks = keystore();
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
) -> anyhow::Result<()> {
    let policy_id = PolicyKeyId::from_str(policy)?;
    let protector_id = ProtectorId::from_str(protector)?;
    dirlock::remove_protector_from_policy(&policy_id, &protector_id, keystore())
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
#[interface(name = "com.valvesoftware.Dirlock")]
impl DirlockDaemon {
    async fn lock_dir(
        &self,
        dir: &Path
    ) -> Result<()> {
        do_lock_dir(dir).into_dbus()
    }

    async fn unlock_dir(
        &self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let pass = get_str(&options, "password")?;
        let protector = get_str(&options, "protector")?;
        do_unlock_dir(dir, &pass, &protector).into_dbus()
    }

    async fn verify_protector_password(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<bool> {
        let pass = get_str(&options, "password")?;
        let protector = get_str(&options, "protector")?;
        do_verify_protector_password(&pass, &protector).into_dbus()
    }

    async fn change_protector_password(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let pass = get_str(&options, "old-password")?;
        let newpass = get_str(&options, "new-password")?;
        let protector = get_str(&options, "protector")?;
        do_change_protector_password(&pass, &newpass, &protector).into_dbus()
    }

    async fn get_dir_status(
        &self,
        dir: &Path,
    ) -> Result<DbusDirStatus> {
        do_get_dir_status(dir).into_dbus()
    }

    async fn encrypt_dir(
        &self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
    ) -> Result<String> {
        let pass = get_str(&options, "password")?;
        let protector = get_str(&options, "protector")?;
        do_encrypt_dir(dir, &pass, &protector).into_dbus()
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
        let job = do_convert_dir(dir, &pass, &protector)
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
        do_create_protector(&ptype, &name, &pass).into_dbus()
    }

    async fn remove_protector(
        &self,
        protector_id: &str,
    ) -> Result<()> {
        do_remove_protector(protector_id).into_dbus()
    }

    async fn get_all_protectors(&self) -> Result<Vec<DbusProtectorData>> {
        do_get_all_protectors().into_dbus()
    }

    async fn get_all_policies(&self) -> Result<DbusPolicyData> {
        do_get_all_policies().into_dbus()
    }

    async fn get_protector(&self, id: &str) -> Result<DbusProtectorData> {
        ProtectorId::from_str(id)
            .and_then(do_get_protector)
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
        do_add_protector_to_policy(&policy, &protector, &protector_pass, &unlock_with, &unlock_with_pass)
            .into_dbus()
    }

    async fn remove_protector_from_policy(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let policy = get_str(&options, "policy")?;
        let protector = get_str(&options, "protector")?;
        do_remove_protector_from_policy(&policy, &protector)
            .into_dbus()
    }

    async fn recovery_add(
        &self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
    ) -> Result<String> {
        let protector = get_str(&options, "protector")?;
        let pass = get_str(&options, "password")?;
        do_recovery_add(dir, &protector, &pass).into_dbus()
    }

    async fn recovery_remove(
        &self,
        dir: &Path,
    ) -> Result<()> {
        do_recovery_remove(dir).into_dbus()
    }

    async fn recovery_restore(
        &self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let recovery_key = get_str(&options, "recovery-key")?;
        let protector = get_str(&options, "protector")?;
        let pass = get_str(&options, "password")?;
        do_recovery_restore(dir, &recovery_key, &protector, &pass).into_dbus()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dirlock::init()?;
    let (tx, mut rx) = mpsc::channel::<Event>(2);
    let builder = zbus::connection::Builder::session()?;
    let conn = builder.name("com.valvesoftware.Dirlock")?
        .build()
        .await?;
    let daemon = DirlockDaemon {
        jobs: HashMap::new(),
        last_jobid: 0,
        tx,
    };

    conn.object_server()
        .at("/com/valvesoftware/Dirlock", daemon)
        .await?;

    let iface : InterfaceRef<DirlockDaemon> =
        conn.object_server().interface("/com/valvesoftware/Dirlock").await?;

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
