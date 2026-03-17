/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail};
use serde::Serialize;
use zbus::fdo::Result;
use zbus::fdo::Error;
use zeroize::Zeroizing;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::os::fd::AsFd;
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
        RemovalStatusFlags,
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

// String versions of fscrypt::RemovalStatusFlags
const FILES_BUSY_FLAG: &str = "files-busy";
const OTHER_USERS_FLAG: &str = "other-users";

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

/// Maximum size of secrets (i.e. passwords) sent via D-Bus
const MAX_SECRET_SIZE: usize = 256;

/// Extract a secret from the options dict.
/// If `<key>-fd` is present, the secret is read from an fd.
/// Otherwise, `<key>` is read as a plain string.
fn get_secret(options: &HashMap<String, Value<'_>>, key: &str) -> zbus::fdo::Result<Zeroizing<Vec<u8>>> {
    let fd_key = format!("{key}-fd");
    if options.contains_key(fd_key.as_str()) && options.contains_key(key) {
        return Err(Error::InvalidArgs(format!("'{key}' and '{fd_key}' are mutually exclusive")));
    }
    if let Some(Value::Fd(fd)) = options.get(fd_key.as_str()) {
        let mut buf = Zeroizing::new(Vec::new());
        let owned = fd.as_fd().try_clone_to_owned()
            .map_err(|e| Error::Failed(format!("failed to clone '{fd_key}': {e}")))?;
        std::fs::File::from(owned)
            .take(MAX_SECRET_SIZE as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| Error::Failed(format!("failed to read from '{fd_key}': {e}")))?;
        if buf.len() > MAX_SECRET_SIZE {
            return Err(Error::InvalidArgs(format!("'{fd_key}' is too long")));
        }
        return Ok(buf);
    }
    Ok(Zeroizing::new(get_str(options, key)?.into_bytes()))
}

/// Extract an optional fd from the options dict.
fn get_opt_fd(options: &HashMap<String, Value<'_>>, key: &str) -> zbus::fdo::Result<Option<std::os::fd::OwnedFd>> {
    match options.get(key) {
        Some(Value::Fd(fd)) => {
            let owned = fd.as_fd().try_clone_to_owned()
                .map_err(|e| Error::Failed(format!("failed to clone '{key}': {e}")))?;
            Ok(Some(owned))
        }
        Some(_) => Err(Error::InvalidArgs(format!("'{key}' must be a file descriptor"))),
        None => Ok(None),
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

/// Convert RemovalStatusFlags into a list of strings
fn removal_status_flags_to_strings(flags: RemovalStatusFlags) -> Vec<String> {
    let mut result = Vec::new();
    let mut remaining = flags;
    if remaining.contains(RemovalStatusFlags::FilesBusy) {
        result.push(FILES_BUSY_FLAG.to_string());
        remaining.remove(RemovalStatusFlags::FilesBusy);
    }
    if remaining.contains(RemovalStatusFlags::OtherUsers) {
        result.push(OTHER_USERS_FLAG.to_string());
        remaining.remove(RemovalStatusFlags::OtherUsers);
    }
    if !remaining.is_empty() {
        result.push(format!("unknown-flags-{:#x}", remaining.bits()));
    }
    result
}

/// Lock a directory
fn do_lock_dir(dir: &Path, ks: &Keystore) -> anyhow::Result<Vec<String>> {
    let encrypted_dir = EncryptedDir::open(dir, ks, LockState::Unlocked)?;
    let flags = encrypted_dir.lock(fscrypt::RemoveKeyUsers::CurrentUser)?;
    Ok(removal_status_flags_to_strings(flags))
}

/// Unlock a directory
fn do_unlock_dir(
    dir: &Path,
    pass: &[u8],
    protector_id: &str,
    ks: &Keystore,
) -> anyhow::Result<()> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let encrypted_dir = EncryptedDir::open(dir, ks, LockState::Locked)?;

    if encrypted_dir.unlock(pass, &protector_id)? {
        Ok(())
    } else {
        bail!("Authentication failed")
    }
}

/// Verify the password of a protector (without unlocking anything)
fn do_verify_protector_password(
    pass: &[u8],
    protector_id: &str,
    ks: &Keystore,
) -> anyhow::Result<bool> {
    ProtectorId::from_str(protector_id)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))
        .and_then(|prot| prot.unwrap_key(pass))
        .map(|key| key.is_some())
}

/// Change the password of a protector
fn do_change_protector_password(
    pass: &[u8],
    newpass: &[u8],
    protector_id: &str,
    ks: &Keystore,
) -> anyhow::Result<()> {
    if pass == newpass {
        bail!("The old and new passwords are identical");
    }

    let mut prot = ProtectorId::from_str(protector_id)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))?;

    if ! dirlock::update_protector_password(&mut prot, pass, newpass, ks)? {
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
    pass: &[u8],
    protector_id: &str,
    ks: &Keystore,
) -> anyhow::Result<String> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let protector = ks.load_protector(protector_id)?;

    dirlock::ensure_unencrypted(dir, ks)?;

    let key = match protector.unwrap_key(pass)? {
        Some(k) => k,
        None => bail!("Authentication failed"),
    };

    let keyid = dirlock::encrypt_dir(dir, &protector, key, ks)?;
    Ok(keyid.to_string())
}

/// Convert a directory using an existing protector
fn do_convert_dir(
    dir: &Path,
    pass: &[u8],
    protector_id: &str,
    ks: &Keystore,
) -> anyhow::Result<ConvertJob> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let protector = ks.load_protector(protector_id)?;

    dirlock::ensure_unencrypted(dir, ks)?;

    if dirlock::util::dir_is_empty(dir)? {
        bail!("The directory is empty, use EncryptDir instead");
    }

    let key = match protector.unwrap_key(pass)? {
        Some(k) => k,
        None => bail!("Authentication failed"),
    };

    ConvertJob::start(dir, &protector, key, ks)
}

/// Create a new protector
fn do_create_protector(
    ptype: &str,
    name: &str,
    pass: &[u8],
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
            dirlock::create_protector(opts, pass, create, ks)
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
    let prot = ks.load_protector(id)
        .map_err(|e| anyhow!("Error reading protector {id}: {e}"))?;
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
    protector_pass: &[u8],
    unlock_with: &str,
    unlock_with_pass: &[u8],
    ks: &Keystore,
) -> anyhow::Result<()> {
    let policy_id = PolicyKeyId::from_str(policy)?;
    let protector = ProtectorId::from_str(protector)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))?;
    let unlock_with = ProtectorId::from_str(unlock_with)
        .and_then(|id| ks.load_protector(id).map_err(|e| e.into()))?;

    let Some(protector_key) = protector.unwrap_key(protector_pass)? else {
        bail!("Invalid {} for protector {}", protector.get_type().credential_name(), protector.id);
    };

    dirlock::add_protector_to_policy(&policy_id, &protector_key, &unlock_with, unlock_with_pass, ks)
}

/// Add a recovery key to an encrypted directory.
/// If `out_fd` is provided, write the recovery key to it and return
/// an empty string, avoiding the secret traveling over D-Bus.
fn do_recovery_add(
    dir: &Path,
    protector_id: &str,
    pass: &[u8],
    out_fd: Option<std::os::fd::OwnedFd>,
    ks: &Keystore,
) -> anyhow::Result<String> {
    let protector_id = ProtectorId::from_str(protector_id)?;
    let mut encrypted_dir = EncryptedDir::open(dir, ks, LockState::Any)?;

    if encrypted_dir.recovery.is_some() {
        bail!("This directory already has a recovery key");
    }

    let prot = encrypted_dir.get_protector_by_id(&protector_id)?;
    let Some(protkey) = prot.unwrap_key(pass)? else {
        bail!("Authentication failed");
    };

    let recovery = encrypted_dir.add_recovery_key(&protkey)?;

    if let Some(fd) = out_fd {
        let mut f = std::fs::File::from(fd);
        f.write_all(recovery.to_string().as_bytes())?;
        Ok(String::new())
    } else {
        Ok(recovery.to_string())
    }
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
    recovery_key_str: &[u8],
    protector_id: &str,
    pass: &[u8],
    ks: &Keystore,
) -> anyhow::Result<()> {
    let encrypted_dir = EncryptedDir::open(dir, ks, LockState::Any)?;

    let Some(recovery) = &encrypted_dir.recovery else {
        bail!("This directory does not have a recovery key");
    };

    let Ok(recovery_key) = RecoveryKey::from_ascii_bytes(recovery_key_str) else {
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
    let Some(protector_key) = protector.unwrap_key(pass)? else {
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
    ) -> Result<Vec<String>> {
        do_lock_dir(dir, &self.ks).into_dbus()
    }

    async fn unlock_dir(
        &self,
        dir: &Path,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let pass = get_secret(&options, "password")?;
        let protector = get_str(&options, "protector")?;
        do_unlock_dir(dir, &pass, &protector, &self.ks).into_dbus()
    }

    async fn verify_protector_password(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<bool> {
        let pass = get_secret(&options, "password")?;
        let protector = get_str(&options, "protector")?;
        do_verify_protector_password(&pass, &protector, &self.ks).into_dbus()
    }

    async fn change_protector_password(
        &self,
        options: HashMap<String, Value<'_>>,
    ) -> Result<()> {
        let pass = get_secret(&options, "old-password")?;
        let newpass = get_secret(&options, "new-password")?;
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
        let pass = get_secret(&options, "password")?;
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
        let pass = get_secret(&options, "password")?;
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
        jobid: u32,
    ) -> Result<()> {
        match self.jobs.get(&jobid) {
            Some(job) => job.cancel().into_dbus(),
            None => Err(Error::Failed(format!("Job {jobid} not found"))),
        }
    }

    async fn job_status(
        &self,
        jobid: u32,
    ) -> Result<i32> {
        match self.jobs.get(&jobid) {
            Some(job) => Ok(job.progress()),
            None => Err(Error::Failed(format!("Job {jobid} not found"))),
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
        let pass = get_secret(&options, "password")?;
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
        let protector_pass = get_secret(&options, "protector-password")?;
        let unlock_with = get_str(&options, "unlock-with")?;
        let unlock_with_pass = get_secret(&options, "unlock-with-password")?;
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
        let pass = get_secret(&options, "password")?;
        let out_fd = get_opt_fd(&options, "recovery-key-fd")?;
        do_recovery_add(dir, &protector, &pass, out_fd, &self.ks).into_dbus()
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
        let recovery_key = get_secret(&options, "recovery-key")?;
        let protector = get_str(&options, "protector")?;
        let pass = get_secret(&options, "password")?;
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
                    if let Err(e) = iface.get_mut().await.handle_event(emitter, ev).await {
                        eprintln!("Error handling event: {e}");
                    }
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

    /// Create a memfd containing the given data and return it as a
    /// D-Bus Value, suitable for using in an options dict.
    fn secret_to_memfd(data: &[u8]) -> Value<'static> {
        use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
        use nix::unistd::{lseek, write, Whence};
        use std::os::fd::AsRawFd;

        let fd = memfd_create(c"dirlock-fd", MemFdCreateFlag::empty())
            .expect("memfd_create failed");
        write(&fd, data).expect("write to memfd failed");
        lseek(fd.as_raw_fd(), 0, Whence::SeekSet).expect("lseek failed");
        Value::from(zvariant::Fd::from(fd))
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
        _event_task: tokio::task::JoinHandle<()>,
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

            let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(2);
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

            // Spawn a task to process events (needed for convert jobs)
            let iface: InterfaceRef<DirlockDaemon> =
                _server_conn.object_server().interface(DIRLOCK_DBUS_PATH).await?;
            let _event_task = tokio::task::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    let emitter = iface.signal_emitter();
                    _ = iface.get_mut().await.handle_event(emitter, ev).await;
                }
            });

            let client_conn = zbus::connection::Builder::session()?
                .build()
                .await?;

            Ok(TestService { _keystore_dir, _server_conn, _event_task, client_conn, service_name })
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
    async fn test_encrypt_dir_non_empty() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create a directory and put a file inside
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        std::fs::write(dir.path().join("file.txt"), "hello")?;

        // Try to encrypt it: it should fail
        let password = "pass1";
        let prot_id = create_test_protector(&proxy, password).await?;
        assert!(encrypt_test_dir(&proxy, dir.path(), &prot_id, password).await.is_err());

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

        // Lock the directory (no open files, so no flags)
        let flags = proxy.lock_dir(dir_str).await?;
        assert!(flags.is_empty());

        // You cannot lock an already locked directory
        assert!(proxy.lock_dir(dir_str).await.is_err());

        // Unlock the directory
        proxy.unlock_dir(dir_str, as_opts(&unlock_opts)).await?;

        // Lock it again (in order to release the key from the kernel)
        let flags = proxy.lock_dir(dir_str).await?;
        assert!(flags.is_empty());

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
    async fn test_lock_dir_files_busy() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let password = "pass1";

        // Create and encrypt a directory
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let dir_str = dir.path().to_str().unwrap();
        let prot_id = create_test_protector(&proxy, password).await?;
        encrypt_test_dir(&proxy, dir.path(), &prot_id, password).await?;

        // Create a file and keep it open
        let open_file = std::fs::File::create(dir.path().join("busy.txt"))?;

        // Lock should succeed but report files-busy
        let flags = proxy.lock_dir(dir_str).await?;
        assert!(flags.contains(&FILES_BUSY_FLAG.to_string()),
                "expected {FILES_BUSY_FLAG} flag, got {flags:?}");

        // The directory should be partially locked
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "partially-locked");

        // Unlock the partially-locked directory (the file is still open)
        let unlock_opts = str_dict([
            ("protector", prot_id.as_str()),
            ("password", password),
        ]);
        proxy.unlock_dir(dir_str, as_opts(&unlock_opts)).await?;
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "unlocked");

        // Lock again while the file is still open
        let flags = proxy.lock_dir(dir_str).await?;
        assert!(flags.contains(&FILES_BUSY_FLAG.to_string()),
                "expected {FILES_BUSY_FLAG} flag, got {flags:?}");
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "partially-locked");

        // Drop the open file, lock, and verify it's fully locked
        drop(open_file);
        let flags = proxy.lock_dir(dir_str).await?;
        assert!(flags.is_empty());

        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "locked");

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

    #[tokio::test]
    async fn test_recovery_add_remove() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let password = "pass1";
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let dir_str = dir.path().to_str().unwrap();
        let prot_id = create_test_protector(&proxy, password).await?;
        encrypt_test_dir(&proxy, dir.path(), &prot_id, password).await?;

        // No recovery key yet
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_bool(&status, "has-recovery-key")?, false);

        // Add a recovery key
        let recovery_key = proxy.recovery_add(dir_str, as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", password),
        ]))).await?;
        assert!(!recovery_key.is_empty());

        // The status should reflect the recovery key
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_bool(&status, "has-recovery-key")?, true);

        // Cannot add a second recovery key
        assert!(proxy.recovery_add(dir_str, as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", password),
        ]))).await.is_err());

        // Remove the recovery key
        proxy.recovery_remove(dir_str).await?;

        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_bool(&status, "has-recovery-key")?, false);

        // Lock to release the key
        proxy.lock_dir(dir_str).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_recovery_add_fd() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create and encrypt a directory
        let password = "pass1";
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let dir_str = dir.path().to_str().unwrap();
        let prot_id = create_test_protector(&proxy, password).await?;
        encrypt_test_dir(&proxy, dir.path(), &prot_id, password).await?;

        // Add a recovery key, using an fd to return it from the daemon
        let (read_fd, write_fd) = nix::unistd::pipe()?;
        let mut opts = str_dict([
            ("protector", prot_id.as_str()),
            ("password", password),
        ]);
        opts.push(("recovery-key-fd", Value::from(zvariant::Fd::from(write_fd))));

        let ret = proxy.recovery_add(dir_str, as_opts(&opts)).await?;
        drop(opts); // this drops write_fd, closing the write part of the pipe
        assert!(ret.is_empty(), "return value should be empty when fd is used");

        // Read the recovery key from the read end of the pipe
        let mut buf = String::new();
        std::fs::File::from(read_fd).read_to_string(&mut buf)?;
        assert!(!buf.is_empty(), "recovery key should have been written to fd");

        // Verify that the recovery key is set
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_bool(&status, "has-recovery-key")?, true);

        // Clean up
        proxy.recovery_remove(dir_str).await?;
        proxy.lock_dir(dir_str).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_recovery_add_wrong_options() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let password = "pass1";
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let dir_str = dir.path().to_str().unwrap();
        let prot_id = create_test_protector(&proxy, password).await?;
        encrypt_test_dir(&proxy, dir.path(), &prot_id, password).await?;

        // Wrong password
        assert!(proxy.recovery_add(dir_str, as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", "wrong"),
        ]))).await.is_err());

        // Missing options
        assert!(proxy.recovery_add(dir_str, as_opts(&str_dict([
            ("protector", &prot_id),
        ]))).await.is_err());
        assert!(proxy.recovery_add(dir_str, as_opts(&str_dict([
            ("password", password),
        ]))).await.is_err());

        // Cannot remove a recovery key that doesn't exist
        assert!(proxy.recovery_remove(dir_str).await.is_err());

        // Cannot add/remove recovery on an unencrypted directory
        let unenc_dir = TempDir::new_in(&mntpoint, "unencrypted")?;
        let unenc_str = unenc_dir.path().to_str().unwrap();
        assert!(proxy.recovery_add(unenc_str, as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", password),
        ]))).await.is_err());
        assert!(proxy.recovery_remove(unenc_str).await.is_err());

        // Lock to release the key
        proxy.lock_dir(dir_str).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_recovery_restore() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create and encrypt a new directory
        let password = "pass1";
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let dir_str = dir.path().to_str().unwrap();
        let prot_id = create_test_protector(&proxy, password).await?;
        encrypt_test_dir(&proxy, dir.path(), &prot_id, password).await?;

        // Add a recovery key and lock the directory
        let recovery_key = proxy.recovery_add(dir_str, as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", password),
        ]))).await?;
        proxy.lock_dir(dir_str).await?;

        // Start a new service with a fresh keystore to simulate losing the old one
        let srv2 = TestService::start().await?;
        let proxy2 = srv2.proxy().await?;

        // The directory is still encrypted (the recovery key keeps it from being key-missing)
        let status = proxy2.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "locked");

        // Create a new protector and restore using the recovery key
        let new_password = "pass2";
        let new_prot_id = create_test_protector(&proxy2, new_password).await?;
        proxy2.recovery_restore(dir_str, as_opts(&str_dict([
            ("recovery-key", &recovery_key),
            ("protector", &new_prot_id),
            ("password", new_password),
        ]))).await?;

        // The directory should now be unlockable with the new protector
        proxy2.unlock_dir(dir_str, as_opts(&str_dict([
            ("protector", &new_prot_id),
            ("password", new_password),
        ]))).await?;

        let status = proxy2.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "unlocked");

        // Lock to release the key
        proxy2.lock_dir(dir_str).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_recovery_restore_wrong_options() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create and encrypt a new directory
        let password = "pass1";
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let dir_str = dir.path().to_str().unwrap();
        let prot_id = create_test_protector(&proxy, password).await?;
        encrypt_test_dir(&proxy, dir.path(), &prot_id, password).await?;

        // Add a recovery key
        let recovery_key = proxy.recovery_add(dir_str, as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", password),
        ]))).await?;

        // Cannot restore with a protector that already protects this directory
        assert!(proxy.recovery_restore(dir_str, as_opts(&str_dict([
            ("recovery-key", &recovery_key),
            ("protector", &prot_id),
            ("password", password),
        ]))).await.is_err());

        // Wrong recovery key
        let new_password = "pass2";
        let new_prot_id = create_test_protector(&proxy, new_password).await?;
        assert!(proxy.recovery_restore(dir_str, as_opts(&str_dict([
            ("recovery-key", "dddddddd-dddddddd-dddddddd-dddddddd-dddddddd-dddddddd-dddddddd-dddddddd"),
            ("protector", &new_prot_id),
            ("password", new_password),
        ]))).await.is_err());

        // Invalid recovery key
        assert!(proxy.recovery_restore(dir_str, as_opts(&str_dict([
            ("recovery-key", "12345"),
            ("protector", &new_prot_id),
            ("password", new_password),
        ]))).await.is_err());

        // Missing options
        assert!(proxy.recovery_restore(dir_str, as_opts(&str_dict([
            ("protector", &new_prot_id),
            ("password", new_password),
        ]))).await.is_err());
        assert!(proxy.recovery_restore(dir_str, as_opts(&str_dict([
            ("recovery-key", &recovery_key),
            ("password", new_password),
        ]))).await.is_err());
        assert!(proxy.recovery_restore(dir_str, as_opts(&str_dict([
            ("recovery-key", &recovery_key),
            ("protector", &new_prot_id),
        ]))).await.is_err());

        // Lock to release the key
        proxy.lock_dir(dir_str).await?;

        Ok(())
    }

    /// Helper: start a convert job and wait for it to finish.
    /// Returns the policy ID from the job_finished signal.
    async fn convert_and_wait(
        proxy: &Dirlock1Proxy<'_>,
        dir: &str,
        prot_id: &str,
        password: &str,
    ) -> Result<String> {
        use futures_lite::StreamExt;

        let mut finished = proxy.receive_job_finished().await?;
        let mut failed = proxy.receive_job_failed().await?;

        let jobid = proxy.convert_dir(dir, as_opts(&str_dict([
            ("protector", prot_id),
            ("password", password),
        ]))).await?;

        // Wait for either job_finished or job_failed
        tokio::select! {
            Some(sig) = finished.next() => {
                let args = sig.args()?;
                assert_eq!(args.jobid, jobid);
                Ok(args.keyid.to_string())
            }
            Some(sig) = failed.next() => {
                let args = sig.args()?;
                assert_eq!(args.jobid, jobid);
                bail!("{}", args.error)
            }
        }
    }

    #[tokio::test]
    async fn test_convert() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create a directory with some files
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        let dir_str = dir.path().to_str().unwrap();
        std::fs::write(dir.path().join("file.txt"), "hello")?;
        std::fs::create_dir(dir.path().join("subdir"))?;
        std::fs::write(dir.path().join("subdir/nested.txt"), "world")?;

        // Create a protector
        let password = "1234";
        let prot_id = create_test_protector(&proxy, password).await?;

        // Convert the directory
        let policy_id = convert_and_wait(&proxy, dir_str, &prot_id, password).await?;
        PolicyKeyId::from_str(&policy_id)?;

        // Verify that the directory is encrypted and unlocked
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "unlocked");
        assert_eq!(expect_str(&status, "policy")?, policy_id);

        // Verify that the data was preserved
        assert_eq!(std::fs::read_to_string(dir.path().join("file.txt"))?, "hello");
        assert_eq!(std::fs::read_to_string(dir.path().join("subdir/nested.txt"))?, "world");

        // Lock and unlock to verify that the protector works
        proxy.lock_dir(dir_str).await?;
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "locked");

        proxy.unlock_dir(dir_str, as_opts(&str_dict([
            ("protector", &prot_id),
            ("password", password),
        ]))).await?;
        let status = proxy.get_dir_status(dir_str).await?;
        assert_eq!(expect_str(&status, "status")?, "unlocked");

        // Verify the data again
        assert_eq!(std::fs::read_to_string(dir.path().join("file.txt"))?, "hello");
        assert_eq!(std::fs::read_to_string(dir.path().join("subdir/nested.txt"))?, "world");

        proxy.lock_dir(dir_str).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_convert_empty_dir() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let password = "1234";
        let prot_id = create_test_protector(&proxy, password).await?;

        // Converting an empty directory should fail
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        let dir_str = dir.path().to_str().unwrap();
        let err = proxy.convert_dir(dir_str, as_opts(&str_dict([
            ("protector", prot_id.as_str()),
            ("password", password),
        ]))).await.unwrap_err();
        assert!(err.to_string().contains("empty"),
                "unexpected error: {err}");

        Ok(())
    }

    #[tokio::test]
    async fn test_convert_already_encrypted() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let password = "1234";
        let prot_id = create_test_protector(&proxy, password).await?;

        // Encrypt a directory first, then put a file in it
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        encrypt_test_dir(&proxy, dir.path(), &prot_id, password).await?;
        std::fs::write(dir.path().join("file.txt"), "data")?;

        // Trying to convert an already-encrypted directory should fail
        let dir_str = dir.path().to_str().unwrap();
        let err = proxy.convert_dir(dir_str, as_opts(&str_dict([
            ("protector", prot_id.as_str()),
            ("password", password),
        ]))).await.unwrap_err();
        assert!(err.to_string().contains("encrypted"),
                "unexpected error: {err}");

        proxy.lock_dir(dir_str).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_secret_fd_basic() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        // Create a protector using a string password
        let password = "pass1";
        let prot_id = create_test_protector(&proxy, password).await?;

        // Verify it passing the password using an fd
        let fd = secret_to_memfd(password.as_bytes());
        let mut opts = str_dict([("protector", prot_id.as_str())]);
        opts.push(("password-fd", fd));
        assert_eq!(proxy.verify_protector_password(as_opts(&opts)).await?, true);

        // Passing the wrong password should fail
        let fd = secret_to_memfd(b"wrong");
        let mut opts = str_dict([("protector", prot_id.as_str())]);
        opts.push(("password-fd", fd));
        assert_eq!(proxy.verify_protector_password(as_opts(&opts)).await?, false);

        Ok(())
    }

    #[tokio::test]
    async fn test_secret_fd_mutually_exclusive() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let prot_id = create_test_protector(&proxy, "pass1").await?;

        // You cannot pass both 'password' and 'password-fd'
        let fd = secret_to_memfd(b"pass1");
        let mut opts = str_dict([
            ("protector", prot_id.as_str()),
            ("password", "pass1"),
        ]);
        opts.push(("password-fd", fd));
        assert!(proxy.verify_protector_password(as_opts(&opts)).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_secret_fd_too_large() -> Result<()> {
        let srv = TestService::start().await?;
        let proxy = srv.proxy().await?;

        let prot_id = create_test_protector(&proxy, "pass1").await?;

        let large = vec![b'x'; MAX_SECRET_SIZE + 1];
        let fd = secret_to_memfd(&large);
        let mut opts = str_dict([("protector", prot_id.as_str())]);
        opts.push(("password-fd", fd));
        assert!(proxy.verify_protector_password(as_opts(&opts)).await.is_err());

        Ok(())
    }
}
