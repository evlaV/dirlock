/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

mod cloner;
use cloner::DirectoryCloner;

use anyhow::{anyhow, bail, Result};
use nix::fcntl;
use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::{
    DirStatus,
    Keystore,
    create_policy_data,
    fscrypt::{KeyStatus, PolicyKeyId},
    inject::{check_injected_error, Injected},
    protector::{Protector, ProtectorKey},
    unlock_dir_with_key,
    user_manager_active,
    util::{
        GlobalLockFile,
        LockFile,
        SafeFile,
        create_dir_if_needed,
        dir_is_empty,
        get_mountpoint,
        is_real_dir,
        remove_file_or_dir,
    },
};

/// A background process that converts an unencrypted directory into
/// an encrypted one.
pub struct ConvertJob {
    /// The source directory that we want to convert
    dirs: SrcDirData,
    /// Encrypted copy of srcdir, located inside {workdir}/encrypted
    dstdir: PathBuf,
    /// The cloner that actually copies the data
    cloner: DirectoryCloner,
    /// The encryption key used to encrypt the data
    keyid: PolicyKeyId,
    /// Work directory using during this conversion job.
    /// The format is /mntpoint/.dirlock/KEY_ID.
    /// workdir itself is unencrypted but it contains
    /// an encrypted directory inside, {workdir}/encrypted
    workdir: PathBuf,
    /// Owner UID if `dirs.src` is a home directory
    home_owner: Option<u32>,
    /// Lock file held for the duration of the job
    _lockfile: LockFile,
}

/// The conversion status of a given directory
pub enum ConversionStatus {
    /// No conversion for this directory
    None,
    /// A live job is copying data
    Ongoing(PolicyKeyId),
    /// A live job has copied the data but cannot commit yet because
    /// the owner of the home directory is still logged in
    Deferred(PolicyKeyId),
    /// No live job, and the source is still unencrypted
    Interrupted(PolicyKeyId),
}

/// The outcome of a [`ConvertJob::commit`] call.
pub enum CommitOutcome {
    /// Conversion successful. Contains the encryption policy and the
    /// old unencrypted data to trash.
    Committed(PolicyKeyId, TrashedData),
    /// Conversion deferred: the user is still active.
    /// The caller should call `commit()` again once the user
    /// is logged out.
    Deferred(ConvertJob),
    /// Conversion restarted: the user was active during the
    /// operation. The caller should wait for the new conversion
    /// pass to finish and then call `commit()` again.
    Restarted(ConvertJob),
}

/// Returns the [`ConversionStatus`] of a given source directory
pub fn conversion_status(dir: &Path) -> Result<ConversionStatus> {
    ConvertJob::status(dir)
}

/// Returns an error if `dir` is the root directory of a filesystem.
///
/// In general our conversion mechanism does not support that because
/// it needs a base /mntpoint/.dirlock directory that should be
/// outside of the directory that we want to convert. On top of that,
/// ext4 does not support encrypting the root directory of a
/// filesystem and even if it did the renameat2() call would fail
/// anyway.
pub fn ensure_not_filesystem_root(dir: &Path) -> Result<()> {
    let dir = dir.canonicalize()?;
    if get_mountpoint(&dir)? == dir {
        bail!("Cannot encrypt the root directory of a filesystem");
    }
    Ok(())
}

/// Convert an unencrypted directory into an encrypted one
pub fn convert_dir(dir: &Path, protector: &Protector, protector_key: ProtectorKey,
                   ks: &Keystore) -> Result<PolicyKeyId> {
    let mut job = ConvertJob::start(dir, protector, protector_key, ks)?;
    let mut stdout = std::io::stdout();
    loop {
        let mut total = 0;
        // Display a progress indicator every half a second
        while ! job.is_finished() {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let current = job.progress() / 5;
            if current > total {
                print!(".{}%", current * 5);
                total = current;
            } else {
                print!(".");
            }
            _ = stdout.flush();
        }
        println!();
        match job.commit()? {
            CommitOutcome::Committed(id, trash) => {
                // The conversion succeeded, let's remove the old (unencrypted) data
                if let Err(e) = trash.purge() {
                    eprintln!("Warning: failed to remove the old data: {e}");
                }
                return Ok(id);
            }
            CommitOutcome::Restarted(j) => {
                // The user logged in during the conversion, so the job had
                // to be restarted to ensure that all new changes are sync'ed.
                job = j;
            }
            CommitOutcome::Deferred(j) => {
                // The user is still logged in, we have to wait.
                job = j;
                println!("Conversion deferred: waiting for user to log out...");
                job.wait_until_idle()?;
            }
        }
    }
}

struct SrcDirData {
    /// The source directory that we want to convert, canonicalized
    src: PathBuf,
    /// src, but relative to the filesystem's mountpoint
    /// (empty if src is the mountpoint itself).
    src_rel: PathBuf,
    /// Dirlock base dir for this filesystem: /mntpoint/.dirlock
    base: PathBuf,
}

impl ConvertJob {
    /// Base work directory used by dirlock to convert directories with data.
    /// It's meant to be located on the root of the filesystem that
    /// contains the data.
    const BASEDIR  : &str = ".dirlock";
    const LOCKFILE : &str = "lock";
    const ENCRYPTED : &str = "encrypted";
    const DSTDIR : &str = "data";
    const DIRTY : &str = "dirty";
    const DEFERRED : &str = "deferred";
    const TRASHDIR : &str = ".trash";

    /// This canonicalizes the source dir and returns [`SrcDirData`]
    fn get_src_dir_data(dir: &Path) -> Result<SrcDirData> {
        // Resolve symlinks before checking the type of the directory.
        let src = dir.canonicalize()
            .map_err(|e| anyhow!("Cannot access {}: {e}", dir.display()))?;
        if ! is_real_dir(&src) {
            bail!("{} is not a directory", dir.display());
        }

        let mut base = get_mountpoint(&src)?;
        // src, but relative to the mount point
        // (empty if src is the mount point itself).
        let src_rel = src.strip_prefix(&base)?.to_owned();
        base.push(Self::BASEDIR);
        Ok(SrcDirData { src, src_rel, base })
    }

    /// Return the owner UID of `dir` iff `dir` is that owner's passwd
    /// home directory. `dir` must already be canonicalized.
    ///
    /// Returns `Ok(Some(uid))` on success, `Ok(None)` if the home does
    /// not match or no passwd entry is found.
    fn home_owner_uid(dir: &Path) -> Result<Option<u32>> {
        use nix::unistd::{Uid, User};
        let uid = fs::symlink_metadata(dir)?.uid();
        let Some(user) = User::from_uid(Uid::from_raw(uid))? else {
            return Ok(None);
        };
        Ok((user.dir.canonicalize()? == dir).then_some(uid))
    }

    /// Returns the [`ConversionStatus`] of a given source directory
    fn status(dir: &Path) -> Result<ConversionStatus> {
        let dirs = Self::get_src_dir_data(dir)?;
        // Fast path: in most cases /mntpoint/.dirlock does not exist
        if ! dirs.base.exists() {
            return Ok(ConversionStatus::None);
        }
        let db = ConvertDb::load(&dirs.base)?;
        let Some(id) = db.get(&dirs.src_rel).cloned() else {
            return Ok(ConversionStatus::None);
        };

        // If the srcdir is already encrypted then a previous commit()
        // completed the exchange but crashed before removing the db
        // entry. The conversion is finished, so there is nothing
        // pending here; cleanup() reclaims the leftovers.
        if crate::get_policy(&dirs.src)?.is_some() {
            return Ok(ConversionStatus::None);
        }

        // If the workdir lock can't be acquired there's a live job.
        // A live job is deferred if it's waiting for the owner to log out.
        let workdir = dirs.base.join(id.to_string());
        if let Ok(None) = LockFile::try_new(&workdir.join(Self::LOCKFILE)) {
            if Self::flag_exists(&workdir, Self::DEFERRED) {
                return Ok(ConversionStatus::Deferred(id));
            }
            return Ok(ConversionStatus::Ongoing(id));
        }

        // No live job: the conversion was interrupted and can be
        // resumed later.
        Ok(ConversionStatus::Interrupted(id))
    }

    /// Start a new asynchronous job to convert `dir` to an encrypted folder
    pub fn start(dir: &Path, protector: &Protector, protector_key: ProtectorKey,
                 ks: &Keystore) -> Result<Self> {
        let dirs = Self::get_src_dir_data(dir)?;

        // Conversion jobs require valid UTF-8 paths
        if dirs.src.to_str().is_none() {
            bail!("{}: the path is not valid UTF-8", dirs.src.display());
        }

        // We cannot convert the root directory of a filesystem
        ensure_not_filesystem_root(&dirs.src)?;

        // Open the convertdb file. This acquires the global lock
        let mut db = ConvertDb::load(&dirs.base)?;

        // Check the status of the source dir. It should not be encrypted
        crate::ensure_unencrypted(&dirs.src, ks)?;

        // Check if we tried to convert this directory already
        let (policy_key, keyid) = match db.get(&dirs.src_rel) {
            // If that's the case, load the policy key
            Some(id) => {
                let policy = ks.load_policy_data(id)?;
                let key = policy.keys.get(&protector.id)
                    .and_then(|key| key.unwrap_key(&protector_key))
                    .ok_or_else(|| anyhow!("Cannot unlock policy {id} with protector {}", &protector.id))?;
                (key, id.clone())
            },
            // If not, generate a new policy key and save it to disk
            None => {
                let (policy, key) = create_policy_data(protector, &protector_key, ks)?;
                let id = policy.id;
                db.insert(&dirs.src_rel, id.clone());
                db.commit()?;
                (key, id)
            }
        };

        // Create the work directory: /<mntpoint>/.dirlock/<policy-id>
        let workdir = dirs.base.join(keyid.to_string());
        create_dir_if_needed(&workdir)?;

        // Lock the work directory for the duration of the conversion
        // task and release the global lock. With this we also check
        // if the directory is being converted at this moment.
        let Some(_lockfile) = LockFile::try_new(&workdir.join(Self::LOCKFILE))? else {
            bail!("Directory {} is already being converted", dirs.src.display());
        };

        // If the source dir is a home directory, get the owner's uid.
        let home_owner = Self::home_owner_uid(&dirs.src)?;

        // If we're converting a home directory and the owner is not
        // completely logged out, mark the conversion dirty.
        // If the owner logs in later during the conversion, the dirty
        // flag is set by the PAM module.
        if let Some(uid) = home_owner {
            let active = user_manager_active(uid).unwrap_or(true);
            if active {
                Self::create_flag(&workdir, Self::DIRTY)?;
            }
        }

        // Check if the dirty flag is set (by the code above, or by a
        // previous run).
        let verify_content = Self::flag_exists(&workdir, Self::DIRTY);

        // A job that crashed while deferred leaves its flag behind.
        // This one is about to copy, so clear it.
        Self::remove_flag(&workdir, Self::DEFERRED)?;

        // Release the global lock
        drop(db);

        // This is an encrypted directory inside the work dir
        // /<mntpoint>/.dirlock/<policy-id>/encrypted
        let workdir_e = workdir.join(Self::ENCRYPTED);
        create_dir_if_needed(&workdir_e)?;

        // Check the status of the encrypted dir
        match crate::open_dir(&workdir_e, ks)? {
            // If it's unencrypted then it must be empty, else something is wrong
            DirStatus::Unencrypted => {
                if dir_is_empty(&workdir_e)? {
                    crate::encrypt_dir_with_key(&workdir_e, &policy_key)?;
                } else {
                    bail!("Unexpected directory with data at {}", workdir_e.display());
                }
            },
            // If it's encrypted then it has to be with the same key
            DirStatus::Encrypted(d) => {
                if d.policy.keyid != keyid  {
                    bail!("Expected policy {keyid} when converting {}, found {}",
                          dirs.src.display(), d.policy.keyid);
                }
                // Unlock the directory if needed
                if d.key_status != KeyStatus::Present {
                    unlock_dir_with_key(&d.path, &policy_key)?;
                }
            },
            status => bail!(status.error_msg()),
        }

        // If a previous commit() crashed immediately before
        // RENAME_EXCHANGE, workdir/data will exist as an orphan.
        // Move it back so we can resync it.
        let dstdir = workdir_e.join(Self::DSTDIR);
        let orphan = workdir.join(Self::DSTDIR);
        if orphan.exists() {
            if dstdir.exists() {
                fs::remove_dir_all(&dstdir)?;
            }
            safe_rename(&orphan, &dstdir)?;
        }

        // Copy the source directory inside the encrypted directory.
        // This will encrypt the data in the process.
        // If the conversion is dirty (e.g. resumed after the user
        // was active), verify the content.
        let cloner = DirectoryCloner::start(&dirs.src, &dstdir, verify_content)?;

        Ok(Self { dirs, cloner, keyid, _lockfile, dstdir, workdir, home_owner })
    }

    /// Return the canonicalized path of the directory being converted.
    ///
    /// Guaranteed to be valid UTF-8 (see ConvertJob::start).
    pub fn src_dir(&self) -> &Path {
        &self.dirs.src
    }

    /// Return the current progress percentage
    pub fn progress(&self) -> i32 {
        self.cloner.progress()
    }

    /// Check is the job is finished
    pub fn is_finished(&self) -> bool {
        self.cloner.is_finished()
    }

    /// Cancel the operation, leaving the conversion interrupted so it
    /// can be resumed later. Use [`remove_conversion()`] to discard it
    /// altogether.
    pub fn cancel(&self) -> Result<()> {
        self.cloner.cancel()
    }

    /// Wail until the operation is done
    pub fn wait(&self) -> Result<()> {
        self.cloner.wait()
    }

    /// Returns `true` if we're converting a home directory and the
    /// owner is active.
    /// Returns `false` for non-home directories or when the owner
    /// is fully logged out.
    pub fn is_owner_active(&self) -> Result<bool> {
        match self.home_owner {
            Some(uid) => user_manager_active(uid),
            None => Ok(false),
        }
    }

    /// If the source is a home directory, block until the owner is
    /// completely logged out. Returns immediately if the source is
    /// not a home directory.
    pub fn wait_until_idle(&self) -> Result<()> {
        while self.is_owner_active()? {
            // TODO: don't use a polling loop
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
        Ok(())
    }

    // Plain file operations on the DIRTY and DEFERRED flags.
    // All ConvertJob methods (start(), commit(), ...) must hold the
    // global lock while they use these, so that a check and the
    // action that depends on it cannot be separated.

    /// Create a flag file in workdir
    fn create_flag(workdir: &Path, flag: &str) -> std::io::Result<()> {
        fs::File::create(workdir.join(flag))?;
        Ok(())
    }

    /// Check if a flag file exists
    fn flag_exists(workdir: &Path, flag: &str) -> bool {
        workdir.join(flag).exists()
    }

    /// Remove a flag file
    fn remove_flag(workdir: &Path, flag: &str) -> std::io::Result<()> {
        match fs::remove_file(workdir.join(flag)) {
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }

    /// Try to remove the trash and base directories. This is a
    /// best-effort removal done during cleanup, it's safe to call
    /// multiple times and failures are ignored.
    /// It must be called under the global lock, because other jobs
    /// could be trying to create it at the same time.
    /// The `&GlobalLockFile` argument proves that the caller is holding it.
    fn try_remove_base_dirs(base: &Path, _lock: &GlobalLockFile) {
        let _ = fs::remove_dir(base.join(Self::TRASHDIR));
        let _ = fs::remove_dir(base);
    }

    /// Mark the conversion of `dir` as dirty.
    ///
    /// If there is a conversion job (in whatever state) for `dir`, create
    /// a file under workdir to indicate that it's dirty (i.e the user may
    /// have modified the source directory).
    /// The process is protected by the global [`ConvertDb`] lock.
    ///
    /// Returns `true` if the flag was created, `false` otherwise.
    pub fn mark_dirty(dir: &Path) -> Result<bool> {
        let dirs = Self::get_src_dir_data(dir)?;
        if ! dirs.base.exists() {
            return Ok(false);
        }
        let db = ConvertDb::load(&dirs.base)?;
        let Some(id) = db.get(&dirs.src_rel) else {
            return Ok(false);
        };
        // If the source dir is already encrypted then the db entry
        // is a leftover from a commit() that crashed. cleanup()
        // will take care of the stale entry, we can ignore it here.
        if matches!(crate::get_policy(&dirs.src), Ok(Some(_))) {
            return Ok(false);
        }
        let workdir = dirs.base.join(id.to_string());
        match Self::create_flag(&workdir, Self::DIRTY) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Wait for the conversion job to finish and replace the original
    /// directory with the encrypted one.
    ///
    /// Returns a different [`CommitOutcome`] depending on the result.
    pub fn commit(mut self) -> Result<CommitOutcome> {
        // Wait until the data is copied
        if let Err(e) = self.cloner.wait() {
            bail!("Error encrypting data: {e}");
        }

        // Acquire the global lock during the dirty-flag check and the
        // RENAME_EXCHANGE, so that a concurrent mark_dirty() cannot
        // race between our check and the exchange.
        let mut db = ConvertDb::load(&self.dirs.base)?;

        // If the dirty flag is set, we cannot complete the conversion.
        if Self::flag_exists(&self.workdir, Self::DIRTY) {
            // The previous conversion ran with the user active, or a
            // stale flag survived a crash.
            let user_active = match self.home_owner {
                // Err is treated as active: we'd rather defer than
                // exchange under a user whose state we can't read.
                Some(uid) => !matches!(user_manager_active(uid), Ok(false)),
                // Not a home dir but the flag is set. This should not happen,
                // so best clear the flag and re-sync.
                None => false,
            };
            if user_active {
                // Defer, the caller must wait until the user is logged out
                Self::create_flag(&self.workdir, Self::DEFERRED)?;
                return Ok(CommitOutcome::Deferred(self));
            }
            // User inactive: clear the flags and restart a cloner with
            // verify_content=true. The previous (partial) clone is
            // unreliable because the user was active while it happened.
            // The job goes back from deferred to ongoing.
            Self::remove_flag(&self.workdir, Self::DIRTY)?;
            Self::remove_flag(&self.workdir, Self::DEFERRED)?;
            drop(db); // We can release the global lock already
            self.cloner = DirectoryCloner::start(&self.dirs.src, &self.dstdir, true)?;
            return Ok(CommitOutcome::Restarted(self));
        }

        // The dirty flag is unset: let's finish the conversion.
        // Move the encrypted copy from workdir/encrypted/ to workdir/
        let dstdir_2 = self.workdir.join(Self::DSTDIR);
        safe_rename(&self.dstdir, &dstdir_2)?;

        check_injected_error(Injected::ConvertCommitBeforeExchange)?;
        // Exchange atomically the source directory and its encrypted copy
        safe_exchange(&self.dirs.src, &dstdir_2)?;
        check_injected_error(Injected::ConvertCommitAfterExchange)?;

        // The conversion is done. workdir contains the original data
        // that can be removed. Move it into .trash first with a
        // simple rename so we can call db.remove() and quickly
        // release the global lock.
        let trashdir = self.dirs.base.join(Self::TRASHDIR);
        create_dir_if_needed(&trashdir)?;
        let trash_target = trashdir.join(self.keyid.to_string());
        safe_rename(&self.workdir, &trash_target)?;

        check_injected_error(Injected::ConvertCommitAfterTrashRename)?;

        // Remove the convertdb entry.
        // If mark_dirty() arrives later there's no entry so it's a no-op.
        db.remove(&self.dirs.src_rel);
        if let Err(e) = db.commit() {
            eprintln!("Warning: failed to update convertdb: {e}");
        }

        // The original data is trashed, but removing it can take minutes.
        // In order to keep this commit() operation short return now
        // and leave it up to the caller to call trash.purge().
        let trash = TrashedData::new(Some(trash_target), self.dirs.base);
        Ok(CommitOutcome::Committed(self.keyid, trash))
    }
}

/// Database of started conversion jobs.
/// Maps source directories to the policy used for encryption.
/// Stored under /mntpoint/.dirlock/convertdb, and protected
/// by the global dirlock lock file.
/// The work directory (/mntpoint/.dirlock) is automatically
/// created and removed as needed.
struct ConvertDb {
    filename: PathBuf,
    db: HashMap<PathBuf, PolicyKeyId>,
    _lock: GlobalLockFile,
    dirty: bool,
}

impl ConvertDb {
    /// Load the database from disk (or return an empty one if it
    /// doesn't exist)
    fn load(basedir: &Path) -> std::io::Result<Self> {
        let filename = basedir.join("convertdb");
        let lock = GlobalLockFile::new()?;
        let db = if filename.exists() {
            serde_json::from_reader(fs::File::open(&filename)?)
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?
        } else {
            HashMap::new()
        };
        Ok(ConvertDb { filename, db, _lock: lock, dirty: false })
    }

    /// Get the [`PolicyKeyId`] being used to encrypt `dir`, if any.
    fn get(&self, dir: &Path) -> Option<&PolicyKeyId> {
        self.db.get(dir)
    }

    /// Add a [`PolicyKeyId`] for encrypting `dir`
    fn insert(&mut self, dir: &Path, keyid: PolicyKeyId) {
        self.dirty = true;
        self.db.insert(PathBuf::from(dir), keyid);
    }

    fn keys(&self) -> impl Iterator<Item = &PathBuf> {
        self.db.keys()
    }

    /// Remove the [`PolicyKeyId`] for `dir` from the database
    fn remove(&mut self, dir: &Path) -> bool {
        self.dirty = true;
        self.db.remove(dir).is_some()
    }

    /// Commit the changes to disk
    fn commit(&mut self) -> std::io::Result<()> {
        if ! self.dirty {
            return Ok(());
        }
        let basedir = self.filename.parent().unwrap();
        let result = if self.db.is_empty() {
            // Remove the db file. The base dir must be cleaned by the caller
            if self.filename.exists() {
                fs::remove_file(&self.filename)?;
            }
            Ok(())
        } else {
            // Create /mnt/.dirlock if it doesn't exist
            if ! is_real_dir(basedir) {
                fs::create_dir(basedir)?;
                fs::set_permissions(basedir, {
                    let mut perms = fs::metadata(basedir)?.permissions();
                    perms.set_mode(0o700);
                    perms
                })?;
            }
            // Write the updated database to disk
            let mut file = SafeFile::create(&self.filename, None, None)?;
            serde_json::to_writer_pretty(&mut file, &self.db)?;
            file.write_all(b"\n")?;
            file.commit()
        };
        if result.is_ok() {
            self.dirty = false;
        }
        result
    }
}

/// Remove the conversion of `dir`. The source directory is never
/// touched and remains intact.
///
/// Only an interrupted conversion can be removed, a running one has
/// to be cancelled first.
///
/// Like [`ConvertJob::commit()`] this is a quick operation and it
/// returns as soon as the encrypted copy has been trashed. The caller
/// must purge the returned [`TrashedData`] when it can afford to block.
pub fn remove_conversion(dir: &Path, ks: &Keystore) -> Result<TrashedData> {
    let dirs = ConvertJob::get_src_dir_data(dir)?;
    if ! dirs.base.exists() {
        bail!("There is no conversion for {}", dirs.src.display());
    }

    // Take the global lock, so no job can start while we remove this
    // conversion.
    let mut db = ConvertDb::load(&dirs.base)?;
    let Some(keyid) = db.get(&dirs.src_rel).cloned() else {
        bail!("There is no conversion for {}", dirs.src.display());
    };
    let workdir = dirs.base.join(keyid.to_string());
    let lockfile = match LockFile::try_new(&workdir.join(ConvertJob::LOCKFILE)) {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => bail!("The conversion of {} is running, cancel it first",
                          dirs.src.display()),
        // No work directory, it was probably removed by hand.
        // We still need to update the db and remove the policy.
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    // Do this under the lock in case another process is or was trying
    // to complete this conversion.
    if crate::get_policy(&dirs.src)?.is_some() {
        bail!("{} is already encrypted", dirs.src.display());
    }

    // Same teardown order as commit(): trash the work dir, update
    // convertdb and release the locks.
    let trash_target = match lockfile {
        Some(_) => {
            let trashdir = dirs.base.join(ConvertJob::TRASHDIR);
            create_dir_if_needed(&trashdir)?;
            let target = trashdir.join(keyid.to_string());
            safe_rename(&workdir, &target)?;
            Some(target)
        }
        None => None,
    };
    db.remove(&dirs.src_rel);
    db.commit()?;
    drop(db);
    drop(lockfile);

    // Now we can get rid of the policy. It was generated internally
    // in ConvertJob::start() so no one else should be using it and
    // it's safe to remove. A missing policy file is not an error
    // here, the conversion is being discarded either way.
    _ = crate::remove_key(&dirs.src, &keyid, crate::RemoveKeyUsers::CurrentUser);
    match ks.remove_policy(&keyid) {
        Err(e) if e.kind() == ErrorKind::NotFound => (),
        r => r?,
    }

    let trash = TrashedData::new(trash_target, dirs.base);
    Ok(trash)
}

/// Remove stale conversion entries for the filesystem containing `dir`.
/// Returns the number of entries removed.
pub fn cleanup(dir: &Path) -> Result<usize> {
    let mntpoint = get_mountpoint(dir)?;
    let base = mntpoint.join(ConvertJob::BASEDIR);
    if ! base.exists() {
        return Ok(0);
    }
    let trashdir = base.join(ConvertJob::TRASHDIR);

    // 1. Purge any leftover trashed workdirs from crashed commits.
    //    This does not need the global lock and ensures that the
    //    dir is empty before we trash new entries in step 2.
    if let Ok(trash_entries) = fs::read_dir(&trashdir) {
        for entry in trash_entries.flatten() {
            let _ = remove_file_or_dir(&entry.path());
        }
    }

    // 2. Clean stale convertdb entries, holding the global lock
    let mut count = 0;
    let mut db = ConvertDb::load(&base)?;
    for (entry, keyid) in db.db.clone() {
        let src = mntpoint.join(&entry);
        if is_real_dir(&src) && crate::get_policy(&src)?.is_none() {
            // A valid, existing conversion requires an actual
            // unencrypted source dir, so if there is one, keep it.
            continue;
        }
        // Now we know that this entry does not have an associated
        // conversion: status() would return ConversionStatus::None
        create_dir_if_needed(&trashdir)?;
        let keyid_str = keyid.to_string();
        let workdir = base.join(&keyid_str);
        let trashed_dir = trashdir.join(&keyid_str);
        // Trash the work directory
        match safe_rename(&workdir, &trashed_dir) {
            Err(e) if e.kind() != ErrorKind::NotFound => {
                eprintln!("Warning: failed to trash workdir: {e}");
            }
            _ => {
                db.remove(&entry);
                db.commit()?;
                count += 1;
            }
        }
    }
    drop(db); // Close the db and release the global lock

    // 3. Purge the newly trashed workdirs. This does not need the global lock.
    if let Ok(trash_entries) = fs::read_dir(&trashdir) {
        for entry in trash_entries.flatten() {
            let _ = remove_file_or_dir(&entry.path());
        }
    }

    // 4. Remove .trash and the base dir if they are now empty
    if let Ok(lock) = GlobalLockFile::new() {
        ConvertJob::try_remove_base_dirs(&base, &lock);
    }

    Ok(count)
}

/// Remove stale conversion entries across all mounted filesystems.
/// Returns the total number of entries removed.
pub fn cleanup_all() -> Result<usize> {
    let mut total = 0;
    for m in crate::util::get_unique_mounts()? {
        total += cleanup(m.fs_mounted_on.as_ref())?;
    }
    Ok(total)
}

// Helper function for safe_rename() and safe_exchange()
fn do_safe_rename(src: &Path, dst: &Path, flags: fcntl::RenameFlags) -> std::io::Result<()> {
    let (Some(src_dir), Some(src_file), Some(dst_dir), Some(dst_file)) =
        (src.parent(), src.file_name(), dst.parent(), dst.file_name()) else {
        let e = format!("Unable to rename {} to {}", src.display(), dst.display());
        return Err(std::io::Error::new(ErrorKind::InvalidInput, e));
    };
    let src_fd = fs::File::open(src_dir)?;
    let dst_fd = fs::File::open(dst_dir)?;
    fcntl::renameat2(Some(src_fd.as_raw_fd()), src_file,
                     Some(dst_fd.as_raw_fd()), dst_file, flags)?;
    src_fd.sync_all()?;
    if src_dir != dst_dir {
        dst_fd.sync_all()?;
    }
    Ok(())
}

/// Rename `src` to `dst`, followed by fsync on both directories.
/// Fails if `dst` already exists.
fn safe_rename(src: &Path, dst: &Path) -> std::io::Result<()> {
    do_safe_rename(src, dst, fcntl::RenameFlags::RENAME_NOREPLACE)
}

/// Exchange `src` and `dst`, followed by fsync on both directories.
fn safe_exchange(src: &Path, dst: &Path) -> std::io::Result<()> {
    do_safe_rename(src, dst, fcntl::RenameFlags::RENAME_EXCHANGE)
}

/// Leftover data from a conversion that can be safely removed.
pub struct TrashedData {
    /// Directory that contains the data, /mnt/.dirlock/.trash/dirname
    trash: Cell<Option<PathBuf>>,
    /// Base directory, /mnt/.dirlock
    base: PathBuf,
}

impl TrashedData {
    fn new(trash: Option<PathBuf>, base: PathBuf) -> Self {
        Self { trash: Cell::new(trash), base }
    }

    /// Purge the trashed data, and the base directory if possible
    pub fn purge(&self) -> std::io::Result<()> {
        if let Some(trash) = self.trash.take() {
            // Errors are reported but otherwise ignored, i.e. you
            // cannot call purge() twice to try again.
            remove_file_or_dir(&trash)?;
        }
        if let Ok(lock) = GlobalLockFile::new() {
            ConvertJob::try_remove_base_dirs(&self.base, &lock);
        }
        Ok(())
    }
}

/// A conversion that has not finished yet.
pub struct PendingConversion {
    /// The directory being converted
    pub dir: PathBuf,
    /// Its status, never [`ConversionStatus::None`]
    pub status: ConversionStatus,
}

/// Return the pending conversions of the filesystem mounted on `mntpoint`.
///
/// Entries of conversions that are already finished are not listed,
/// it is up to [`cleanup()`] to remove them.
fn list_conversions(mntpoint: &Path) -> Result<Vec<PendingConversion>> {
    // The convertdb keys are relative to the canonicalized mount point
    let mntpoint = mntpoint.canonicalize()?;
    let base = mntpoint.join(ConvertJob::BASEDIR);
    if ! base.exists() {
        return Ok(vec![]);
    }

    let entries : Vec<PathBuf> = {
        let db = ConvertDb::load(&base)?;
        db.keys().cloned().collect()
    };

    let mut result = vec![];
    for entry in entries {
        let dir = mntpoint.join(&entry);
        // A missing source directory is a stale entry, cleanup() removes those
        if ! is_real_dir(&dir) {
            continue;
        }
        match ConvertJob::status(&dir)? {
            ConversionStatus::None => (),
            status => result.push(PendingConversion { dir, status }),
        }
    }
    Ok(result)
}

/// Return the pending conversions of all mounted filesystems.
pub fn list_all_conversions() -> Result<Vec<PendingConversion>> {
    let mut result = vec![];
    for m in crate::util::get_unique_mounts()? {
        result.extend(list_conversions(m.fs_mounted_on.as_ref())?);
    }
    Ok(result)
}

#[cfg(test)]
mod test;
