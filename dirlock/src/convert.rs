/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, Result};
use nix::fcntl;
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
    cloner::DirectoryCloner,
    fscrypt::{KeyStatus, PolicyKeyId},
    inject::{check_injected_error, InjectedError},
    protector::{Protector, ProtectorKey},
    unlock_dir_with_key,
    user_manager_active,
    util::{
        LockFile,
        SafeFile,
        create_dir_if_needed,
        dir_is_empty,
        get_mountpoint,
        is_real_dir,
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
    None,
    Ongoing(PolicyKeyId),
    Interrupted(PolicyKeyId),
}

/// The outcome of a [`ConvertJob::commit`] call.
pub enum CommitOutcome {
    /// Conversion successful. Contains the encryption policy.
    Committed(PolicyKeyId),
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
            CommitOutcome::Committed(id) => return Ok(id),
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

    /// This canonicalizes the source dir and returns [`SrcDirData`]
    fn get_src_dir_data(dir: &Path) -> Result<SrcDirData> {
        if ! is_real_dir(dir) {
            bail!("{} is not a directory", dir.display());
        }

        let src = dir.canonicalize()?;
        let mut base = get_mountpoint(&src)?;
        if base == src {
            bail!("Cannot encrypt the root directory of a filesystem");
        };
        // src, but relative to the mount point
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
        let mut db = ConvertDb::load(&dirs.base)?;
        let status = match db.get(&dirs.src_rel) {
            Some(id) => {
                let mut lockfile = dirs.base.join(id.to_string());
                lockfile.push(Self::LOCKFILE);
                match LockFile::try_new(&lockfile) {
                    Ok(None) => ConversionStatus::Ongoing(id.clone()),
                    _ => {
                        // No active job. If the directory is already encrypted,
                        // a previous commit() completed the exchange but crashed
                        // before removing the db entry. Clean up and report None.
                        if crate::get_policy(&dirs.src)?.is_some() {
                            let workdir = dirs.base.join(id.to_string());
                            let _ = fs::remove_dir_all(workdir);
                            db.remove(&dirs.src_rel);
                            let _ = db.commit();
                            ConversionStatus::None
                        } else {
                            ConversionStatus::Interrupted(id.clone())
                        }
                    }
                }
            },
            None => ConversionStatus::None,
        };
        Ok(status)
    }

    /// Start a new asynchronous job to convert `dir` to an encrypted folder
    pub fn start(dir: &Path, protector: &Protector, protector_key: ProtectorKey,
                 ks: &Keystore) -> Result<Self> {
        // Open the convertdb file. This acquires the global lock
        let dirs = Self::get_src_dir_data(dir)?;
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
        // flag is set by the PAM module (TODO).
        if let Some(uid) = home_owner {
            let active = user_manager_active(uid).unwrap_or(true);
            if active {
                Self::create_dirty_flag(&workdir)?;
            }
        }

        // Check if the dirty flag is set (by the code above, or by a
        // previous run).
        let verify_content = Self::dirty_flag_exists(&workdir);

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
            fs::rename(&orphan, &dstdir)?;
        }

        // Copy the source directory inside the encrypted directory.
        // This will encrypt the data in the process.
        // If the conversion is dirty (e.g. resumed after the user
        // was active), verify the content.
        let cloner = DirectoryCloner::start(&dirs.src, &dstdir, verify_content)?;

        Ok(Self { dirs, cloner, keyid, _lockfile, dstdir, workdir, home_owner })
    }

    /// Return the current progress percentage
    pub fn progress(&self) -> i32 {
        self.cloner.progress()
    }

    /// Check is the job is finished
    pub fn is_finished(&self) -> bool {
        self.cloner.is_finished()
    }

    /// Cancel the operation
    // TODO: this leaves the conversion as interrupted,
    // it would be nice to have a way to abort it completely.
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

    /// Create a dirty flag. This must happen under the global lock
    fn create_dirty_flag(workdir: &Path) -> std::io::Result<()> {
        fs::File::create(workdir.join(Self::DIRTY))?;
        Ok(())
    }

    /// Check if a dirty flag exists. This must happen under the global lock
    fn dirty_flag_exists(workdir: &Path) -> bool {
        workdir.join(Self::DIRTY).exists()
    }

    /// Remove a dirty flag. This must happen under the global lock
    fn remove_dirty_flag(workdir: &Path) -> std::io::Result<()> {
        match fs::remove_file(workdir.join(Self::DIRTY)) {
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            r => r,
        }
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
        let workdir = dirs.base.join(id.to_string());
        match Self::create_dirty_flag(&workdir) {
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

        // Pre-flush dirty pages outside the global lock
        // so later we only have to do it for the rename part
        let syncfd = fs::File::open(&self.dirs.base)?;
        _ = nix::unistd::syncfs(syncfd.as_raw_fd());

        // Acquire the global lock during the dirty-flag check and the
        // RENAME_EXCHANGE, so that a concurrent mark_dirty() cannot
        // race between our check and the exchange.
        let mut db = ConvertDb::load(&self.dirs.base)?;

        // If the dirty flag is set, we cannot complete the conversion.
        if Self::dirty_flag_exists(&self.workdir) {
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
                return Ok(CommitOutcome::Deferred(self));
            }
            // User inactive: clear the flag and restart a cloner with
            // verify_content=true. The previous (partial) clone is
            // unreliable because the user was active while it happened.
            Self::remove_dirty_flag(&self.workdir)?;
            drop(db); // We can release the global lock already
            self.cloner = DirectoryCloner::start(&self.dirs.src, &self.dstdir, true)?;
            return Ok(CommitOutcome::Restarted(self));
        }

        // The dirty flag is unset: let's finish the conversion.
        // Move the encrypted copy from workdir/encrypted/ to workdir/
        let dstdir_2 = self.workdir.join(Self::DSTDIR);
        fs::rename(&self.dstdir, &dstdir_2)?;

        check_injected_error(InjectedError::ConvertCommitBeforeExchange)?;

        // Exchange atomically the source directory and its encrypted copy
        fcntl::renameat2(None, &self.dirs.src, None, &dstdir_2,
                         fcntl::RenameFlags::RENAME_EXCHANGE)?;
        _ = nix::unistd::syncfs(syncfd.as_raw_fd());

        check_injected_error(InjectedError::ConvertCommitAfterExchange)?;

        // Remove the convertdb entry and release the global lock.
        // If mark_dirty() arrives later there's no entry so it's a no-op.
        db.remove(&self.dirs.src_rel);
        if let Err(e) = db.commit() {
            eprintln!("Warning: failed to update convertdb: {e}");
        }
        drop(db);

        // Now we can remove the workdir outside the lock.
        // TODO: if we crash here, the workdir is leaked
        if let Err(e) = fs::remove_dir_all(&self.workdir) {
            eprintln!("Warning: failed to remove workdir: {e}");
        }

        Ok(CommitOutcome::Committed(self.keyid))
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
    _lock: LockFile,
    dirty: bool,
}

impl ConvertDb {
    /// Load the database from disk (or return an empty one if it
    /// doesn't exist)
    fn load(basedir: &Path) -> std::io::Result<Self> {
        let filename = basedir.join("convertdb");
        let _lock = LockFile::global()?;
        let db = if filename.exists() {
            serde_json::from_reader(fs::File::open(&filename)?)
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?
        } else {
            HashMap::new()
        };
        Ok(ConvertDb { filename, db, _lock, dirty: false })
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
        if self.db.is_empty() {
            // Remove the db file and the parent directory if they're empty
            if self.filename.exists() {
                fs::remove_file(&self.filename)?;
            }
            if dir_is_empty(basedir).unwrap_or(false) {
                _ = fs::remove_dir(basedir);
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
        }
    }
}

/// Remove stale conversion entries for the filesystem containing `dir`.
/// Returns the number of entries removed.
pub fn cleanup(dir: &Path) -> Result<usize> {
    let mntpoint = get_mountpoint(&dir.canonicalize()?)?;
    let base = mntpoint.join(ConvertJob::BASEDIR);
    if ! base.exists() {
        return Ok(0);
    }
    let entries = {
        let db = ConvertDb::load(&base)?;
        let entries : Vec<PathBuf> =
            db.keys().map(|src_rel| mntpoint.join(src_rel)).collect();
        // If convertdb is empty remove the base dir and return
        if entries.is_empty() {
            // We only want to remove *empty* directories
            _ = fs::remove_dir(base);
            return Ok(0);
        }
        entries
    };
    let mut count = 0;
    for src in entries {
        if matches!(conversion_status(&src)?, ConversionStatus::None) {
            count += 1;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{bail, Result};
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use tempdir::TempDir;
    use crate::{Keystore, CreateOpts, EncryptedDir, LockState, RemoveKeyUsers};
    use crate::inject::{clear_injected_error, inject_error};
    use crate::protector::{Protector, ProtectorKey, opts::ProtectorOptsBuilder};

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

    /// Helper: create a basic password protector
    fn make_test_protector(ks: &Keystore) -> Result<(Protector, ProtectorKey)> {
        let opts = ProtectorOptsBuilder::new()
            .with_name("test".into())
            .with_kdf_iter(std::num::NonZeroU32::new(1))
            .build()?;
        crate::create_protector(opts, b"pass", CreateOpts::CreateAndSave, ks)
    }

    #[test]
    fn test_convert() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create a directory and populate it with some files
        let dir = TempDir::new_in(&mntpoint, "dir-with-data")?;
        let path = dir.path();

        // One of them deep in the hierarchy
        fs::create_dir_all(path.join("a/b"))?;
        fs::write(path.join("a/b/deep.txt"), "deep")?;
        let md_before = fs::metadata(path.join("a/b/deep.txt"))?;

        // Another gets one hard link and one symbolic link
        fs::write(path.join("original.txt"), "linked")?;
        fs::hard_link(path.join("original.txt"), path.join("hardlink.txt"))?;
        std::os::unix::fs::symlink("original.txt", path.join("symlink.txt"))?;

        // Set xattrs
        xattr::set(path.join("original.txt"), "user.test", b"xattr-value")?;

        // Do the conversion job
        let (protector, protector_key) = make_test_protector(&ks)?;
        let job = ConvertJob::start(path, &protector, protector_key, &ks)?;
        let _policy = job.commit()?;

        // The directory show now be encrypted
        let encrypted_dir = EncryptedDir::open(path, &ks, LockState::Unlocked)?;

        // Check that the metadata is preserved
        let md_after = fs::metadata(path.join("a/b/deep.txt"))?;
        assert_eq!(md_before.modified()?, md_after.modified()?);
        assert_eq!(md_before.file_type(), md_after.file_type());
        assert_eq!(md_before.permissions(), md_after.permissions());

        // Check the contents of the files
        assert_eq!(fs::read_to_string(path.join("a/b/deep.txt"))?, "deep");
        assert_eq!(fs::read_to_string(path.join("original.txt"))?, "linked");
        assert_eq!(fs::read_to_string(path.join("hardlink.txt"))?, "linked");
        assert_eq!(fs::read_to_string(path.join("symlink.txt"))?, "linked");

        // Check that the hard linked files have the same inode
        let orig_ino = fs::metadata(path.join("original.txt"))?.ino();
        let link_ino = fs::metadata(path.join("hardlink.txt"))?.ino();
        assert_eq!(orig_ino, link_ino, "hard link relationship not preserved");

        // Check that the symlink points to the original file
        assert_eq!(fs::read_link(path.join("symlink.txt"))?, Path::new("original.txt"));

        // Check the value of the xattr
        assert_eq!(xattr::get(path.join("original.txt"), "user.test")?,
                   Some(b"xattr-value".to_vec()), "xattrs not preserved");

        encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

        Ok(())
    }

    #[test]
    fn test_conversion_status_lifecycle() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create a directory with data
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        let path = dir.path();
        std::fs::write(path.join("file.txt"), "hello")?;

        // Create a protector
        let (protector, protector_key) = make_test_protector(&ks)?;

        // Check the conversion status before, during and after the job
        assert!(matches!(conversion_status(path)?, ConversionStatus::None));
        let job = ConvertJob::start(path, &protector, protector_key, &ks)?;
        assert!(matches!(conversion_status(path)?, ConversionStatus::Ongoing(_)));
        job.commit()?;
        assert!(matches!(conversion_status(path)?, ConversionStatus::None));

        // The directory show now be encrypted
        let encrypted_dir = EncryptedDir::open(path, &ks, LockState::Unlocked)?;
        encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

        Ok(())
    }

    #[test]
    fn test_cancel_and_resume() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };
        crate::init()?;

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create a directory with data
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        let path = dir.path();
        std::fs::write(path.join("file.txt"), "hello")?;

        // Create a protector
        let (protector, protector_key) = make_test_protector(&ks)?;

        // Start a conversion job, then cancel it
        let job = ConvertJob::start(path, &protector, protector_key.clone(), &ks)?;
        job.cancel()?;
        drop(job);

        // The original directory should remain unmodified
        crate::ensure_unencrypted(path, &ks)?;
        assert_eq!(std::fs::read_to_string(path.join("file.txt"))?, "hello");

        // Check the conversion status
        assert!(matches!(conversion_status(path)?, ConversionStatus::Interrupted(_)));

        // Start the job again, but let it finish this time
        let job = ConvertJob::start(path, &protector, protector_key, &ks)?;
        assert!(matches!(conversion_status(path)?, ConversionStatus::Ongoing(_)));
        job.commit()?;

        let encrypted_dir = EncryptedDir::open(path, &ks, LockState::Unlocked)?;
        assert_eq!(std::fs::read_to_string(path.join("file.txt"))?, "hello");
        assert!(matches!(conversion_status(path)?, ConversionStatus::None));
        encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

        Ok(())
    }

    #[test]
    fn test_concurrent_start_rejected() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };
        crate::init()?;

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create a directory with data
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        let path = dir.path();
        std::fs::write(dir.path().join("file.txt"), "hello")?;

        // Create a protector
        let (protector, protector_key) = make_test_protector(&ks)?;

        // Start a conversion job
        let job = ConvertJob::start(path, &protector, protector_key.clone(), &ks)?;
        assert!(matches!(conversion_status(path)?, ConversionStatus::Ongoing(_)));

        // Try to start another job while the first one is ongoing
        assert!(ConvertJob::start(path, &protector, protector_key, &ks).is_err());

        // Finish the first job
        job.commit()?;

        // Check that everying is in its expected status
        let encrypted_dir = EncryptedDir::open(path, &ks, LockState::Unlocked)?;
        assert_eq!(std::fs::read_to_string(path.join("file.txt"))?, "hello");
        assert!(matches!(conversion_status(path)?, ConversionStatus::None));
        encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

        Ok(())
    }

    // Test a crash between fs::rename and RENAME_EXCHANGE.
    // - The source directory is still unencrypted
    // - The encrypted copy is orphaned at workdir/data.
    // - start() should detect the orphan, move it back, re-run rsync, and
    //   allow commit() to complete successfully.
    #[test]
    fn test_crash_before_exchange() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };
        crate::init()?;

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create a directory with data
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        let path = dir.path();
        std::fs::write(path.join("file.txt"), "hello")?;

        // Create a protector
        let (protector, protector_key) = make_test_protector(&ks)?;

        // Simulate a crash between fs::rename and RENAME_EXCHANGE:
        inject_error(InjectedError::ConvertCommitBeforeExchange);
        let job = ConvertJob::start(path, &protector, protector_key.clone(), &ks)?;
        let workdir = job.workdir.clone();
        assert!(job.commit().is_err());

        // workdir/data is left as an orphan, source is still unencrypted.
        assert!(workdir.join(ConvertJob::DSTDIR).exists());
        crate::ensure_unencrypted(path, &ks)?;
        assert!(matches!(conversion_status(path)?, ConversionStatus::Interrupted(_)));

        // start() moves the orphan back and re-runs rsync; commit() finishes the job
        clear_injected_error();
        let job = ConvertJob::start(path, &protector, protector_key, &ks)?;
        job.commit()?;

        // Check that everying is in its expected status
        let encrypted_dir = EncryptedDir::open(path, &ks, LockState::Unlocked)?;
        assert_eq!(std::fs::read_to_string(path.join("file.txt"))?, "hello");
        assert!(matches!(conversion_status(path)?, ConversionStatus::None));
        assert!(!workdir.exists());
        encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

        Ok(())
    }

    // Test a crash after RENAME_EXCHANGE but before convertdb is updated
    // - The source directory is already encrypted
    // - workdir still exists, and there's an entry in the convertdb file
    // - conversion_status() should clean things up and report None
    #[test]
    fn test_crash_after_exchange() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };
        crate::init()?;

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create a directory with data
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        let path = dir.path();
        std::fs::write(path.join("file.txt"), "hello")?;

        // Create a protector
        let (protector, protector_key) = make_test_protector(&ks)?;

        // Simulate a crash between RENAME_EXCHANGE and db.commit():
        inject_error(InjectedError::ConvertCommitAfterExchange);
        let job = ConvertJob::start(path, &protector, protector_key.clone(), &ks)?;
        let workdir = job.workdir.clone();
        assert!(job.commit().is_err());

        // The directory is now encrypted
        let encrypted_dir = EncryptedDir::open(path, &ks, LockState::Unlocked)?;
        assert_eq!(std::fs::read_to_string(path.join("file.txt"))?, "hello");

        // Restarting a conversion job fails because of that
        let Err(err) = ConvertJob::start(path, &protector, protector_key, &ks) else {
            bail!("Expected error when restarting finished job");
        };
        assert_eq!(err.to_string(), "Directory already encrypted");

        // But the work directory still exists because this crashed before db.commit()
        assert!(workdir.exists());

        // conversion_status() detects the stale entry and cleans everything up
        assert!(matches!(conversion_status(path)?, ConversionStatus::None));
        assert!(!workdir.exists());

        encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

        Ok(())
    }
}
