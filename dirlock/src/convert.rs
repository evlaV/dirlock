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
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::{
    CreateOpts,
    DirStatus,
    Keystore,
    create_policy_data,
    cloner::DirectoryCloner,
    fscrypt::{self, KeyStatus, PolicyKeyId},
    protector::{Protector, ProtectorId, ProtectorKey},
    unlock_dir_with_key,
    util::{
        LockFile,
        SafeFile,
        create_dir_if_needed,
        dir_is_empty,
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
    /// Lock file held for the duration of the job
    _lockfile: LockFile,
}

/// The conversion status of a given directory
pub enum ConversionStatus {
    None,
    Ongoing(PolicyKeyId),
    Interrupted(PolicyKeyId),
}

/// Returns the [`ConversionStatus`] of a given source directory
pub fn conversion_status(dir: &Path) -> Result<ConversionStatus> {
    ConvertJob::status(dir)
}

/// Check if an unencrypted directory can be converted into an encrypted one.
// TODO: this is used to warn the user before attempting a conversion, but
// it should probably be part of the conversion job and run asynchronously.
pub fn check_can_convert_dir(dir: &Path, protid: Option<&ProtectorId>, ks: &Keystore) -> Result<()> {
    // First, it must be an actual directory
    if ! is_real_dir(dir) {
        bail!("{} is not a directory", dir.display());
    }

    // It cannot be the root directory of a filesystem
    let dir = dir.canonicalize()?;
    let dev = dir.metadata()?.st_dev();
    let parent_dev = dir.parent().unwrap_or(&dir).metadata()?.st_dev();
    if dev != parent_dev {
        bail!("Cannot encrypt the root directory of a filesytem");
    }

    // Check that the directory is not being converted already
    match ConvertJob::status(&dir)? {
        ConversionStatus::None => (),
        ConversionStatus::Ongoing(id) => {
            bail!("Directory {} is alredy being converted with policy {id}", dir.display());
        },
        ConversionStatus::Interrupted(id) => {
            let policy = ks.load_policy_data(&id)?;
            if let Some(protid) = protid {
                if ! policy.keys.contains_key(protid) {
                    bail!("Directory {} is already being converted with policy {id} but protector {} cannot unlock it",
                          dir.display(), protid);
                }
            }
        },
    }

    // Check all subdirectories
    for iter in WalkDir::new(&dir).follow_links(false) {
        let entry = iter?;
        if ! entry.file_type().is_dir() {
            continue;
        }
        // All contents must be in the same filesystem
        if entry.metadata()?.st_dev() != dev {
            bail!("{} has contents in different filesystems", dir.display());
        }
        // All contents must be unencrypted
        if fscrypt::get_policy(entry.path())?.is_some() {
            bail!("{} has encrypted content", dir.display());
        }
    }

    Ok(())
}

/// Convert an unencrypted directory into an encrypted one
pub fn convert_dir(dir: &Path, protector: &Protector, protector_key: ProtectorKey,
                   ks: &Keystore) -> Result<PolicyKeyId> {
    let job = ConvertJob::start(dir, protector, protector_key, ks)?;
    let mut stdout = std::io::stdout();
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
    job.commit()
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

    /// This canonicalizes the source dir and returns [`SrcDirData`]
    fn get_src_dir_data(dir: &Path) -> Result<SrcDirData> {
        let src = dir.canonicalize()?;
        let mut base = fscrypt::get_mountpoint(&src)?;
        if base == src {
            bail!("Cannot encrypt the root directory of a filesystem");
        };
        // src, but relative to the mount point
        let src_rel = src.strip_prefix(&base)?.to_owned();
        base.push(Self::BASEDIR);
        Ok(SrcDirData { src, src_rel, base })
    }

    /// Returns the [`ConversionStatus`] of a given source directory
    fn status(dir: &Path) -> Result<ConversionStatus> {
        let dirs = Self::get_src_dir_data(dir)?;
        // Fast path: in most cases /mntpoint/.dirlock does not exist
        if ! dirs.base.exists() {
            return Ok(ConversionStatus::None);
        }
        let db = ConvertDb::load(&dirs.base)?;
        let status = match db.get(&dirs.src_rel) {
            Some(id) => {
                let mut lockfile = dirs.base.join(id.to_string());
                lockfile.push(Self::LOCKFILE);
                match LockFile::try_new(&lockfile) {
                    Ok(None) => ConversionStatus::Ongoing(id.clone()),
                    _ => ConversionStatus::Interrupted(id.clone())
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
                let (policy, key) = create_policy_data(protector, protector_key,
                                                       CreateOpts::CreateAndSave, ks)?;
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

        // Copy the source directory inside the encrypted directory.
        // This will encrypt the data in the process.
        let dstdir = workdir_e.join(Self::DSTDIR);
        let cloner = DirectoryCloner::start(&dirs.src, &dstdir)?;

        Ok(Self { dirs, cloner, keyid, _lockfile, dstdir, workdir })
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
    pub fn cancel(&self) -> Result<()> {
        self.cloner.cancel()
    }

    /// Wail until the operation is done
    pub fn wait(&self) -> Result<()> {
        self.cloner.wait()
    }

    /// Wait for the conversion job to finish and replace the original
    /// directory with the encrypted one.
    pub fn commit(self) -> Result<PolicyKeyId> {
        // Wait until the data is copied
        if let Err(e) = self.cloner.wait() {
            bail!("Error encrypting data: {e}");
        }

        // Move the encrypted copy from workdir/encrypted/ to workdir/
        let dstdir_2 = self.workdir.join(Self::DSTDIR);
        fs::rename(&self.dstdir, &dstdir_2)?;

        // Exchange atomically the source directory and its encrypted copy
        let syncfd = fs::File::open(&self.dirs.base)?;
        _ = nix::unistd::syncfs(syncfd.as_raw_fd());
        fcntl::renameat2(None, &self.dirs.src, None, &dstdir_2,
                         fcntl::RenameFlags::RENAME_EXCHANGE)?;
        _ = nix::unistd::syncfs(syncfd.as_raw_fd());

        // Remove the original data, now under workdir/data
        let _ = fs::remove_dir_all(&dstdir_2);

        // Remove the job from the convertdb.
        // This acquires the global lock.
        let mut db = ConvertDb::load(&self.dirs.base)?;
        db.remove(&self.dirs.src_rel);

        // Remove the rest of workdir
        let _ = fs::remove_dir_all(&self.workdir);
        // workdir is gone, write the updated convertdb to disk
        let _ = db.commit();

        Ok(self.keyid)
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
