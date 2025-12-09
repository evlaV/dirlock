/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, Result};
use nix::fcntl;
use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempdir::TempDir;
use walkdir::WalkDir;

use crate::{
    Keystore,
    cloner::DirectoryCloner,
    fscrypt::{self, PolicyKeyId},
    protector::{Protector, ProtectorKey},
};

/// A background process that converts an unencrypted directory into
/// an encrypted one.
pub struct ConvertJob {
    cloner: DirectoryCloner,
    keyid: PolicyKeyId,
    // Original dir to encrypt
    srcdir: PathBuf,
    // Temporary work directory.
    // The top-level tempdir is unencrypted but it contains
    // an encrypted directory inside, {tempdir}/encrypted
    tempdir: TempDir,
    // Encrypted copy of srcdir, located inside {tempdir}/encrypted
    dstdir: PathBuf,
}

/// Check if an unencrypted directory can be converted into an encrypted one
pub fn check_can_convert_dir(dir: &Path) -> Result<()> {
    // First, it must be an actual directory
    if dir.is_symlink() || !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }

    // It cannot be the root directory of a filesystem
    let dir = dir.canonicalize()?;
    let dev = dir.metadata()?.st_dev();
    let parent_dev = dir.parent().unwrap_or(&dir).metadata()?.st_dev();
    if dev != parent_dev {
        bail!("Cannot encrypt the root directory of a filesytem");
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

impl ConvertJob {
    /// Start a new asynchronous job to convert `dir` to an encrypted folder
    pub fn start(dir: &Path, protector: &Protector, protector_key: ProtectorKey,
                 ks: &Keystore) -> Result<ConvertJob> {
        let srcdir = dir.canonicalize()?;
        let Some(parent) = srcdir.parent() else {
            bail!("Cannot encrypt the root directory");
        };

        // Create a temporary work dir in the parent directory
        let tempdir = TempDir::new_in(parent, ".dirlock")?;
        let workdir = tempdir.path();
        fs::set_permissions(workdir, {
            let mut perms = fs::metadata(workdir)?.permissions();
            perms.set_mode(0o700);
            perms
        })?;
        // Create an encrypted directory inside the work dir
        let workdir_e = workdir.join("encrypted");
        fs::create_dir(&workdir_e)?;
        let keyid = crate::encrypt_dir(&workdir_e, protector, protector_key, ks)?;

        // Copy the source directory inside the encrypted directory.
        // This will encrypt the data in the process.
        let dstdir = workdir_e.join("data");
        let cloner = DirectoryCloner::start(&srcdir, &dstdir)?;
        let job = ConvertJob { cloner, keyid, srcdir, tempdir, dstdir };

        Ok(job)
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
    pub fn stop(&mut self) -> Result<()> {
        self.cloner.stop()
    }

    /// Commit the changes and return the policy ID
    pub fn commit(self) -> Result<PolicyKeyId> {
        // Wait until the data is copied
        if let Err(e) = self.cloner.wait() {
            bail!("Error encrypting data: {e}");
        }

        // Move the encrypted copy from workdir/encrypted/ to workdir/
        let dstdir_2 = self.tempdir.path().join("data");
        fs::rename(&self.dstdir, &dstdir_2)?;

        // Exchange atomically the source directory and its encrypted copy
        let syncfd = fs::File::open(self.tempdir.path())?;
        _ = nix::unistd::syncfs(syncfd.as_raw_fd());
        fcntl::renameat2(None, &self.srcdir, None, &dstdir_2,
                         fcntl::RenameFlags::RENAME_EXCHANGE)?;
        _ = nix::unistd::syncfs(syncfd.as_raw_fd());

        Ok(self.keyid)
    }
}
