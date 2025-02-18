/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, ensure, Result};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempdir::TempDir;
use walkdir::WalkDir;

use crate::fscrypt;

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
pub fn convert_dir(dir: &Path, pass: &[u8]) -> Result<fscrypt::PolicyKeyId> {
    let dir = dir.canonicalize()?;
    let parent = dir.parent().unwrap_or(&dir);

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
    let keyid = crate::encrypt_dir(&workdir_e, pass)?;

    // Copy the source directory inside the encrypted directory.
    // This will encrypt the data in the process.
    let encrypted_dir = workdir_e.join("data");
    let status = Command::new("cp")
        .arg("-a")
        .arg(dir.as_os_str())
        .arg(encrypted_dir.as_os_str())
        .status()?;

    ensure!(status.success(), "Error encrypting data");

    // Move the encrypted copy ("data") from workdir/encrypted/ to workdir/
    let encrypted_dir2 = workdir.join("data");
    fs::rename(&encrypted_dir, &encrypted_dir2)?;

    // Sync the filesystem
    let _ = fs::File::open(&encrypted_dir2).map(|f| nix::unistd::syncfs(f.as_raw_fd()));

    // Exchange atomically the source directory and its encrypted copy
    nix::fcntl::renameat2(None, &dir, None, &encrypted_dir2, nix::fcntl::RenameFlags::RENAME_EXCHANGE)?;

    Ok(keyid)
}
