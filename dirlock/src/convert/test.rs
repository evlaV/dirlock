/*
 * Copyright © 2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

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
