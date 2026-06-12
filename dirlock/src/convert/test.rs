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
use crate::inject::{clear_injected, inject, Injected};
use crate::protector::{Protector, ProtectorKey, opts::ProtectorOptsBuilder};

// Tests in this module verify that interrupted conversion jobs are
// handled correctly and that their state is cleaned up.
// In general all works automatically and nothing special needs to be done,
// but test_cleanup() in particular tests the general cleanup() function that
// can potentially affect the result of the other tests.
//
// For this reason, test_cleanup() acquires this lock with exclusive access
// and all other tests in this module must acquire it with shared access.
static FS_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

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
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());

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
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());

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
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());
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
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());
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
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());
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
    inject(Injected::ConvertCommitBeforeExchange);
    let job = ConvertJob::start(path, &protector, protector_key.clone(), &ks)?;
    let workdir = job.workdir.clone();
    assert!(job.commit().is_err());

    // workdir/data is left as an orphan, source is still unencrypted.
    assert!(workdir.join(ConvertJob::DSTDIR).exists());
    crate::ensure_unencrypted(path, &ks)?;
    assert!(matches!(conversion_status(path)?, ConversionStatus::Interrupted(_)));

    // start() moves the orphan back and re-runs rsync; commit() finishes the job
    clear_injected();
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
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());
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
    inject(Injected::ConvertCommitAfterExchange);
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

// If a conversion job is marked dirty then commit() restarts it, and
// a second commit() updates the data and completes the conversion.
#[test]
fn test_mark_dirty_restarts_commit() -> Result<()> {
    let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());
    crate::init()?;

    let ks_dir = TempDir::new("keystore")?;
    let ks = Keystore::from_path(ks_dir.path());

    // Create a directory with data
    let dir = TempDir::new_in(&mntpoint, "convert")?;
    let path = dir.path();
    std::fs::write(path.join("file.txt"), "hello")?;
    std::fs::write(path.join("gone.txt"), "to be deleted")?;

    // Create a protector
    let (protector, protector_key) = make_test_protector(&ks)?;

    // This does nothing if no conversion started yet
    assert!(!ConvertJob::mark_dirty(path)?);

    // Start the conversion. No dirty flag yet
    let job = ConvertJob::start(path, &protector, protector_key, &ks)?;
    assert!(!ConvertJob::dirty_flag_exists(&job.workdir));

    // Wait for the copy to finish, then mark the conversion dirty
    job.wait()?;
    assert!(ConvertJob::mark_dirty(path)?);
    assert!(ConvertJob::dirty_flag_exists(&job.workdir));

    // Modify the original file, add a new one and remove gone.txt
    std::fs::write(path.join("file.txt"), "goodbye")?;
    std::fs::write(path.join("new.txt"), "new file")?;
    std::fs::remove_file(path.join("gone.txt"))?;

    // It's safe to call mark_dirty() multiple times
    assert!(ConvertJob::mark_dirty(path)?);
    assert!(ConvertJob::mark_dirty(path)?);

    // With the dirty flag set, commit() restarts the job
    let CommitOutcome::Restarted(job) = job.commit()? else {
        bail!("dirty conversion job was not restarted");
    };

    // The restart cleared the flag, now the conversion can complete
    assert!(!ConvertJob::dirty_flag_exists(&job.workdir));
    assert!(matches!(job.commit()?, CommitOutcome::Committed(_)));

    // The encrypted directory contains the modified file
    let encrypted_dir = EncryptedDir::open(path, &ks, LockState::Unlocked)?;
    assert_eq!(std::fs::read_to_string(path.join("file.txt"))?, "goodbye");
    assert_eq!(std::fs::read_to_string(path.join("new.txt"))?, "new file");
    assert!(!path.join("gone.txt").exists());
    assert!(matches!(conversion_status(path)?, ConversionStatus::None));
    encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

    Ok(())
}

// Test a crash after the workdir is moved to .trash but before the
// convertdb entry is removed.
// - The source directory is already encrypted
// - The old workdir has been moved to .trash
// - The convertdb entry is still there
// - conversion_status() should remove the trashed data and return None
#[test]
fn test_crash_after_trash_rename() -> Result<()> {
    let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());
    crate::init()?;

    let ks_dir = TempDir::new("keystore")?;
    let ks = Keystore::from_path(ks_dir.path());

    // Create a directory with data
    let dir = TempDir::new_in(&mntpoint, "convert")?;
    let path = dir.path();
    std::fs::write(path.join("file.txt"), "hello")?;

    // Create a protector
    let (protector, protector_key) = make_test_protector(&ks)?;

    // Simulate a crash after the workdir is trashed but before db.commit():
    inject(Injected::ConvertCommitAfterTrashRename);
    let job = ConvertJob::start(path, &protector, protector_key, &ks)?;
    let workdir = job.workdir.clone();
    assert!(job.commit().is_err());
    clear_injected();

    // The directory is now encrypted
    let encrypted_dir = EncryptedDir::open(path, &ks, LockState::Unlocked)?;
    assert_eq!(std::fs::read_to_string(path.join("file.txt"))?, "hello");
    encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

    // The workdir was moved into .trash: its old location is gone but the
    // trashed copy is still on disk (to be reclaimed during cleanup).
    let trash_entry = workdir.parent().unwrap()
        .join(ConvertJob::TRASHDIR)
        .join(workdir.file_name().unwrap());
    assert!(!workdir.exists());
    assert!(trash_entry.exists());

    // conversion_status() detects the stale entry, removes the trashed
    // data and reports None
    assert!(matches!(conversion_status(path)?, ConversionStatus::None));
    assert!(!trash_entry.exists());

    Ok(())
}

// When the source is a home directory whose owner is logged in, a dirty
// conversion must be deferred rather than exchanged. Once the owner logs
// out it restarts and then completes. user_manager_active() is forced
// here since the test directory is not a real home.
#[test]
fn test_dirty_conversion_is_deferred() -> Result<()> {
    let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());
    crate::init()?;

    let ks_dir = TempDir::new("keystore")?;
    let ks = Keystore::from_path(ks_dir.path());

    // Create a directory with data
    let dir = TempDir::new_in(&mntpoint, "convert")?;
    let path = dir.path();
    std::fs::write(path.join("file.txt"), "hello")?;

    // Create a protector
    let (protector, protector_key) = make_test_protector(&ks)?;

    // Pretend that the source is a home directory
    let mut job = ConvertJob::start(path, &protector, protector_key, &ks)?;
    job.home_owner = Some(std::fs::metadata(path)?.uid());

    // Fake a login mid-conversion, marking the job dirty
    inject(Injected::UserManagerActive(true));
    assert!(ConvertJob::mark_dirty(path)?);

    // commit() defers while the owner is active
    let CommitOutcome::Deferred(job) = job.commit()? else {
        bail!("expected the conversion to be deferred");
    };
    crate::ensure_unencrypted(path, &ks)?;
    assert!(ConvertJob::dirty_flag_exists(&job.workdir));

    // Same result, no matter how often we try
    let CommitOutcome::Deferred(job) = job.commit()? else {
        bail!("expected the conversion to be deferred");
    };
    crate::ensure_unencrypted(path, &ks)?;
    assert!(ConvertJob::dirty_flag_exists(&job.workdir));

    // The owner logs out: commit() now restarts the copy
    inject(Injected::UserManagerActive(false));
    let CommitOutcome::Restarted(job) = job.commit()? else {
        bail!("expected the conversion to be restarted after logout");
    };

    // The dirty flag is now gone
    assert!(!ConvertJob::dirty_flag_exists(&job.workdir));

    // The owner logs in again before the restart finishes: the job must
    // defer once more rather than complete.
    inject(Injected::UserManagerActive(true));
    assert!(ConvertJob::mark_dirty(path)?);
    let CommitOutcome::Deferred(job) = job.commit()? else {
        bail!("expected the conversion to be deferred after the second login");
    };
    crate::ensure_unencrypted(path, &ks)?;
    assert!(ConvertJob::dirty_flag_exists(&job.workdir));

    // The owner logs out for good: commit() restarts once more
    inject(Injected::UserManagerActive(false));
    let CommitOutcome::Restarted(job) = job.commit()? else {
        bail!("expected the conversion to be restarted after the second logout");
    };
    assert!(!ConvertJob::dirty_flag_exists(&job.workdir));

    // Now the job can complete successfully
    assert!(matches!(job.commit()?, CommitOutcome::Committed(_)));
    clear_injected();

    // The directory is encrypted with the data intact.
    let encrypted_dir = EncryptedDir::open(path, &ks, LockState::Unlocked)?;
    assert_eq!(std::fs::read_to_string(path.join("file.txt"))?, "hello");
    assert!(matches!(conversion_status(path)?, ConversionStatus::None));
    encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

    Ok(())
}

// Restart a conversion but modify a source file keeping its size and
// mtime. This verifies that rsync is run with --checksum and detects
// these changes.
#[test]
fn test_dirty_restart_uses_checksum() -> Result<()> {
    use nix::sys::stat::{utimensat, UtimensatFlags};
    use nix::sys::time::TimeSpec;

    let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };
    let _shared = FS_LOCK.read().unwrap_or_else(|e| e.into_inner());
    crate::init()?;

    let ks_dir = TempDir::new("keystore")?;
    let ks = Keystore::from_path(ks_dir.path());

    // Create a directory with data
    let dir = TempDir::new_in(&mntpoint, "convert")?;
    let srcdir = dir.path();
    let srcfile = srcdir.join("file.txt");
    std::fs::write(&srcfile, "hello")?;

    // Create a protector
    let (protector, protector_key) = make_test_protector(&ks)?;

    // The first pass copies "hello" into the (encrypted) destination.
    let job = ConvertJob::start(srcdir, &protector, protector_key, &ks)?;
    job.wait()?;

    // Rewrite the source file but keep the size and timestamps
    let dst_md = std::fs::metadata(job.dstdir.join("file.txt"))?;
    let atime = TimeSpec::new(dst_md.atime(), dst_md.atime_nsec());
    let mtime = TimeSpec::new(dst_md.mtime(), dst_md.mtime_nsec());
    std::fs::write(&srcfile, "world")?;
    utimensat(None, &srcfile, &atime, &mtime, UtimensatFlags::FollowSymlink)?;

    // Now both timestamps should be identical
    let src_md = std::fs::metadata(&srcfile)?;
    assert_eq!(src_md.len(), dst_md.len());
    assert_eq!(src_md.mtime(), dst_md.mtime());
    assert_eq!(src_md.mtime_nsec(), dst_md.mtime_nsec());

    // Marking the job dirty makes commit() restart the copy with --checksum.
    // This should detect the changes even though the sizes and timestamps
    // match.
    assert!(ConvertJob::mark_dirty(srcdir)?);
    let CommitOutcome::Restarted(job) = job.commit()? else {
        bail!("expected the dirty conversion to be restarted");
    };

    // Now the job can complete successfully
    assert!(matches!(job.commit()?, CommitOutcome::Committed(_)));

    // Verify that the final (encrypted) directory has the new contents
    let encrypted_dir = EncryptedDir::open(srcdir, &ks, LockState::Unlocked)?;
    assert_eq!(std::fs::read_to_string(&srcfile)?, "world");
    encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;

    Ok(())
}

// General test for cleanup().
// This cannot be run in parallel with the other ones so it acquires
// FS_LOCK with exclusive access.
#[test]
fn test_cleanup() -> Result<()> {
    let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };
    let _exclusive = FS_LOCK.write().unwrap_or_else(|e| e.into_inner());
    crate::init()?;

    let ks_dir = TempDir::new("keystore")?;
    let ks = Keystore::from_path(ks_dir.path());

    // Create a protector
    let (protector, protector_key) = make_test_protector(&ks)?;

    // A resumable conversion: interrupted, but its source still exists.
    let keep_dir = TempDir::new_in(&mntpoint, "convert")?;
    let keep = keep_dir.path();
    std::fs::write(keep.join("file.txt"), "hello")?;
    let job = ConvertJob::start(keep, &protector, protector_key.clone(), &ks)?;
    let base = job.dirs.base.clone();
    let trash = base.join(ConvertJob::TRASHDIR);
    job.cancel()?;
    drop(job);
    assert!(matches!(conversion_status(keep)?, ConversionStatus::Interrupted(_)));

    // A dead conversion: interrupted, and then its source disappears.
    let gone_dir = TempDir::new_in(&mntpoint, "convert")?;
    let gone = gone_dir.path().to_owned();
    std::fs::write(gone.join("file.txt"), "hello")?;
    let job = ConvertJob::start(&gone, &protector, protector_key, &ks)?;
    let gone_workdir = job.workdir.clone();
    job.cancel()?;
    drop(job);
    drop(gone_dir); // This removes the source directory
    assert!(!gone.exists());
    assert!(gone_workdir.exists());

    // A dead conversion: neither the source dir or workdir exist
    let stale_rel = PathBuf::from("dirlock-test-missing-source");
    let mut db = ConvertDb::load(&base)?;
    db.insert(&stale_rel, PolicyKeyId::default());
    db.commit()?;
    drop(db);
    assert!(ConvertDb::load(&base)?.get(&stale_rel).is_some());

    // A trashed leftover from some crashed commit.
    let trash_leftover = trash.join("stale");
    std::fs::create_dir_all(&trash_leftover)?;

    // In total there are at least 3 convertdb entries
    // (there could be more than 3 if an earlier test failed).
    assert!(ConvertDb::load(&base)?.keys().count() >= 3);

    // cleanup() must handle all of these without failing.
    cleanup(&mntpoint)?;

    // The resumable conversion is left untouched.
    assert!(matches!(conversion_status(keep)?, ConversionStatus::Interrupted(_)));
    // The dead conversion's workdir has been removed.
    assert!(!gone_workdir.exists());
    // The dead conversion with a missing workdir has been removed.
    assert!(ConvertDb::load(&base)?.get(&stale_rel).is_none());
    // The leftover has been removed.
    assert!(!trash_leftover.exists());

    // There should be one conversion left: the resumable one.
    assert_eq!(ConvertDb::load(&base)?.keys().count(), 1);

    // Remove the last conversion so the test leaves no state behind
    drop(keep_dir);
    cleanup(&mntpoint)?;
    assert_eq!(ConvertDb::load(&base)?.keys().count(), 0);
    assert!(!base.exists());

    Ok(())
}
