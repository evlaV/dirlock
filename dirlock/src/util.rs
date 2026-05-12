/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, Result};
use nix::libc;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{self, MetadataExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::Host;
use crate::config::Config;
use crate::protector::{Protector, ProtectorType};

/// Get the mount point of the file system that contains `dir`
pub fn get_mountpoint(dir: &Path) -> std::io::Result<PathBuf> {
    let mut current = dir.canonicalize()?;
    loop {
        // Compare a directory's metadata with its parent's
        let parent = current.parent().unwrap_or(&current);
        let md1 = std::fs::metadata(&current)?;
        let md2 = std::fs::metadata(parent)?;
        // Same inode? => We reached the root directory
        if md2.ino() == md1.ino() {
            return Ok(current);
        }
        // Different device? => The parent is in a different filesystem
        if md2.dev() != md1.dev() {
            return Ok(current);
        }
        current.pop();
    }
}

/// Get the user's home dir, or None if the user does not exist
pub(crate) fn get_homedir(user: &str) -> Result<Option<PathBuf>> {
    homedir::home(user)
        .map_err(|e| anyhow!("Unable to get {user}'s home directory: {e}"))
}

/// Check if a directory is empty
pub fn dir_is_empty(dir: &Path) -> std::io::Result<bool> {
    let empty = std::fs::read_dir(dir)?.next().is_none();
    Ok(empty)
}

/// Like [`Path::is_dir`] but does not follow symlinks
pub fn is_real_dir(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir)
        .map(|md| md.is_dir())
        .unwrap_or(false)
}

/// Create a directory but don't fail if it already exists.
/// This fails if `dir` is a symlink to a directory.
pub fn create_dir_if_needed(dir: &Path) -> std::io::Result<()> {
    if is_real_dir(dir) {
        Ok(())
    } else {
        std::fs::create_dir(dir)
    }
}

thread_local! {
    /// Queue of passwords to be returned by the password-reading
    /// functions like [`read_password_for_protector()`].
    /// Used for tests who need to provide their own passwords and
    /// bypass the interactive prompt.
    static PASSWORD_QUEUE: RefCell<VecDeque<String>> = const { RefCell::new(VecDeque::new()) };
}

/// Push a new password to the queue
pub fn push_test_password(pass: &str) {
    PASSWORD_QUEUE.with_borrow_mut(|q| q.push_back(String::from(pass)));
}

/// Pop a password from the queue
fn pop_test_password() -> Option<Zeroizing<String>> {
    PASSWORD_QUEUE.with_borrow_mut(|q| q.pop_front().map(Zeroizing::new))
}

/// Prompt the user for a new protector password (with confirmation) and return it
pub fn read_new_password_for_protector(ptype: ProtectorType) -> Result<Zeroizing<String>> {
    if let Some(pass) = pop_test_password() {
        return Ok(pass);
    }

    // For FIDO2 protectors we need the existing PIN of the token, not a new one
    if ptype == ProtectorType::Fido2 {
        crate::protector::fido2::check_device_available()?;
        let name = ptype.credential_name();
        eprint!("Enter the {name}: ");
        let pin = Zeroizing::new(rpassword::read_password()?);
        return Ok(pin);
    }

    let name = ptype.credential_name();
    eprint!("Enter a new {name}: ");
    let pass = Zeroizing::new(rpassword::read_password()?);
    eprint!("Repeat the {name}: ");
    let pass2 = Zeroizing::new(rpassword::read_password()?);
    if pass != pass2 {
        bail!("The values don't match");
    }
    Ok(pass)
}

/// Prompt the user for a recovery key and return it
pub fn read_recovery_key() -> Result<Zeroizing<String>> {
    if let Some(pass) = pop_test_password() {
        return Ok(pass);
    }
    eprint!("Enter recovery key: ");
    Ok(Zeroizing::new(rpassword::read_password()?))
}

/// Prompt the user for a password for a specific protector and return it
pub fn read_password_for_protector(prot: &Protector) -> Result<Zeroizing<String>> {
    if let Some(pass) = pop_test_password() {
        return Ok(pass);
    }
    let prompt = prot.get_prompt(Host::Local).map_err(|e| anyhow!("{e}"))?;
    let pass = if prot.needs_password() {
        eprint!("{prompt}: ");
        Zeroizing::new(rpassword::read_password()?)
    } else {
        eprintln!("{prompt}");
        Zeroizing::new(String::new())
    };
    Ok(pass)
}

/// Return the list of mounted filesystems that support fscrypt,
/// deduplicated by source device to avoid processing the same
/// filesystem twice due to bind mounts.
pub fn get_unique_mounts() -> Result<Vec<get_sys_info::Filesystem>> {
    use get_sys_info::Platform;
    let mut mounts : Vec<_> = get_sys_info::System::new().mounts()?
        .into_iter()
        .filter(|m| fs_supports_encryption(&m.fs_type))
        .collect();
    mounts.sort_by(|a, b| a.fs_mounted_from.cmp(&b.fs_mounted_from));
    mounts.dedup_by(|a, b| a.fs_mounted_from == b.fs_mounted_from);
    Ok(mounts)
}

/// Return true if a filesystem has fscrypt support
pub fn fs_supports_encryption(fstype: &str) -> bool {
    matches!(fstype, "ext4" | "f2fs" | "ubifs" | "ceph")
}

/// Wrapper for the statx(2) system call
pub struct Statx {
    stx: statx_sys::statx,
}

impl Statx {
    /// Call statx(2) on this path. The path must be absolute
    pub fn from_path(path: &std::ffi::CStr) -> Result<Self> {
        use statx_sys::*;
        let mut stx : statx = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            statx(-1, path.as_ptr(), AT_SYMLINK_NOFOLLOW, 0, &raw mut stx)
        };
        if ret != 0 {
            bail!("statx({}) failed: {}", path.to_string_lossy(), std::io::Error::last_os_error());
        }
        Ok(Statx { stx })
    }

    /// Check if the path is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.stx.stx_attributes & (statx_sys::STATX_ATTR_ENCRYPTED as u64) != 0
    }

    /// Check if both paths are in the same filesystem
    pub fn same_dev(&self, other: &Statx) -> bool {
        self.stx.stx_dev_major == other.stx.stx_dev_major &&
        self.stx.stx_dev_minor == other.stx.stx_dev_minor
    }
}

/// Helper to safely write the new version of a file to disk.
///
/// This creates a temporary file on the same directory and all write
/// operations use that temporary file, which is later transparently
/// renamed to the final one once all data has been written and
/// flushed to disk.
///
/// If an error happens the temporary file is removed and the original
/// file is left intact.
pub struct SafeFile {
    temp_path: PathBuf,
    final_path: PathBuf,
    file: File,
    committed: bool,
}

impl SafeFile {
    /// Create a new [`SafeFile`] to write data to `path`.
    ///
    /// This works on a temporary file, the actual file at `path` is
    /// only updated when calling commit().
    pub fn create(path: &Path, default_uid: Option<u32>, default_gid: Option<u32>) -> std::io::Result<Self> {
        let template = match (path.parent(), path.file_name()) {
            (Some(dirname), Some(filename)) => {
                let mut name = std::ffi::OsString::from(".#");
                name.push(filename);
                name.push(".XXXXXX");
                dirname.join(name)
            },
            _ => {
                let msg = format!("Invalid path {}", path.display());
                return Err(std::io::Error::new(ErrorKind::InvalidInput, msg));
            },
        };
        let (fd, temp_path) = nix::unistd::mkstemp(&template)?;
        let file = unsafe { File::from_raw_fd(fd) };
        // If the target file already exists then keep the ownership and mode
        if let Ok(oldmd) = std::fs::metadata(path) {
            let newmd = file.metadata()?;
            if oldmd.uid() != newmd.uid() || oldmd.gid() != newmd.gid() {
                fs::fchown(&file, Some(oldmd.uid()), Some(oldmd.gid()))?;
            }
            if oldmd.permissions() != newmd.permissions() {
                file.set_permissions(oldmd.permissions())?;
            }
        } else if default_uid.is_some() || default_gid.is_some() {
            fs::fchown(&file, default_uid, default_gid)?;
        }
        let final_path = PathBuf::from(path);
        let committed = false;
        Ok(SafeFile { temp_path, final_path, file, committed })
    }

    /// Flush all changes to disk, close the file and rename it,
    /// replacing the previous version if there is one.
    pub fn commit(mut self) -> std::io::Result<()> {
        self.file.sync_all()?;
        let dir = File::open(self.final_path.parent().unwrap())?;
        std::fs::rename(&self.temp_path, &self.final_path)?;
        self.committed = true;
        let _ = dir.sync_all();
        Ok(())
    }
}

impl std::io::Write for SafeFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Drop for SafeFile {
    /// On drop the temporary file is discarded if the changes were
    /// not committed
    fn drop(&mut self) {
        if ! self.committed {
            let _ = std::fs::remove_file(&self.temp_path);
        }
    }
}


/// A lock file that uses flock() internally
pub struct LockFile {
    _file: File,
}

impl LockFile {
    const GLOBAL_LOCKFILE : &str = "dirlock.lock";

    /// Acquire a lock file.
    /// Blocks until the file is available.
    pub fn new(path: &Path) -> std::io::Result<Self> {
        Self::new_full(path, libc::LOCK_EX)
    }

    /// Acquire a lock file. This function does not block, it returns
    /// Ok(None) if the lock is being held.
    pub fn try_new(path: &Path) -> std::io::Result<Option<Self>> {
        match Self::new_full(path, libc::LOCK_EX | libc::LOCK_NB) {
            Ok(lockfile) => Ok(Some(lockfile)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Acquire a global, system-wide lockfile.
    /// Blocks until the file is available.
    pub fn global() -> std::io::Result<Self> {
        let lockfile = Config::runtime_dir().join(Self::GLOBAL_LOCKFILE);
        Self::new(&lockfile)
    }

    // Actual constructor, private
    fn new_full(path: &Path, flags: std::ffi::c_int) -> std::io::Result<Self> {
        // Open the file if it already exists, else create it
        let _file = OpenOptions::new().create(true).write(true).truncate(false)
            .open(path)?;
        if unsafe { libc::flock(_file.as_raw_fd(), flags) } == 0 {
            Ok(LockFile { _file })
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}


#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::io::Write;
    use std::fs::{self, Permissions};
    use std::os::unix::{self, fs::MetadataExt, fs::PermissionsExt};
    use super::SafeFile;

    #[test]
    fn test_safefile() -> Result<()> {
        let tmpdir = tempdir::TempDir::new("safefile")?;

        // Create a SafeFile but don't commit it
        let path = tmpdir.path().join("test1");
        fs::write(&path, b"old")?;

        let mut file = SafeFile::create(&path, None, None)?;
        _ = file.write(b"new")?;
        drop(file);

        assert_eq!(fs::read(path)?, b"old");

        // Check that the ownership is kept
        let path = tmpdir.path().join("test2");
        fs::write(&path, b"old")?;
        unix::fs::chown(&path, Some(1), Some(2))
            .expect("chown() failed. Run as root or with fakeroot");
        let oldmd = fs::metadata(&path)?;

        let mut file = SafeFile::create(&path, None, None)?;
        _ = file.write(b"new")?;
        file.commit()?;
        let newmd = fs::metadata(&path)?;

        assert_eq!(fs::read(path)?, b"new");
        assert_eq!(oldmd.permissions(), newmd.permissions());
        assert_eq!(oldmd.uid(), newmd.uid());
        assert_eq!(oldmd.gid(), newmd.gid());

        // Check that the mode is kept
        let path = tmpdir.path().join("test3");
        fs::write(&path, b"old")?;
        fs::set_permissions(&path, Permissions::from_mode(0o751))?;
        let oldmd = fs::metadata(&path)?;

        let mut file = SafeFile::create(&path, None, None)?;
        _ = file.write(b"new")?;
        file.commit()?;
        let newmd = fs::metadata(&path)?;

        assert_eq!(fs::read(path)?, b"new");
        assert_eq!(oldmd.permissions(), newmd.permissions());
        assert_eq!(oldmd.uid(), newmd.uid());
        assert_eq!(oldmd.gid(), newmd.gid());

        // Check that both ownership and mode are kept
        let path = tmpdir.path().join("test4");
        fs::write(&path, b"old")?;
        unix::fs::chown(&path, Some(1), Some(2))
            .expect("chown() failed. Run as root or with fakeroot");
        fs::set_permissions(&path, Permissions::from_mode(0o751))?;
        let oldmd = fs::metadata(&path)?;

        let mut file = SafeFile::create(&path, None, None)?;
        _ = file.write(b"new")?;
        file.commit()?;
        let newmd = fs::metadata(&path)?;

        assert_eq!(fs::read(path)?, b"new");
        assert_eq!(oldmd.permissions(), newmd.permissions());
        assert_eq!(oldmd.uid(), newmd.uid());
        assert_eq!(oldmd.gid(), newmd.gid());

        Ok(())
    }
}
