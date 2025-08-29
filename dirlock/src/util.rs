/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, Result};
use std::io::ErrorKind;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{self, MetadataExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::protector::{Protector, ProtectorType};

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

/// Prompt the user for a new protector password (with confirmation) and return it
pub fn read_new_password_for_protector(ptype: ProtectorType) -> Result<Zeroizing<String>> {
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

/// Prompt the user for a password for a specific protector and return it
pub fn read_password_for_protector(prot: &Protector) -> Result<Zeroizing<String>> {
    let prompt = prot.get_prompt().map_err(|e| anyhow!("{e}"))?;
    let pass = if prot.needs_password() {
        eprint!("{prompt}: ");
        Zeroizing::new(rpassword::read_password()?)
    } else {
        eprintln!("{prompt}");
        Zeroizing::new(String::new())
    };
    Ok(pass)
}

/// Return true if a filesystem has fscrypt support
pub fn fs_supports_encryption(fstype: &str) -> bool {
    matches!(fstype, "ext4" | "f2fs" | "ubifs" | "ceph")
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
    pub fn create(path: &Path) -> std::io::Result<Self> {
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

        let mut file = SafeFile::create(&path)?;
        file.write(b"new")?;
        drop(file);

        assert_eq!(fs::read(path)?, b"old");

        // Check that the ownership is kept
        let path = tmpdir.path().join("test2");
        fs::write(&path, b"old")?;
        unix::fs::chown(&path, Some(1), Some(2))
            .expect("chown() failed. Run as root or with fakeroot");
        let oldmd = fs::metadata(&path)?;

        let mut file = SafeFile::create(&path)?;
        file.write(b"new")?;
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

        let mut file = SafeFile::create(&path)?;
        file.write(b"new")?;
        file.commit()?;

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

        let mut file = SafeFile::create(&path)?;
        file.write(b"new")?;
        file.commit()?;

        assert_eq!(fs::read(path)?, b"new");
        assert_eq!(oldmd.permissions(), newmd.permissions());
        assert_eq!(oldmd.uid(), newmd.uid());
        assert_eq!(oldmd.gid(), newmd.gid());

        Ok(())
    }
}
