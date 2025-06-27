/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, Result};
use std::fs::File;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::protector::{Protector, ProtectorType};

/// Get the user's home dir, or None if the user does not exist
pub(crate) fn get_homedir(user: &str) -> Result<Option<PathBuf>> {
    homedir::home(user)
        .map_err(|e| anyhow!("Unable to get {user}'s home directory: {e}"))
}

/// Check if a directory is empty
pub fn dir_is_empty(dir: &Path) -> Result<bool> {
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
    if ! prot.needs_password() {
        return Ok(Zeroizing::new(String::from("")));
    }
    let prompt = prot.get_prompt().map_err(|e| anyhow!("{e}"))?;
    eprint!("{prompt}: ");
    let pass = Zeroizing::new(rpassword::read_password()?);
    Ok(pass)
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
    pub fn create(path: &Path) -> Result<Self> {
        let template = match (path.parent(), path.file_name()) {
            (Some(dirname), Some(filename)) => {
                let mut name = std::ffi::OsString::from(".#");
                name.push(filename);
                name.push(".XXXXXX");
                dirname.join(name)
            },
            _ => bail!("Invalid path {}", path.display()),
        };
        let (fd, temp_path) = nix::unistd::mkstemp(&template)?;
        let file = unsafe { File::from_raw_fd(fd) };
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
