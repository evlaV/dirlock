
use anyhow::Result;
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Get the mount point of the file system that contains `dir`
pub fn get_mountpoint(dir: &Path) -> Result<PathBuf> {
    let mut current = dir.canonicalize()?;
    loop {
        // Compare a directory's metadata with its parent's
        let parent = current.parent().unwrap_or(&current);
        let md1 = std::fs::metadata(&current)?;
        let md2 = std::fs::metadata(parent)?;
        // Same inode? => We reached the root directory
        if md2.st_ino() == md1.st_ino() {
            return Ok(current);
        }
        // Different device? => The parent is in a different filesystem
        if md2.st_dev() != md1.st_dev() {
            return Ok(current);
        }
        current.pop();
    }
}

/// Check if a directory is empty
pub(crate) fn dir_is_empty(dir: &Path) -> Result<bool> {
    let empty = std::fs::read_dir(dir)?.next().is_none();
    Ok(empty)
}
