
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

/// Get the user's home dir, or None if the user does not exist
pub(crate) fn get_homedir(user: &str) -> Result<Option<PathBuf>> {
    homedir::home(user)
        .map_err(|e| anyhow!("Unable to get {user}'s home directory: {e}"))
}

/// Check if a directory is empty
pub(crate) fn dir_is_empty(dir: &Path) -> Result<bool> {
    let empty = std::fs::read_dir(dir)?.next().is_none();
    Ok(empty)
}
