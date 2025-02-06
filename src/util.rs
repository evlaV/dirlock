
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

/// Get the user's home dir or return an error
pub(crate) fn get_homedir(user: &str) -> Result<PathBuf> {
    homedir::home(user)?
        .ok_or(anyhow!("User {user} not found"))
}

/// Check if a directory is empty
pub(crate) fn dir_is_empty(dir: &Path) -> Result<bool> {
    let empty = std::fs::read_dir(dir)?.next().is_none();
    Ok(empty)
}
