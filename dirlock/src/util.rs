/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

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

/// Number of times that the user has to enter a password
pub enum ReadPassword {
    Once,
    Twice,
}

/// Prompt the user for a password and return it
pub fn read_password(prompt: &str, times: ReadPassword) -> Result<Zeroizing<String>> {
    eprint!("{prompt}: ");
    let pass = Zeroizing::new(rpassword::read_password()?);
    if matches!(times, ReadPassword::Twice) {
        eprint!("Repeat the password: ");
        let pass2 = Zeroizing::new(rpassword::read_password()?);
        if pass != pass2 {
            bail!("Passwords don't match");
        }
    }
    Ok(pass)
}
