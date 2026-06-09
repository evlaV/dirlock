/*
 * Copyright © 2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! This module allows injecting conditions during tests, so we can
//! simulate failures and edge cases and verify that the code handles
//! them correctly.
//!
//! Non-test builds don't use any of this.

use anyhow::Result;
#[cfg(test)]
use std::cell::Cell;

/// A condition injected during tests.
#[derive(Copy, Clone, PartialEq)]
pub enum Injected {
    /// ConvertJob::commit(), between fs::rename and RENAME_EXCHANGE.
    /// This leaves workdir/data as an orphan while the source
    /// directory is still unencrypted.
    ConvertCommitBeforeExchange,
    /// ConvertJob::commit(), between RENAME_EXCHANGE and cleanup.
    /// The directory is encrypted but the convertdb entry is still there.
    ConvertCommitAfterExchange,
    /// ConvertJob::commit(), after the workdir is moved to .trash but
    /// before the convertdb entry is removed. The directory is encrypted,
    /// the old workdir is gone, and the convertdb entry is still there.
    ConvertCommitAfterTrashRename,
}

/// Returns the currently injected condition, if any.
/// In non-test builds this is always None and gets optimized away.
#[cfg(not(test))]
#[inline(always)]
pub fn check_injected_value() -> Option<Injected> { None }

#[cfg(test)]
pub fn check_injected_value() -> Option<Injected> {
    INJECTED.with(|c| c.get())
}

/// Returns an error if `condition` is the currently injected one.
#[inline]
pub fn check_injected_error(condition: Injected) -> Result<()> {
    if check_injected_value() == Some(condition) {
        anyhow::bail!("injected error");
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static INJECTED: Cell<Option<Injected>> = Cell::new(None);
}

#[cfg(test)]
pub fn inject(condition: Injected) {
    INJECTED.with(|c| c.set(Some(condition)));
}

#[cfg(test)]
pub fn clear_injected() {
    INJECTED.with(|c| c.set(None));
}
