/*
 * Copyright © 2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! This module allows injecting errors during tests.
//! With this we can simulate different types of failures and
//! verify that the code handles them correctly.
//!
//! Non-test builds don't use any of this.

use anyhow::Result;
#[cfg(test)]
use std::cell::Cell;

/// Types of errors that can be injected
#[derive(Copy, Clone, PartialEq)]
pub enum InjectedError {
    /// ConvertJob::commit(), between fs::rename and RENAME_EXCHANGE.
    /// This leaves workdir/data as an orphan while the source
    /// directory is still unencrypted.
    ConvertCommitBeforeExchange,
    /// ConvertJob::commit(), between RENAME_EXCHANGE and cleanup.
    /// The directory is encrypted but the convertdb entry is still there.
    ConvertCommitAfterExchange,
}

/// In non-test builds this a no-op and gets optimized away.
#[cfg(not(test))]
#[inline(always)]
pub fn check_injected_error(_: InjectedError) -> Result<()> { Ok(()) }

#[cfg(test)]
thread_local! {
    static INJECTED_ERROR: Cell<Option<InjectedError>> = Cell::new(None);
}

#[cfg(test)]
pub fn check_injected_error(error: InjectedError) -> Result<()> {
    if INJECTED_ERROR.with(|c| c.get()) == Some(error) {
        anyhow::bail!("injected error");
    }
    Ok(())
}

#[cfg(test)]
pub fn inject_error(error: InjectedError) {
    INJECTED_ERROR.with(|c| c.set(Some(error)));
}

#[cfg(test)]
pub fn clear_injected_error() {
    INJECTED_ERROR.with(|c| c.set(None));
}
