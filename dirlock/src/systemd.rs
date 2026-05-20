/*
 * Copyright © 2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use std::ffi::{c_char, c_int, c_void, CStr};
use anyhow::{Result, bail};

#[link(name = "systemd")]
extern "C" {
    // Returns a newly-allocated string describing the login state of uid
    // ("offline", "opening", "lingering", "online", "active", "closing").
    // The caller must free() the string.
    fn sd_uid_get_state(uid: u32, state: *mut *mut c_char) -> c_int;
}

/// Returns `true` if systemd's user manager for the given uid
/// is active (i.e. not completely offline).
pub fn user_manager_active(uid: u32) -> Result<bool> {
    let mut state: *mut c_char = std::ptr::null_mut();
    let ret = unsafe { sd_uid_get_state(uid, &mut state) };
    if ret < 0 || state.is_null() {
        bail!("sd_uid_get_state() failed for uid {uid}");
    }
    let active = unsafe { CStr::from_ptr(state) }
        .to_bytes() != b"offline";
    unsafe { libc::free(state as *mut c_void) };
    Ok(active)
}
