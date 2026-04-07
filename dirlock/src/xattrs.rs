/*
 * Copyright © 2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

/// Manages the set of `trusted.dirlockN` xattrs on a directory.
pub struct Xattrs {
    slots: HashMap<u8, String>,
}

impl Xattrs {
    const PREFIX: &str = "trusted.dirlock";
    const MAX_SLOTS: u8 = 10;
    pub const TYPE_RECOVERY: &str = "1";

    fn slot_name(slot: u8) -> String {
        format!("{}{}", Self::PREFIX, slot)
    }

    /// Loads all dirlock xattrs from `path`.
    pub fn load(path: &Path) -> Self {
        let slots = xattr::list(path).ok().map(|names| {
            names.filter_map(|name| {
                let index = name.to_str()?
                    .strip_prefix(Self::PREFIX)?
                    .parse::<u8>().ok()?;
                let value = xattr::get(path, &name).ok()??;
                Some((index, String::from_utf8_lossy(&value).into_owned()))
            }).collect()
        }).unwrap_or_default();
        Xattrs { slots }
    }

    /// Returns the index and value of the first slot with the given type, or `None` if not found.
    pub fn find_slot(&self, slot_type: &str) -> Option<(u8, &str)> {
        self.slots.iter()
            .find(|(_, attr)| attr.split(':').next() == Some(slot_type))
            .map(|(i, attr)| (*i, attr.as_str()))
    }

    /// Returns the index of the first empty slot, or `None` if all slots are occupied.
    pub fn first_free_slot(&self) -> Option<u8> {
        (0..Self::MAX_SLOTS).find(|i| !self.slots.contains_key(i))
    }

    /// Writes `value` to the given slot on `path`, replacing any existing value.
    pub fn set(path: &Path, slot: u8, value: &str) -> Result<()> {
        xattr::set(path, Self::slot_name(slot), value.as_bytes())?;
        Ok(())
    }

    /// Removes the given slot from `path`.
    pub fn remove(path: &Path, slot: u8) -> Result<()> {
        xattr::remove(path, Self::slot_name(slot))?;
        Ok(())
    }
}
