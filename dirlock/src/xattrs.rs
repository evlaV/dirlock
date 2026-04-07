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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_slot_empty() {
        let xattrs = Xattrs { slots: HashMap::new() };
        assert!(xattrs.find_slot(Xattrs::TYPE_RECOVERY).is_none());
    }

    #[test]
    fn test_find_slot_match() {
        // Insert a couple of slots, one of them of type 'recovery'
        let mut slots = HashMap::new();
        slots.insert(0, "0:a".to_string());
        slots.insert(3, "1:data:iv:hmac".to_string());
        let xattrs = Xattrs { slots };

        // Find the slot and check its value
        let (index, value) = xattrs.find_slot(Xattrs::TYPE_RECOVERY)
            .expect("slot not found");
        assert_eq!(index, 3);
        assert_eq!(value, "1:data:iv:hmac");
    }

    #[test]
    fn test_find_slot_no_match() {
        let mut slots = HashMap::new();
        slots.insert(0, "2:some:other:data".to_string());
        let xattrs = Xattrs { slots };
        assert!(xattrs.find_slot(Xattrs::TYPE_RECOVERY).is_none());
    }

    #[test]
    fn test_first_free_slot_empty() {
        let xattrs = Xattrs { slots: HashMap::new() };
        assert_eq!(xattrs.first_free_slot(), Some(0));
    }

    #[test]
    fn test_first_free_slot_gap() {
        let mut slots = HashMap::new();
        slots.insert(0, "1:a".to_string());
        slots.insert(1, "1:b".to_string());
        slots.insert(3, "1:c".to_string());
        slots.insert(11, "1:c".to_string());
        let xattrs = Xattrs { slots };
        assert_eq!(xattrs.first_free_slot(), Some(2));
    }

    #[test]
    fn test_first_free_slot_full() {
        let slots = (0..Xattrs::MAX_SLOTS).map(|i| (i, format!("1:slot{i}"))).collect();
        let xattrs = Xattrs { slots };
        assert!(xattrs.first_free_slot().is_none());
    }

    #[test]
    fn test_load_no_xattrs() {
        let tmpdir = tempdir::TempDir::new("xattrs").expect("tmpdir");
        let xattrs = Xattrs::load(tmpdir.path());
        assert!(xattrs.find_slot(Xattrs::TYPE_RECOVERY).is_none());
        assert_eq!(xattrs.first_free_slot(), Some(0));
    }
}
