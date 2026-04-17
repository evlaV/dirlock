/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

mod error;
mod linux;
use linux::*;

use nix::errno::Errno;
use num_enum::{FromPrimitive, TryFromPrimitive};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, hex::Hex};
use std::{
    fs::File,
    mem,
    os::fd::AsRawFd,
    path::Path,
};
use zeroize::Zeroize;

pub use error::{Error, PolicyIdParseError, Result};

/// The maximum size of an encryption key allowed by the kernel
pub const MAX_KEY_SIZE: usize = linux::FSCRYPT_MAX_KEY_SIZE;

/// The size of an fscrypt key descriptor (for v1 policies)
pub const KEY_DESCRIPTOR_SIZE: usize = linux::FSCRYPT_KEY_DESCRIPTOR_SIZE;

/// The size of an fscrypt key identifier (for v2 policies)
pub const KEY_IDENTIFIER_SIZE: usize = linux::FSCRYPT_KEY_IDENTIFIER_SIZE;

/// An 8-byte key descriptor for v1 fscrypt policies
#[derive(derive_more::Display)]
#[display("{}", hex::encode(_0))]
pub struct PolicyKeyDescriptor([u8; KEY_DESCRIPTOR_SIZE]);

/// A 16-byte key identifier for v2 fscrypt policies
#[serde_as]
#[derive(Default, PartialEq, Hash, Eq, Serialize, Deserialize, Clone, Debug, derive_more::Display)]
#[display("{}", hex::encode(_0))]
pub struct PolicyKeyId(
    #[serde_as(as = "Hex")]
    [u8; KEY_IDENTIFIER_SIZE]
);

impl std::str::FromStr for PolicyKeyId {
    type Err = PolicyIdParseError;
    /// Create a key identifier from a hex string
    fn from_str(s: &str) -> std::result::Result<Self, PolicyIdParseError> {
        let mut ret = PolicyKeyId::default();
        hex::decode_to_slice(s, &mut ret.0).map_err(|_| PolicyIdParseError)?;
        Ok(ret)
    }
}

impl PolicyKeyId {
    /// Calculates the fscrypt v2 key ID from an encryption key
    ///
    /// The key ID is calculated using unsalted HKDF-SHA512:
    /// <https://github.com/google/fscrypt/blob/v0.3.5/crypto/crypto.go#L183>
    ///
    /// Note that this function does not check that the key has a
    /// valid length, the kernel might reject it if it's too short or
    /// too long.
    pub fn new_from_key(key: &[u8]) -> Self {
        let info = b"fscrypt\x00\x01";
        let hkdf = hkdf::Hkdf::<sha2::Sha512>::new(None, key);
        let mut result = PolicyKeyId::default();
        hkdf.expand(info, &mut result.0).unwrap();
        result
    }
}


/// A fscrypt encryption policy
pub enum Policy {
    V1(PolicyV1),
    V2(PolicyV2),
    Unknown(u8)
}

/// A (deprecated) v1 encryption policy. They can be queried but are otherwise unsupported by this module.
pub struct PolicyV1 {
    pub contents_mode: EncryptionMode,
    pub filenames_mode: EncryptionMode,
    pub flags: PolicyFlags,
    pub keyid: PolicyKeyDescriptor
}

/// A v2 encryption policy. This is the one supported by this module.
pub struct PolicyV2 {
    pub contents_mode: EncryptionMode,
    pub filenames_mode: EncryptionMode,
    pub flags: PolicyFlags,
    pub log2_data_unit_size: u8,
    pub keyid: PolicyKeyId
}

impl From<&fscrypt_policy_v1> for PolicyV1 {
    fn from(p: &fscrypt_policy_v1) -> Self {
        Self {
            contents_mode: p.contents_encryption_mode.into(),
            filenames_mode: p.filenames_encryption_mode.into(),
            flags: p.flags.into(),
            keyid: PolicyKeyDescriptor(p.master_key_descriptor),
        }
    }
}

impl From<&fscrypt_policy_v2> for PolicyV2 {
    fn from(p: &fscrypt_policy_v2) -> Self {
        Self {
            contents_mode: p.contents_encryption_mode.into(),
            filenames_mode: p.filenames_encryption_mode.into(),
            flags: p.flags.into(),
            log2_data_unit_size: p.log2_data_unit_size,
            keyid: PolicyKeyId(p.master_key_identifier),
        }
    }
}

impl From<fscrypt_policy> for Policy {
    fn from(p: fscrypt_policy) -> Self {
        let version = unsafe { p.version };
        match version {
            FSCRYPT_POLICY_V1 => Policy::V1(unsafe { &p.v1 }.into()),
            FSCRYPT_POLICY_V2 => Policy::V2(unsafe { &p.v2 }.into()),
            x => Policy::Unknown(x)
        }
    }
}

#[derive(derive_more::Display)]
#[derive(TryFromPrimitive, Debug)]
#[repr(u8)]
pub enum PolicyFlagsPad {
    #[display("4")]
    Pad4 = FSCRYPT_POLICY_FLAGS_PAD_4,
    #[display("8")]
    Pad8 = FSCRYPT_POLICY_FLAGS_PAD_8,
    #[display("16")]
    Pad16 = FSCRYPT_POLICY_FLAGS_PAD_16,
    #[display("32")]
    Pad32 = FSCRYPT_POLICY_FLAGS_PAD_32,
}

bitflags::bitflags! {
    #[derive(derive_more::Display)]
    pub struct PolicyFlagsFlags: u8 {
        const DirectKey = FSCRYPT_POLICY_FLAG_DIRECT_KEY;
        const IvInoLblk64 = FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64;
        const IvInoLblk32 = FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32;
        const _ = !0; // Unnamed flag for unknown bits
    }
}

pub struct PolicyFlags {
    pub pad: PolicyFlagsPad,
    pub flags: PolicyFlagsFlags
}

impl From<u8> for PolicyFlags {
    fn from(v: u8) -> Self {
        Self {
            pad: PolicyFlagsPad::try_from(v & FSCRYPT_POLICY_FLAGS_PAD_MASK).unwrap(),
            flags: PolicyFlagsFlags::from_bits_truncate(v & !FSCRYPT_POLICY_FLAGS_PAD_MASK)
        }
    }
}

/// Value indicating what users are affected by a call to [remove_key()].
pub enum RemoveKeyUsers {
    CurrentUser,
    AllUsers
}

bitflags::bitflags! {
    /// Flags indicating the result of removing an encryption key from the kernel.
    ///
    /// **Note**: known flags are listed here, but other unknown bits are possible.
    pub struct RemovalStatusFlags: u32 {
        /// Set if some files are still in use.
        const FilesBusy = FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY;
        /// Set if the user's claim to the key was removed but not the key itself.
        const OtherUsers = FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS;
        const _ = !0; // Unnamed flag for unknown bits
    }
}

#[derive(TryFromPrimitive, Debug, PartialEq, derive_more::Display)]
#[display(rename_all = "kebab-case")]
#[repr(u32)]
/// Indicates the presence of an encryption key in the kernel (for a given filesystem).
pub enum KeyStatus {
    /// The key is absent from the filesystem.
    Absent = FSCRYPT_KEY_STATUS_ABSENT,
    /// The key is present in the filesystem.
    Present = FSCRYPT_KEY_STATUS_PRESENT,
    /// The removal has been initiated but some files are still in use.
    IncompletelyRemoved = FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED,
}

bitflags::bitflags! {
    /// Flags indicating the status of an encryption key in the kernel (see [get_key_status()]).
    ///
    /// **Note**: known flags are listed here, but other unknown bits are possible.
    pub struct KeyStatusFlags: u32 {
        const AddedBySelf = FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF;
        const _ = !0; // Unnamed flag for unknown bits
    }
}

#[derive(FromPrimitive, derive_more::Display)]
#[allow(non_camel_case_types)]
#[repr(u8)]
/// Encryption mode
pub enum EncryptionMode {
    AES_256_XTS = FSCRYPT_MODE_AES_256_XTS,
    AES_256_CTS = FSCRYPT_MODE_AES_256_CTS,
    AES_128_CBC = FSCRYPT_MODE_AES_128_CBC,
    AES_128_CTS = FSCRYPT_MODE_AES_128_CTS,
    SM4_XTS = FSCRYPT_MODE_SM4_XTS,
    SM4_CTS = FSCRYPT_MODE_SM4_CTS,
    Adiantum = FSCRYPT_MODE_ADIANTUM,
    AES_256_HCTR2 = FSCRYPT_MODE_AES_256_HCTR2,
    #[display("Unknown({_0})")]
    #[num_enum(catch_all)]
    Unknown(u8)
}

// This is fscrypt_add_key_arg with an additional 'raw' field
#[repr(C)]
struct fscrypt_add_key_arg_full {
    key_spec: fscrypt_key_specifier,
    raw_size: u32,
    key_id: u32,
    flags: u32,
    __reserved: [u32; 7],
    raw: [u8; MAX_KEY_SIZE]
}

impl Drop for fscrypt_add_key_arg_full {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

// These macros generate public functions so put them in their own module
mod ioctl {
    use super::linux;

    nix::ioctl_read!(fscrypt_set_policy, b'f', 19, linux::fscrypt_policy_v1);
    nix::ioctl_readwrite!(fscrypt_get_policy_ex, b'f', 22, linux::fscrypt_get_policy_ex_arg_ioctl);
    nix::ioctl_readwrite!(fscrypt_add_key, b'f', 23, linux::fscrypt_add_key_arg);
    nix::ioctl_readwrite!(fscrypt_remove_key, b'f', 24, linux::fscrypt_remove_key_arg);
    nix::ioctl_readwrite!(fscrypt_remove_key_all_users, b'f', 25, linux::fscrypt_remove_key_arg);
    nix::ioctl_readwrite!(fscrypt_get_key_status, b'f', 26, linux::fscrypt_get_key_status_arg);
}

/// Add an encryption key to the kernel for a given filesystem
pub fn add_key(dir: &Path, key: &[u8]) -> Result<PolicyKeyId> {
    if key.is_empty() || key.len() > MAX_KEY_SIZE {
        return Err(Error::InvalidPolicy);
    }

    let fd = File::open(dir)?;

    let mut arg : fscrypt_add_key_arg_full = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.raw_size = key.len() as u32;
    arg.key_id = 0;
    arg.flags = 0;
    arg.raw[..key.len()].copy_from_slice(key);

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg as *mut fscrypt_add_key_arg;
    match unsafe { ioctl::fscrypt_add_key(raw_fd, argptr) } {
        Err(x) => Err(Error::from(x)),
        _ => Ok(PolicyKeyId(unsafe { arg.key_spec.u.identifier }))
    }
}

/// Remove an encryption key from the kernel for a given filesystem
pub fn remove_key(dir: &Path, keyid: &PolicyKeyId, user: RemoveKeyUsers) -> Result<RemovalStatusFlags> {
    let fd = File::open(dir)?;

    let mut arg : fscrypt_remove_key_arg = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.key_spec.u.identifier = keyid.0;

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg;
    match user {
        RemoveKeyUsers::CurrentUser => unsafe { ioctl::fscrypt_remove_key(raw_fd, argptr) },
        RemoveKeyUsers::AllUsers => unsafe { ioctl::fscrypt_remove_key_all_users(raw_fd, argptr) },
    }.map_err(Error::from)?;

    Ok(RemovalStatusFlags::from_bits_truncate(arg.removal_status_flags))
}

/// Check if a directory is encrypted and return its [`Policy`] if that's the case.
///
/// Returns [`Error::NotSupported`] or [`Error::NotEnabled`] if the filesystem
/// does not support encryption or it is not enabled in the kernel.
///
/// If the kernel does not have encryption enabled but callers still want to know
/// if the directory is actually encrypted, they must handle it themselves
/// (e.g. by using `statx(2)` and checking the `STATX_ATTR_ENCRYPTED` attribute).
pub fn get_policy(dir: &Path) -> Result<Option<Policy>> {
    let fd = File::open(dir)?;

    let mut arg : fscrypt_get_policy_ex_arg = unsafe { mem::zeroed() };
    arg.policy_size = mem::size_of::<fscrypt_policy>() as u64;

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg as *mut fscrypt_get_policy_ex_arg_ioctl;
    match unsafe { ioctl::fscrypt_get_policy_ex(raw_fd, argptr) } {
        Err(Errno::ENODATA) => Ok(None),
        Err(x) => Err(Error::from(x)),
        Ok(_) => Ok(Some(arg.policy.into()))
    }
}

/// Enable encryption on a directory by setting a new [`Policy`]
pub fn set_policy(dir: &Path, keyid: &PolicyKeyId) -> Result<()> {
    let fd = File::open(dir)?;

    let mut arg = fscrypt_policy_v2 {
        version : FSCRYPT_POLICY_V2,
        contents_encryption_mode : FSCRYPT_MODE_AES_256_XTS,
        filenames_encryption_mode : FSCRYPT_MODE_AES_256_CTS,
        flags : FSCRYPT_POLICY_FLAGS_PAD_32,
        log2_data_unit_size: 0,
        __reserved : [0u8; 3],
        master_key_identifier : keyid.0
    };

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg as *mut fscrypt_policy_v1;
    match unsafe { ioctl::fscrypt_set_policy(raw_fd, argptr) } {
        Err(x) => Err(Error::from(x)),
        _ => Ok(())
    }
}

/// Check if a key with the given [`PolicyKeyId`] is loaded into the kernel for a given filesystem
pub fn get_key_status(dir: &Path, keyid: &PolicyKeyId) -> Result<(KeyStatus, KeyStatusFlags)> {
    let fd = File::open(dir)?;

    let mut arg : fscrypt_get_key_status_arg = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.key_spec.u.identifier = keyid.0;

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg;
    unsafe { ioctl::fscrypt_get_key_status(raw_fd, argptr) }.map_err(Error::from)?;

    let key_status = KeyStatus::try_from(arg.status)
        .map_err(|_| Error::UnknownKeyStatus(arg.status))?;

    Ok((key_status, KeyStatusFlags::from_bits_truncate(arg.status_flags)))
}



#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, rngs::OsRng};
    use std::path::PathBuf;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    const MNTPOINT_ENV_VAR : &str = "DIRLOCK_TEST_FS";

    /// Set the effective UID of the calling thread.
    ///
    /// We use the raw `setresuid` syscall because glibc's wrappers affect
    /// all threads, which would interfere with other tests running in parallel.
    /// The raw syscall only affects the calling thread.
    fn setresuid(uid: u32) {
        let ruid = -1i32 as libc::uid_t;
        let euid = uid as libc::uid_t;
        let suid = -1i32 as libc::uid_t;
        unsafe { libc::syscall(libc::SYS_setresuid, ruid, euid, suid) };
    }

    fn mntpoint() -> Option<PathBuf> {
        match std::env::var(MNTPOINT_ENV_VAR) {
            Ok(x) if x == "skip" => None,
            Ok(x) => {
                let p = PathBuf::from(x);
                assert!(p.exists(), "Test directory {p:?} does not exist");
                Some(p)
            },
            _ => panic!("Environment variable '{MNTPOINT_ENV_VAR}' not set"),
        }
    }

    fn random_key(size: usize) -> Vec<u8> {
        let mut key = vec![0u8; size];
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_add_key() -> Result<()> {
        fn do_test_key(key: &[u8], mntpoint: &Path) -> Result<()> {
            // Create a temporary directory and check that it's not encrypted
            let workdir = tempdir::TempDir::new_in(mntpoint, "encrypted")?;
            if get_policy(workdir.as_ref())?.is_some() {
                panic!("Found policy where none was expected")
            };

            // Calculate the expected key ID
            let id = PolicyKeyId::new_from_key(key);

            // Check that the key is absent from the filesystem
            let (status, _) = get_key_status(mntpoint, &id)?;
            assert_eq!(status, KeyStatus::Absent);

            // Add the key to the filesystem, check the ID and its presence
            let new_id = add_key(mntpoint, key)?;
            assert!(new_id == id);
            let (status, flags) = get_key_status(mntpoint, &id)?;
            assert_eq!(status, KeyStatus::Present);
            assert!(flags.contains(KeyStatusFlags::AddedBySelf));

            // Encrypt the directory and check the new status
            set_policy(workdir.as_ref(), &id)?;
            match get_policy(workdir.as_ref())? {
                Some(Policy::V2(x)) if x.keyid == id => (),
                _ => panic!("Could not find the expected policy")
            };

            // Remove the key from the filesystem and check that it's absent
            remove_key(mntpoint, &id, RemoveKeyUsers::CurrentUser)?;
            let (status, _) = get_key_status(mntpoint, &id)?;
            assert_eq!(status, KeyStatus::Absent);

            // Check again that the directory is still encrypted
            match get_policy(workdir.as_ref())? {
                Some(Policy::V2(x)) if x.keyid == id => Ok(()),
                _ => panic!("Could not find the expected policy")
            }
        }

        let Some(mntpoint) = mntpoint() else { return Ok(()) };

        // Test keys of different sizes
        for i in 0..5 {
            let key = random_key(MAX_KEY_SIZE - 8 * i);
            do_test_key(&key, &mntpoint)?;
        }

        Ok(())
    }

    #[test]
    fn test_invalid_policy() -> Result<()> {
        let Some(mntpoint) = mntpoint() else { return Ok(()) };
        let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;
        let fd = File::open(workdir.path())?;

        // Use the raw ioctl because our set_policy() function never provides
        // invalid values here.
        let mut arg = fscrypt_policy_v2 {
            version: FSCRYPT_POLICY_V2,
            contents_encryption_mode: 0xFF, // invalid
            filenames_encryption_mode: FSCRYPT_MODE_AES_256_CTS,
            flags: FSCRYPT_POLICY_FLAGS_PAD_32,
            log2_data_unit_size: 0,
            __reserved: [0u8; 3],
            master_key_identifier: [0u8; KEY_IDENTIFIER_SIZE],
        };
        let result = unsafe {
            ioctl::fscrypt_set_policy(fd.as_raw_fd(), &raw mut arg as *mut fscrypt_policy_v1)
        };
        assert!(matches!(Error::from(result.unwrap_err()), Error::InvalidPolicy));
        Ok(())
    }

    #[test]
    fn test_policy_too_large() -> Result<()> {
        let Some(mntpoint) = mntpoint() else { return Ok(()) };
        let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;
        let fd = File::open(workdir.path())?;

        // Encrypt the directory with a new key
        let id = add_key(&mntpoint, &random_key(MAX_KEY_SIZE))?;
        set_policy(workdir.path(), &id)?;
        remove_key(&mntpoint, &id, RemoveKeyUsers::CurrentUser)?;

        // Get the policy in a buffer that is too small.
        // Use the ioctl because get_policy() never uses invalid values.
        let mut arg : fscrypt_get_policy_ex_arg = unsafe { mem::zeroed() };
        arg.policy_size = 1u64;
        let argptr = &raw mut arg as *mut fscrypt_get_policy_ex_arg_ioctl;
        let result = unsafe {
            ioctl::fscrypt_get_policy_ex(fd.as_raw_fd(), argptr)
        };
        assert!(matches!(Error::from(result.unwrap_err()), Error::PolicyTooLarge));

        Ok(())
    }

    #[test]
    fn test_already_encrypted() -> Result<()> {
        let Some(mntpoint) = mntpoint() else { return Ok(()) };
        let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;

        let id1 = add_key(&mntpoint, &random_key(MAX_KEY_SIZE))?;
        let id2 = add_key(&mntpoint, &random_key(MAX_KEY_SIZE))?;
        set_policy(workdir.path(), &id1)?;
        assert!(matches!(set_policy(workdir.path(), &id2), Err(Error::AlreadyEncrypted)));

        remove_key(&mntpoint, &id1, RemoveKeyUsers::CurrentUser)?;
        remove_key(&mntpoint, &id2, RemoveKeyUsers::CurrentUser)?;
        Ok(())
    }

    #[test]
    fn test_permission_denied() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let Some(mntpoint) = mntpoint() else { return Ok(()) };

        // This tests requires root: it creates a directory owned by root
        // and then drops to an unprivileged uid that doesn't own it.
        if ! nix::unistd::getuid().is_root() {
            return Ok(());
        }

        let id = PolicyKeyId::new_from_key(&random_key(MAX_KEY_SIZE));

        // Directory owned by root, accessible to other users
        let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;
        std::fs::set_permissions(workdir.path(), std::fs::Permissions::from_mode(0o777))?;

        // Drop privileges and try to set the key
        setresuid(65534);
        let result = set_policy(workdir.path(), &id);
        setresuid(0);

        assert!(matches!(result, Err(Error::PermissionDenied)));
        Ok(())
    }

    #[test]
    fn test_key_not_found() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let Some(mntpoint) = mntpoint() else { return Ok(()) };

        let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;
        std::fs::set_permissions(workdir.path(), std::fs::Permissions::from_mode(0o755))?;

        let id = PolicyKeyId::new_from_key(&random_key(MAX_KEY_SIZE));

        // KeyNotFound can only be returned if the user owns the directory
        // *and* lacks the CAP_FOWNER capability.
        // So when running as root, chown the directory to the 'nobody' user
        // and drop privileges.
        let is_root = nix::unistd::getuid().is_root();
        if is_root {
            let nobody = nix::unistd::Uid::from_raw(65534);
            nix::unistd::chown(workdir.path(), Some(nobody), None)?;
            setresuid(65534);
        }
        let result = set_policy(workdir.path(), &id);
        if is_root {
            setresuid(0);
        }

        assert!(matches!(result, Err(Error::KeyNotFound)));
        Ok(())
    }

    #[test]
    fn test_not_a_directory() -> Result<()> {
        let Some(mntpoint) = mntpoint() else { return Ok(()) };

        let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;
        let file = workdir.path().join("file");
        std::fs::write(&file, b"")?;

        let id = PolicyKeyId::new_from_key(&random_key(MAX_KEY_SIZE));
        assert!(matches!(set_policy(&file, &id), Err(Error::NotADirectory)));
        Ok(())
    }

    #[test]
    fn test_directory_not_empty() -> Result<()> {
        let Some(mntpoint) = mntpoint() else { return Ok(()) };

        let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;
        std::fs::write(workdir.path().join("file"), b"")?;

        let id = PolicyKeyId::new_from_key(&random_key(MAX_KEY_SIZE));
        assert!(matches!(set_policy(workdir.path(), &id), Err(Error::DirectoryNotEmpty)));
        Ok(())
    }

    #[test]
    fn test_io_error() -> Result<()> {
        let result = get_policy(Path::new("/nonexistent"));
        assert!(matches!(result, Err(Error::Io(_))));
        Ok(())
    }

    #[test]
    fn test_no_encryption_supported() -> Result<()> {
        let mntpoint = std::path::Path::new("/tmp");
        let workdir = tempdir::TempDir::new_in(mntpoint, "encrypted")?;

        // We're using /tmp in this test instead of $DIRLOCK_TEST_FS.
        // We expect it to be a tmpfs so it should return NotSupported.
        assert!(
            matches!(get_policy(workdir.path()), Err(Error::NotSupported)),
            "This test requires /tmp to be a tmpfs"
        );

        let key = random_key(MAX_KEY_SIZE);
        let id = PolicyKeyId::new_from_key(&key);

        assert!(matches!(add_key(mntpoint, &key), Err(Error::NotSupported)));
        assert!(matches!(set_policy(workdir.path(), &id), Err(Error::NotSupported)));
        assert!(matches!(get_key_status(mntpoint, &id), Err(Error::NotSupported)));
        assert!(matches!(remove_key(mntpoint, &id, RemoveKeyUsers::CurrentUser), Err(Error::NotSupported)));

        Ok(())
    }
}
