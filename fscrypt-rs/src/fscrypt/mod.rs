
mod linux;
use linux::*;

use anyhow::{bail, ensure, Result};
use nix::errno::Errno;
use num_enum::{FromPrimitive, TryFromPrimitive};
use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, hex::Hex};
use std::{
    mem,
    os::{
        fd::AsRawFd,
        linux::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

/// All our keys use the maximum length allowed by fscrypt
pub(crate) const POLICY_KEY_LEN: usize = FSCRYPT_MAX_KEY_SIZE;

/// An 8-byte key descriptor for v1 fscrypt policies
#[derive(derive_more::Display)]
#[display("{}", hex::encode(_0))]
pub struct PolicyKeyDescriptor([u8; FSCRYPT_KEY_DESCRIPTOR_SIZE]);

/// A 16-byte key identifier for v2 fscrypt policies
#[serde_as]
#[derive(Default, PartialEq, Hash, Eq, Serialize, Deserialize, Clone, Debug, derive_more::Display)]
#[display("{}", hex::encode(_0))]
pub struct PolicyKeyId(
    #[serde_as(as = "Hex")]
    [u8; FSCRYPT_KEY_IDENTIFIER_SIZE]
);

impl TryFrom<&str> for PolicyKeyId {
    type Error = anyhow::Error;
    /// Create a key identifier from an hex string
    fn try_from(s: &str) -> Result<Self> {
        let mut ret = PolicyKeyId::default();
        hex::decode_to_slice(s, &mut ret.0)?;
        Ok(ret)
    }
}


/// A raw master encryption key, meant to be added to the kernel for a specific filesystem.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct PolicyKey([u8; POLICY_KEY_LEN]);

impl AsRef<[u8; POLICY_KEY_LEN]> for PolicyKey {
    fn as_ref(&self) -> &[u8; POLICY_KEY_LEN] {
        &self.0
    }
}

impl AsMut<[u8; POLICY_KEY_LEN]> for PolicyKey {
    fn as_mut(&mut self) -> &mut [u8; POLICY_KEY_LEN] {
        &mut self.0
    }
}

impl From<&[u8; POLICY_KEY_LEN]> for PolicyKey {
    fn from(src: &[u8; POLICY_KEY_LEN]) -> Self {
        PolicyKey(*src)
    }
}

impl Default for PolicyKey {
    /// Returns a key containing only zeroes.
    fn default() -> Self {
        Self([0u8; POLICY_KEY_LEN])
    }
}

impl PolicyKey {
    /// Generates a new, random key
    pub fn new_random() -> Self {
        let mut key = PolicyKey::default();
        OsRng.fill_bytes(&mut key.0);
        key
    }

    /// Generates a new key, reading the data from a given source
    pub fn new_from_reader(r: &mut impl std::io::Read) -> Result<Self> {
        let mut key = PolicyKey::default();
        let len = r.read(&mut key.0)?;
        ensure!(len == key.0.len(), "Expected {} bytes when reading key, got {len}", key.0.len());
        Ok(key)
    }

    /// Calculates the fscrypt v2 key ID for this key
    ///
    /// The key ID is calculated using unsalted HKDF-SHA512:
    /// <https://github.com/google/fscrypt/blob/v0.3.5/crypto/crypto.go#L183>
    pub fn get_id(&self) -> PolicyKeyId {
        let info = b"fscrypt\x00\x01";
        let hkdf = hkdf::Hkdf::<sha2::Sha512>::new(None, &self.0);
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

/// A (deprecated) v1 encryption policy. They can be queried but are otherwise unsupported by this tool.
pub struct PolicyV1 {
    pub contents_mode: EncryptionMode,
    pub filenames_mode: EncryptionMode,
    pub flags: PolicyFlags,
    pub keyid: PolicyKeyDescriptor
}

/// A v2 encryption policy. This is the one supported by this tool.
pub struct PolicyV2 {
    pub contents_mode: EncryptionMode,
    pub filenames_mode: EncryptionMode,
    pub flags: PolicyFlags,
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

#[derive(TryFromPrimitive, Debug)]
#[repr(u8)]
pub enum PolicyFlagsPad {
    Pad4 = FSCRYPT_POLICY_FLAGS_PAD_4,
    Pad8 = FSCRYPT_POLICY_FLAGS_PAD_8,
    Pad16 = FSCRYPT_POLICY_FLAGS_PAD_16,
    Pad32 = FSCRYPT_POLICY_FLAGS_PAD_32,
}

bitflags::bitflags! {
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
    /// Flags indicating the result of removing a [`PolicyKey`] from the kernel.
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

#[derive(TryFromPrimitive, Debug, PartialEq)]
#[repr(u32)]
/// Indicates the presence of a [`PolicyKey`] in the kernel (for a given filesystem).
pub enum KeyStatus {
    /// The key is absent from the filesystem.
    Absent = FSCRYPT_KEY_STATUS_ABSENT,
    /// The key is present in the filesystem.
    Present = FSCRYPT_KEY_STATUS_PRESENT,
    /// The removal has been initiated but some files are still in use.
    IncompletelyRemoved = FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED,
}

bitflags::bitflags! {
    /// Flags indicating the status of a [`PolicyKey`] in the kernel (see [get_key_status()]).
    ///
    /// **Note**: known flags are listed here, but other unknown bits are possible.
    pub struct KeyStatusFlags: u32 {
        const AddedBySelf = FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF;
        const _ = !0; // Unnamed flag for unknown bits
    }
}

#[derive(FromPrimitive)]
#[repr(u8)]
/// Encryption mode
pub enum EncryptionMode {
    Invalid = FS_ENCRYPTION_MODE_INVALID,
    AES256XTS = FS_ENCRYPTION_MODE_AES_256_XTS,
    AES256GCM = FS_ENCRYPTION_MODE_AES_256_GCM,
    AES256CBC = FS_ENCRYPTION_MODE_AES_256_CBC,
    AES256CTS = FS_ENCRYPTION_MODE_AES_256_CTS,
    AES128CBC = FS_ENCRYPTION_MODE_AES_128_CBC,
    AES128CTS = FS_ENCRYPTION_MODE_AES_128_CTS,
    SPECK128_256XTS = FS_ENCRYPTION_MODE_SPECK128_256_XTS,
    SPECK128_256CTS = FS_ENCRYPTION_MODE_SPECK128_256_CTS,
    Adiantum = FS_ENCRYPTION_MODE_ADIANTUM,
    #[num_enum(catch_all)]
    Unknown(u8)
}

// This is fscrypt_add_key_arg with an additional 'raw' field
#[repr(C)]
struct fscrypt_add_key_arg_full {
    key_spec: fscrypt_key_specifier,
    raw_size: u32,
    key_id: u32,
    __reserved: [u32; 8],
    raw: [u8; POLICY_KEY_LEN]
}

impl Drop for fscrypt_add_key_arg_full {
    fn drop(&mut self) {
        unsafe {
            zeroize::zeroize_flat_type(self)
        }
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

/// Add a [`PolicyKey`] to the kernel for a given filesystem
pub fn add_key(dir: &Path, key: &PolicyKey) -> Result<PolicyKeyId> {
    let fd = std::fs::File::open(get_mountpoint(dir)?)?;

    let mut arg : fscrypt_add_key_arg_full = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.raw_size = key.as_ref().len() as u32;
    arg.key_id = 0;
    arg.raw = *key.as_ref();

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg as *mut fscrypt_add_key_arg;
    match unsafe { ioctl::fscrypt_add_key(raw_fd, argptr) } {
        Err(x) => Err(describe_error(x)),
        _ => Ok(PolicyKeyId(unsafe { arg.key_spec.u.identifier }))
    }
}

/// Remove a [`PolicyKey`] from the kernel for a given filesystem
pub fn remove_key(dir: &Path, keyid: &PolicyKeyId, users: RemoveKeyUsers) -> Result<RemovalStatusFlags> {
    let fd = std::fs::File::open(get_mountpoint(dir)?)?;

    let mut arg : fscrypt_remove_key_arg = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.key_spec.u.identifier = keyid.0;

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg;
    if let Err(x) = match users {
        RemoveKeyUsers::CurrentUser => unsafe { ioctl::fscrypt_remove_key(raw_fd, argptr) },
        RemoveKeyUsers::AllUsers => unsafe { ioctl::fscrypt_remove_key_all_users(raw_fd, argptr) },
    } {
        return Err(describe_error(x));
    }

    Ok(RemovalStatusFlags::from_bits_truncate(arg.removal_status_flags))
}

/// Check if a directory is encrypted and return its [`Policy`] if that's the case
pub fn get_policy(dir: &Path) -> Result<Option<Policy>> {
    let fd = std::fs::File::open(dir)?;

    let mut arg : fscrypt_get_policy_ex_arg = unsafe { mem::zeroed() };
    arg.policy_size = mem::size_of::<fscrypt_policy>() as u64;

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg as *mut fscrypt_get_policy_ex_arg_ioctl;
    match unsafe { ioctl::fscrypt_get_policy_ex(raw_fd, argptr) } {
        Err(Errno::ENODATA) => Ok(None),
        Err(x) => Err(describe_error(x)),
        Ok(_) => Ok(Some(arg.policy.into()))
    }
}

/// Enable encryption on a directory by setting a new [`Policy`]
pub fn set_policy(dir: &Path, keyid: &PolicyKeyId) -> Result<()> {
    let fd = std::fs::File::open(dir)?;

    let mut arg = fscrypt_policy_v2 {
        version : FSCRYPT_POLICY_V2,
        contents_encryption_mode : FSCRYPT_MODE_AES_256_XTS,
        filenames_encryption_mode : FSCRYPT_MODE_AES_256_CTS,
        flags : FSCRYPT_POLICY_FLAGS_PAD_32,
        __reserved : [0u8; 4],
        master_key_identifier : keyid.0
    };

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg as *mut fscrypt_policy_v1;
    match unsafe { ioctl::fscrypt_set_policy(raw_fd, argptr) } {
        Err(x) => Err(describe_error(x)),
        _ => Ok(())
    }
}

/// Check if a [`PolicyKey`] is loaded into the kernel for a given filesystem
pub fn get_key_status(dir: &Path, keyid: &PolicyKeyId) -> Result<(KeyStatus, KeyStatusFlags)> {
    let fd = std::fs::File::open(get_mountpoint(dir)?)?;

    let mut arg : fscrypt_get_key_status_arg = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.key_spec.u.identifier = keyid.0;

    let raw_fd = fd.as_raw_fd();
    let argptr = &raw mut arg;
    if let Err(x) = unsafe { ioctl::fscrypt_get_key_status(raw_fd, argptr) } {
        return Err(describe_error(x));
    };

    let Ok(key_status) = KeyStatus::try_from(arg.status) else {
        bail!("Unknown key status: {}", arg.status);
    };

    Ok((key_status, KeyStatusFlags::from_bits_truncate(arg.status_flags)))
}


/// Get the mount point of the file system that contains `dir`
fn get_mountpoint(dir: &Path) -> Result<PathBuf> {
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

/// Describe the errors returned by the fscrypt ioctls
fn describe_error(err: Errno) -> anyhow::Error {
    let msg = match err {
        Errno::EEXIST => "Already encrypted with a different key",
        Errno::EINVAL => "Invalid or unsupported encryption policy",
        Errno::ENOTTY => "This filesystem does not support encryption",
        Errno::EOPNOTSUPP => "Encryption not enabled in the filesystem or in the kernel",
        Errno::EPERM => "This directory cannot be encrypted (is it the root of that filesystem?)",
        e => e.desc(), // The default message is fine for everything else
    };
    anyhow::anyhow!(msg)
}

#[cfg(test)]
mod tests {
    use crate::fscrypt::*;
    use anyhow::{bail, Result};
    use std::env;

    const MNTPOINT_ENV_VAR : &str = "FSCRYPT_RS_TEST_FS";

    #[test]
    fn test_add_key() -> Result<()> {
        let mntpoint = match env::var(MNTPOINT_ENV_VAR) {
            Ok(x) if x == "skip" => return Ok(()),
            Ok(x) => std::path::PathBuf::from(&x),
            _ => bail!("Environment variable '{MNTPOINT_ENV_VAR}' not set"),
        };

        for _ in 0..5 {
            // Create a temporary directory and check that it's not encrypted
            let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;
            if let Some(_) = get_policy(workdir.as_ref())? {
                panic!("Found policy where none was expected")
            };

            // Generate a random key and calculate its expected ID
            let key = PolicyKey::new_random();
            let id = key.get_id();

            // Check that the key is absent from the filesystem
            let (status, _) = get_key_status(&mntpoint, &id)?;
            assert_eq!(status, KeyStatus::Absent);

            // Add the key to the filesystem, check the ID and its presence
            let new_id = add_key(&mntpoint, &key)?;
            assert!(new_id == id);
            let (status, flags) = get_key_status(&mntpoint, &id)?;
            assert_eq!(status, KeyStatus::Present);
            assert!(flags.contains(KeyStatusFlags::AddedBySelf));

            // Encrypt the directory and check the new status
            set_policy(workdir.as_ref(), &id)?;
            match get_policy(workdir.as_ref())? {
                Some(Policy::V2(x)) if x.keyid == id => (),
                _ => panic!("Could not find the expected policy")
            };

            // Remove the key from the filesystem and check that it's absent
            remove_key(&mntpoint, &id, RemoveKeyUsers::CurrentUser)?;
            let (status, _) = get_key_status(&mntpoint, &id)?;
            assert_eq!(status, KeyStatus::Absent);

            // Check again that the directory is still encrypted
            match get_policy(workdir.as_ref())? {
                Some(Policy::V2(x)) if x.keyid == id => (),
                _ => panic!("Could not find the expected policy")
            };
        };

        Ok(())
    }

    #[test]
    fn test_no_encryption_supported() -> Result<()> {
        let mntpoint = std::path::Path::new("/tmp");
        let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;

        let key = PolicyKey::new_random();
        let id = key.get_id();

        assert!(add_key(&mntpoint, &key).is_err());
        assert!(set_policy(workdir.path(), &id).is_err());
        assert!(get_policy(workdir.path()).is_err());
        assert!(get_key_status(&mntpoint, &id).is_err());
        assert!(remove_key(&mntpoint, &id, RemoveKeyUsers::CurrentUser).is_err());

        Ok(())
    }
}
