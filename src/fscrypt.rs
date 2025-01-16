
use anyhow::{bail, ensure, Result};
use std::os::fd::AsRawFd;
use nix::errno::Errno;
use num_enum::{FromPrimitive, TryFromPrimitive};
use rand::RngCore;
use std::mem;
use std::path::Path;
use crate::linux::*;

/// An 8-byte key descriptor for v1 fscrypt policies
pub struct KeyDescriptor([u8; FSCRYPT_KEY_DESCRIPTOR_SIZE]);

impl std::fmt::Display for KeyDescriptor {
    /// Display a KeyDescriptor in hex format
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}


/// A 16-byte key identifier for v2 fscrypt policies
#[derive(Default, PartialEq)]
pub struct KeyIdentifier([u8; FSCRYPT_KEY_IDENTIFIER_SIZE]);

impl std::fmt::Display for KeyIdentifier {
    /// Display a key identifier in hex format
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl TryFrom<&str> for KeyIdentifier {
    type Error = anyhow::Error;
    /// Create a key identifier from an hex string
    fn try_from(s: &str) -> Result<Self> {
        let mut ret = KeyIdentifier::default();
        hex::decode_to_slice(s, &mut ret.0)?;
        Ok(ret)
    }
}


/// A raw master encryption key. Meant to be loaded directly into the kernel.
pub struct RawKey(pub [u8; FSCRYPT_MAX_KEY_SIZE]);

impl Default for RawKey {
    /// Returns a key containing only zeroes.
    fn default() -> Self {
        Self([0u8; FSCRYPT_MAX_KEY_SIZE])
    }
}

impl Drop for RawKey {
    /// Wipes the key safely from memory on drop.
    fn drop(&mut self) {
        unsafe { zeroize::zeroize_flat_type(self) }
    }
}

impl RawKey {
    /// Generates a new, random key
    pub fn new_random() -> Self {
        let mut rng = rand::thread_rng();
        let mut key = RawKey::default();
        rng.try_fill_bytes(&mut key.0).unwrap();
        key
    }

    /// Generates a new key, reading the data from a given source
    pub fn new_from_reader(r: &mut impl std::io::Read) -> Result<Self> {
        let mut key = RawKey::default();
        let len = r.read(&mut key.0)?;
        ensure!(len == key.0.len(), "Expected {} bytes when reading key, got {len}", key.0.len());
        Ok(key)
    }

    /// Calculates the fscrypt v2 key ID for this key
    ///
    /// The key ID is calculated using unsalted HKDF-SHA512:
    /// <https://github.com/google/fscrypt/blob/v0.3.5/crypto/crypto.go#L183>
    pub fn get_id(&self) -> KeyIdentifier {
        let info = b"fscrypt\x00\x01";
        let hkdf = hkdf::Hkdf::<sha2::Sha512>::new(None, &self.0);
        let mut result = KeyIdentifier::default();
        hkdf.expand(info, &mut result.0).unwrap();
        result
    }
}


pub enum Policy {
    V1(PolicyV1),
    V2(PolicyV2),
    Unknown(u8)
}

pub struct PolicyV1 {
    pub contents_encryption_mode : EncryptionMode,
    pub filenames_encryption_mode : EncryptionMode,
    pub flags : PolicyFlags,
    pub master_key_descriptor : KeyDescriptor
}

pub struct PolicyV2 {
    pub contents_encryption_mode : EncryptionMode,
    pub filenames_encryption_mode : EncryptionMode,
    pub flags : PolicyFlags,
    pub master_key_identifier : KeyIdentifier
}

impl From<&fscrypt_policy_v1> for PolicyV1 {
    fn from(p: &fscrypt_policy_v1) -> Self {
        Self {
            contents_encryption_mode: p.contents_encryption_mode.into(),
            filenames_encryption_mode: p.filenames_encryption_mode.into(),
            flags: p.flags.into(),
            master_key_descriptor: KeyDescriptor(p.master_key_descriptor),
        }
    }
}

impl From<&fscrypt_policy_v2> for PolicyV2 {
    fn from(p: &fscrypt_policy_v2) -> Self {
        Self {
            contents_encryption_mode: p.contents_encryption_mode.into(),
            filenames_encryption_mode: p.filenames_encryption_mode.into(),
            flags: p.flags.into(),
            master_key_identifier: KeyIdentifier(p.master_key_identifier),
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

pub enum RemoveKeyUsers {
    CurrentUser,
    AllUsers
}

bitflags::bitflags! {
    pub struct RemovalStatusFlags: u32 {
        const FilesBusy = FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY;
        const OtherUsers = FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS;
        const _ = !0; // Unnamed flag for unknown bits
    }
}

#[derive(TryFromPrimitive, Debug)]
#[repr(u32)]
pub enum KeyStatus {
    Absent = FSCRYPT_KEY_STATUS_ABSENT,
    Present = FSCRYPT_KEY_STATUS_PRESENT,
    IncompletelyRemoved = FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED,
}

bitflags::bitflags! {
    pub struct KeyStatusFlags: u32 {
        const AddedBySelf = FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF;
        const _ = !0; // Unnamed flag for unknown bits
    }
}

#[derive(FromPrimitive)]
#[repr(u8)]
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
pub struct fscrypt_add_key_arg_full {
    key_spec: fscrypt_key_specifier,
    raw_size: u32,
    key_id: u32,
    __reserved: [u32; 8],
    raw: [u8; FSCRYPT_MAX_KEY_SIZE]
}

impl Drop for fscrypt_add_key_arg_full {
    fn drop(&mut self) {
        unsafe {
            zeroize::zeroize_flat_type(self)
        }
    }
}

nix::ioctl_read!(fscrypt_set_policy, b'f', 19, fscrypt_policy_v1);
nix::ioctl_readwrite!(fscrypt_get_policy_ex, b'f', 22, fscrypt_get_policy_ex_arg_ioctl);
nix::ioctl_readwrite!(fscrypt_add_key, b'f', 23, fscrypt_add_key_arg);
nix::ioctl_readwrite!(fscrypt_remove_key, b'f', 24, fscrypt_remove_key_arg);
nix::ioctl_readwrite!(fscrypt_remove_key_all_users, b'f', 25, fscrypt_remove_key_arg);
nix::ioctl_readwrite!(fscrypt_get_key_status, b'f', 26, fscrypt_get_key_status_arg);

pub fn add_key(dir: &Path, key: &RawKey) -> Result<KeyIdentifier> {
    let fd = std::fs::File::open(dir)?;

    let mut arg : fscrypt_add_key_arg_full = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.raw_size = key.0.len() as u32;
    arg.key_id = 0;
    arg.raw = key.0;

    let raw_fd = fd.as_raw_fd();
    let argptr = std::ptr::addr_of_mut!(arg) as *mut fscrypt_add_key_arg;
    match unsafe { fscrypt_add_key(raw_fd, argptr) } {
        Err(x) => Err(x.into()),
        _ => Ok(KeyIdentifier(unsafe { arg.key_spec.u.identifier }))
    }
}

pub fn remove_key(dir: &Path, keyid: &KeyIdentifier, users: RemoveKeyUsers) -> Result<RemovalStatusFlags> {
    let fd = std::fs::File::open(dir)?;

    let mut arg : fscrypt_remove_key_arg = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.key_spec.u.identifier = keyid.0;

    let raw_fd = fd.as_raw_fd();
    let argptr = std::ptr::addr_of_mut!(arg);
    if let Err(x) = match users {
        RemoveKeyUsers::CurrentUser => unsafe { fscrypt_remove_key(raw_fd, argptr) },
        RemoveKeyUsers::AllUsers => unsafe { fscrypt_remove_key_all_users(raw_fd, argptr) },
    } {
        return Err(x.into());
    }

    Ok(RemovalStatusFlags::from_bits_truncate(arg.removal_status_flags))
}

pub fn get_policy(dir: &Path) -> Result<Option<Policy>> {
    let fd = std::fs::File::open(dir)?;

    let mut arg : fscrypt_get_policy_ex_arg = unsafe { mem::zeroed() };
    arg.policy_size = mem::size_of::<fscrypt_policy>() as u64;

    let raw_fd = fd.as_raw_fd();
    let argptr = std::ptr::addr_of_mut!(arg) as *mut fscrypt_get_policy_ex_arg_ioctl;
    match unsafe { fscrypt_get_policy_ex(raw_fd, argptr) } {
        Err(Errno::ENODATA) => Ok(None),
        Err(x) => Err(x.into()),
        Ok(_) => Ok(Some(arg.policy.into()))
    }
}

pub fn set_policy(dir: &Path, keyid: &KeyIdentifier) -> Result<()> {
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
    let argptr = std::ptr::addr_of_mut!(arg) as *mut fscrypt_policy_v1;
    match unsafe { fscrypt_set_policy(raw_fd, argptr) } {
        Err(x) => Err(x.into()),
        _ => Ok(())
    }
}

pub fn get_key_status(dir: &Path, keyid: &KeyIdentifier) -> Result<(KeyStatus, KeyStatusFlags)> {
    let fd = std::fs::File::open(dir)?;

    let mut arg : fscrypt_get_key_status_arg = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.key_spec.u.identifier = keyid.0;

    let raw_fd = fd.as_raw_fd();
    let argptr = std::ptr::addr_of_mut!(arg);
    if let Err(x) = unsafe { fscrypt_get_key_status(raw_fd, argptr) } {
        return Err(x.into());
    };

    let Ok(key_status) = KeyStatus::try_from(arg.status) else {
        bail!("Unknown key status: {}", arg.status);
    };

    Ok((key_status, KeyStatusFlags::from_bits_truncate(arg.status_flags)))
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
            let key = RawKey::new_random();
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
                Some(Policy::V2(x)) if x.master_key_identifier == id => (),
                _ => panic!("Could not find the expected policy")
            };

            // Remove the key from the filesystem and check that it's absent
            remove_key(&mntpoint, &id, RemoveKeyUsers::CurrentUser)?;
            let (status, _) = get_key_status(&mntpoint, &id)?;
            assert_eq!(status, KeyStatus::Absent);

            // Check again that the directory is still encrypted
            match get_policy(workdir.as_ref())? {
                Some(Policy::V2(x)) if x.master_key_identifier == id => (),
                _ => panic!("Could not find the expected policy")
            };
        };

        Ok(())
    }

    #[test]
    fn test_no_encryption_supported() -> Result<()> {
        let mntpoint = std::path::Path::new("/tmp");
        let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;

        let key = RawKey::new_random();
        let id = key.get_id();

        assert!(add_key(&mntpoint, &key).is_err());
        assert!(set_policy(workdir.path(), &id).is_err());
        assert!(get_policy(workdir.path()).is_err());
        assert!(get_key_status(&mntpoint, &id).is_err());
        assert!(remove_key(&mntpoint, &id, RemoveKeyUsers::CurrentUser).is_err());

        Ok(())
    }
}
