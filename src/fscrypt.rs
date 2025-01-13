
use anyhow::{anyhow, bail, Result};
use std::os::fd::AsRawFd;
use nix::errno::Errno;
use num_enum::{FromPrimitive, TryFromPrimitive};
use std::mem;
use std::path::Path;
use crate::linux::*;

type KeyDescriptor = [u8; FSCRYPT_KEY_DESCRIPTOR_SIZE];
type KeyIdentifier = [u8; FSCRYPT_KEY_IDENTIFIER_SIZE];
type RawKey = [u8; FSCRYPT_MAX_KEY_SIZE];

pub enum Policy {
    V1(PolicyV1),
    V2(PolicyV2),
    Unknown(u8)
}

#[allow(dead_code)]
pub struct PolicyV1 {
    pub contents_encryption_mode : EncryptionMode,
    pub filenames_encryption_mode : EncryptionMode,
    pub flags : PolicyFlags,
    pub master_key_descriptor : KeyDescriptor
}

#[allow(dead_code)]
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
            master_key_descriptor: p.master_key_descriptor,
        }
    }
}

impl From<&fscrypt_policy_v2> for PolicyV2 {
    fn from(p: &fscrypt_policy_v2) -> Self {
        Self {
            contents_encryption_mode: p.contents_encryption_mode.into(),
            filenames_encryption_mode: p.filenames_encryption_mode.into(),
            flags: p.flags.into(),
            master_key_identifier: p.master_key_identifier,
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

#[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    raw: RawKey
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

#[allow(dead_code)]
pub fn get_key_id(key: &[u8]) -> Result<KeyIdentifier> {
    let key : &RawKey = key.try_into().map_err(|_| anyhow!("Invalid key length"))?;
    // The key ID is calculated using unsalted HKDF-SHA512
    // https://github.com/google/fscrypt/blob/v0.3.5/crypto/crypto.go#L183
    let info = b"fscrypt\x00\x01";
    let hkdf = hkdf::Hkdf::<sha2::Sha512>::new(None, key);
    let mut result = KeyIdentifier::default();
    hkdf.expand(info, &mut result).unwrap();
    Ok(result)
}

pub fn add_key(dir: &Path, key: &[u8]) -> Result<KeyIdentifier> {
    let key : &RawKey = key.try_into().map_err(|_| anyhow!("Invalid key length"))?;
    let fd = std::fs::File::open(dir)?;

    let mut arg : fscrypt_add_key_arg_full = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.raw_size = key.len() as u32;
    arg.key_id = 0;
    arg.raw = *key;

    let raw_fd = fd.as_raw_fd();
    let argptr = std::ptr::addr_of_mut!(arg) as *mut fscrypt_add_key_arg;
    match unsafe { fscrypt_add_key(raw_fd, argptr) } {
        Err(x) => Err(x.into()),
        _ => Ok(unsafe { arg.key_spec.u.identifier })
    }
}

pub fn remove_key(dir: &Path, keyid: &[u8], users: RemoveKeyUsers) -> Result<RemovalStatusFlags> {
    let keyid : &KeyIdentifier = keyid.try_into().map_err(|_| anyhow!("Invalid key ID length"))?;
    let fd = std::fs::File::open(dir)?;

    let mut arg : fscrypt_remove_key_arg = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.key_spec.u.identifier = *keyid;

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

pub fn set_policy(dir: &Path, keyid: &[u8]) -> Result<()> {
    let keyid : &KeyIdentifier = keyid.try_into().map_err(|_| anyhow!("Invalid key ID length"))?;
    let fd = std::fs::File::open(dir)?;

    let mut arg = fscrypt_policy_v2 {
        version : FSCRYPT_POLICY_V2,
        contents_encryption_mode : FSCRYPT_MODE_AES_256_XTS,
        filenames_encryption_mode : FSCRYPT_MODE_AES_256_CTS,
        flags : FSCRYPT_POLICY_FLAGS_PAD_32,
        __reserved : [0u8; 4],
        master_key_identifier : *keyid
    };

    let raw_fd = fd.as_raw_fd();
    let argptr = std::ptr::addr_of_mut!(arg) as *mut fscrypt_policy_v1;
    match unsafe { fscrypt_set_policy(raw_fd, argptr) } {
        Err(x) => Err(x.into()),
        _ => Ok(())
    }
}

pub fn get_key_status(dir: &Path, keyid: &[u8]) -> Result<(KeyStatus, KeyStatusFlags)> {
    let keyid : &KeyIdentifier = keyid.try_into().map_err(|_| anyhow!("Invalid key ID length"))?;
    let fd = std::fs::File::open(dir)?;

    let mut arg : fscrypt_get_key_status_arg = unsafe { mem::zeroed() };
    arg.key_spec.type_ = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.key_spec.u.identifier = *keyid;

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
    use rand::prelude::*;

    const EMPTY_RAW_KEY : RawKey = [0u8; FSCRYPT_MAX_KEY_SIZE];
    const MNTPOINT_ENV_VAR : &str = "FSCRYPT_RS_TEST_FS";

    #[test]
    fn test_add_key() -> Result<()> {
        let mntpoint = match env::var(MNTPOINT_ENV_VAR) {
            Ok(x) if x == "skip" => return Ok(()),
            Ok(x) => std::path::PathBuf::from(&x),
            _ => bail!("Environment variable '{MNTPOINT_ENV_VAR}' not set"),
        };

        let mut key = EMPTY_RAW_KEY;
        let mut rng = rand::thread_rng();

        for _ in 0..5 {
            // Create a temporary directory and check that it's not encrypted
            let workdir = tempdir::TempDir::new_in(&mntpoint, "encrypted")?;
            if let Some(_) = get_policy(workdir.as_ref())? {
                panic!("Found policy where none was expected")
            };

            // Generate a random key and calculate its expected ID
            rng.try_fill_bytes(&mut key[..])?;
            let id = get_key_id(&key)?;

            // Check that the key is absent from the filesystem
            let (status, _) = get_key_status(&mntpoint, &id)?;
            assert_eq!(status, KeyStatus::Absent);

            // Add the key to the filesystem, check the ID and its presence
            let new_id = add_key(&mntpoint, &key)?;
            assert_eq!(new_id, id);
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

        let mut key = EMPTY_RAW_KEY;
        let mut rng = rand::thread_rng();
        rng.try_fill_bytes(&mut key[..])?;
        let id = get_key_id(&key)?;

        assert!(add_key(&mntpoint, &key).is_err());
        assert!(set_policy(workdir.path(), &id).is_err());
        assert!(get_policy(workdir.path()).is_err());
        assert!(get_key_status(&mntpoint, &id).is_err());
        assert!(remove_key(&mntpoint, &id, RemoveKeyUsers::CurrentUser).is_err());

        Ok(())
    }
}
