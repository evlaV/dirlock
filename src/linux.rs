
// fscrypt user API, see <linux/fscrypt.h>

pub const FSCRYPT_POLICY_V1: u8 = 0;
pub const FSCRYPT_POLICY_V2: u8 = 2;
pub const FSCRYPT_KEY_DESCRIPTOR_SIZE: usize = 8;
pub const FSCRYPT_KEY_IDENTIFIER_SIZE: usize = 16;
pub const FSCRYPT_MAX_KEY_SIZE: usize = 64;
pub const FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER: u32 = 2;
pub const FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY: u32 = 1;
pub const FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS: u32 = 2;
pub const FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF: u32 = 0x00000001;

pub const FSCRYPT_MODE_AES_256_XTS: u8 = 1;
pub const FSCRYPT_MODE_AES_256_CTS: u8 = 4;

pub const FSCRYPT_POLICY_FLAGS_PAD_4: u8 = 0;
pub const FSCRYPT_POLICY_FLAGS_PAD_8: u8 = 1;
pub const FSCRYPT_POLICY_FLAGS_PAD_16: u8 = 2;
pub const FSCRYPT_POLICY_FLAGS_PAD_32: u8 = 3;
pub const FSCRYPT_POLICY_FLAGS_PAD_MASK: u8 = 3;
pub const FSCRYPT_POLICY_FLAG_DIRECT_KEY: u8 = 4;
pub const FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64: u8 = 8;
pub const FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32: u8 = 16;

pub const FS_ENCRYPTION_MODE_INVALID: u8 = 0;
pub const FS_ENCRYPTION_MODE_AES_256_XTS: u8 = 1;
pub const FS_ENCRYPTION_MODE_AES_256_GCM: u8 = 2;
pub const FS_ENCRYPTION_MODE_AES_256_CBC: u8 = 3;
pub const FS_ENCRYPTION_MODE_AES_256_CTS: u8 = 4;
pub const FS_ENCRYPTION_MODE_AES_128_CBC: u8 = 5;
pub const FS_ENCRYPTION_MODE_AES_128_CTS: u8 = 6;
pub const FS_ENCRYPTION_MODE_SPECK128_256_XTS: u8 = 7;
pub const FS_ENCRYPTION_MODE_SPECK128_256_CTS: u8 = 8;
pub const FS_ENCRYPTION_MODE_ADIANTUM: u8 = 9;

pub const FSCRYPT_KEY_STATUS_ABSENT: u32 = 1;
pub const FSCRYPT_KEY_STATUS_PRESENT: u32 = 2;
pub const FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED: u32 = 3;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct fscrypt_policy_v1 {
    pub version: u8,
    pub contents_encryption_mode: u8,
    pub filenames_encryption_mode: u8,
    pub flags: u8,
    pub master_key_descriptor: [u8; FSCRYPT_KEY_DESCRIPTOR_SIZE],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct fscrypt_policy_v2 {
    pub version: u8,
    pub contents_encryption_mode: u8,
    pub filenames_encryption_mode: u8,
    pub flags: u8,
    pub __reserved: [u8; 4],
    pub master_key_identifier: [u8; FSCRYPT_KEY_IDENTIFIER_SIZE],
}

#[repr(C)]
pub union fscrypt_policy {
    pub version: u8,
    pub v1: fscrypt_policy_v1,
    pub v2: fscrypt_policy_v2,
}

#[repr(C)]
pub struct fscrypt_get_policy_ex_arg {
    pub policy_size: u64,
    pub policy: fscrypt_policy,
}

// The first two fields of fscrypt_get_policy_ex_arg, for the ioctl
#[repr(C, packed)]
pub struct fscrypt_get_policy_ex_arg_ioctl {
    policy_size: u64,
    version: u8,
}

#[repr(C)]
pub union fscrypt_key_specifier_u {
    pub __reserved: [u8; 32],
    pub descriptor: [u8; FSCRYPT_KEY_DESCRIPTOR_SIZE],
    pub identifier: [u8; FSCRYPT_KEY_IDENTIFIER_SIZE],
}

#[repr(C)]
pub struct fscrypt_key_specifier {
    pub type_: u32,
    pub __reserved: u32,
    pub u: fscrypt_key_specifier_u,
}

#[repr(C)]
pub struct fscrypt_remove_key_arg {
    pub key_spec: fscrypt_key_specifier,
    pub removal_status_flags: u32,
    pub __reserved: [u32; 5],
}

#[repr(C)]
pub struct fscrypt_get_key_status_arg {
    pub key_spec: fscrypt_key_specifier,
    pub __reserved: [u32; 6],
    pub status: u32,
    pub status_flags: u32,
    pub user_count: u32,
    pub __out_reserved: [u32; 13],
}

#[repr(C)]
pub struct fscrypt_add_key_arg {
    pub key_spec: fscrypt_key_specifier,
    pub raw_size: u32,
    pub key_id: u32,
    pub __reserved: [u32; 8],
}
