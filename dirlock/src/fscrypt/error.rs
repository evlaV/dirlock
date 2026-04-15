/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use nix::errno::Errno;

/// Error returned if parsing a [`super::PolicyKeyId`] from a hex string fails
#[derive(Debug)]
pub struct PolicyIdParseError;

impl std::fmt::Display for PolicyIdParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid policy ID")
    }
}

impl std::error::Error for PolicyIdParseError {}

/// Error type for fscrypt operations
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// The directory is already encrypted with a different key (EEXIST)
    AlreadyEncrypted,
    /// The directory is not empty (ENOTEMPTY)
    DirectoryNotEmpty,
    /// The hardware-wrapped key is invalid (EBADMSG)
    InvalidWrappedKey,
    /// The encryption policy or key is invalid or unsupported (EINVAL)
    InvalidPolicy,
    /// An I/O error occurred (e.g., failed to open the directory)
    Io(std::io::Error),
    /// The encryption key is not available (ENOKEY)
    KeyNotFound,
    /// The key was rejected because it had the wrong type (EKEYREJECTED)
    KeyRejected,
    /// The target is not a directory (ENOTDIR)
    NotADirectory,
    /// Encryption is not enabled in the filesystem or in the kernel (EOPNOTSUPP)
    NotEnabled,
    /// The directory cannot be encrypted, e.g. it is the root of an ext4 filesystem (EPERM)
    NotPermitted,
    /// This type of filesystem does not support fscrypt (ENOTTY)
    NotSupported,
    /// The caller lacks permissions or a required capability, e.g. CAP_FOWNER or CAP_SYS_ADMIN (EACCES)
    PermissionDenied,
    /// The encryption policy does not fit in the provided buffer (EOVERFLOW)
    PolicyTooLarge,
    /// The key quota for this user would be exceeded (EDQUOT)
    QuotaExceeded,
    /// The filesystem is read-only (EROFS)
    ReadOnly,
    /// An unexpected errno was returned by a kernel call
    Unknown(Errno),
    /// The kernel returned an unknown fscrypt key status code
    UnknownKeyStatus(u32),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Returns the errno that best represents this error
    pub fn errno(&self) -> Errno {
        match self {
            Error::AlreadyEncrypted    => Errno::EEXIST,
            Error::DirectoryNotEmpty   => Errno::ENOTEMPTY,
            Error::InvalidWrappedKey   => Errno::EBADMSG,
            Error::InvalidPolicy       => Errno::EINVAL,
            Error::Io(e)               => e.raw_os_error().map_or(Errno::EIO, Errno::from_raw),
            Error::KeyNotFound         => Errno::ENOKEY,
            Error::KeyRejected         => Errno::EKEYREJECTED,
            Error::NotADirectory       => Errno::ENOTDIR,
            Error::NotEnabled          => Errno::EOPNOTSUPP,
            Error::NotPermitted        => Errno::EPERM,
            Error::NotSupported        => Errno::ENOTTY,
            Error::PermissionDenied    => Errno::EACCES,
            Error::PolicyTooLarge      => Errno::EOVERFLOW,
            Error::QuotaExceeded       => Errno::EDQUOT,
            Error::ReadOnly            => Errno::EROFS,
            Error::Unknown(e)          => *e,
            Error::UnknownKeyStatus(_) => Errno::EPROTO,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AlreadyEncrypted    => write!(f, "Already encrypted with a different key"),
            Error::InvalidPolicy       => write!(f, "Invalid or unsupported encryption policy"),
            Error::Io(e)               => e.fmt(f),
            Error::NotEnabled          => write!(f, "Encryption not enabled in the filesystem or in the kernel"),
            Error::NotPermitted        => write!(f, "This directory cannot be encrypted"),
            Error::NotSupported        => write!(f, "This filesystem does not support encryption"),
            Error::QuotaExceeded       => write!(f, "Key quota exceeded for this user"),
            Error::UnknownKeyStatus(n) => write!(f, "Unknown fscrypt key status: {n}"),
            // In all other cases, the generic error message is valid for our case.
            // InvalidWrappedKey (EBADMSG) is theoretically possible but unreachable
            // in practice since our add_key() never uses hardware-wrapped keys.
            other                      => other.errno().fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Create an fscrypt error from a standard library's I/O error
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Create an fscrypt error from the returned values of the fscrypt ioctls
impl From<Errno> for Error {
    fn from(errno: Errno) -> Self {
        match errno {
            Errno::EBADMSG      => Error::InvalidWrappedKey,
            Errno::EACCES       => Error::PermissionDenied,
            Errno::EDQUOT       => Error::QuotaExceeded,
            Errno::EEXIST       => Error::AlreadyEncrypted,
            Errno::EINVAL       => Error::InvalidPolicy,
            Errno::EKEYREJECTED => Error::KeyRejected,
            Errno::ENOKEY       => Error::KeyNotFound,
            Errno::ENOTDIR      => Error::NotADirectory,
            Errno::ENOTEMPTY    => Error::DirectoryNotEmpty,
            Errno::ENOTTY       => Error::NotSupported,
            Errno::EOPNOTSUPP   => Error::NotEnabled,
            Errno::EOVERFLOW    => Error::PolicyTooLarge,
            Errno::EPERM        => Error::NotPermitted,
            Errno::EROFS        => Error::ReadOnly,
            // According to the kernel fscrypt documentation we should
            // not get any other error type, so we treat everything else
            // as unknown. Note that this includes EIO and EPROTO.
            // We return those in Error::errno(), but they are synthetic
            // values set by us, not something that the fscrypt ioctls
            // are expected to return.
            e                   => Error::Unknown(e),
        }
    }
}
