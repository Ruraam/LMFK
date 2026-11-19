//! Error type shared by the integrity and authenticity stages.

use core::fmt;

use lmfk_drv_format::cbor::Error as CborError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// One or more section payloads do not match their stored SHA-256 digest.
    IntegrityMismatch(Vec<usize>),
    MalformedSignatureBlob(CborError),
    MissingField(&'static str),
    WrongType(&'static str),
    UnsupportedAlgorithm(String),
    MalformedKey,
    MalformedSignature,
    /// The key id embedded in the signature is not in the trust store.
    UnknownKey([u8; 32]),
    /// The key is known but has been revoked.
    RevokedKey([u8; 32]),
    /// The signature does not verify over the signed region.
    InvalidSignature,
    MissingSignature,
    FormatTooOld {
        minimum: u16,
        actual: u16,
    },
    /// The manifest carries no security policy level.
    PolicyMissing,
    PolicyTooOld {
        minimum: u64,
        actual: u64,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegrityMismatch(indexes) => {
                write!(f, "SHA-256 mismatch in section(s): {indexes:?}")
            }
            Self::MalformedSignatureBlob(e) => write!(f, "malformed signature blob: {e:?}"),
            Self::MissingField(name) => write!(f, "missing signature field: {name}"),
            Self::WrongType(name) => write!(f, "wrong type for signature field: {name}"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported signature algorithm: {alg}"),
            Self::MalformedKey => f.write_str("malformed public key"),
            Self::MalformedSignature => f.write_str("malformed Ed25519 signature"),
            Self::UnknownKey(id) => write!(f, "untrusted key: {}", hex(id)),
            Self::RevokedKey(id) => write!(f, "revoked key: {}", hex(id)),
            Self::InvalidSignature => f.write_str("Ed25519 signature verification failed"),
            Self::MissingSignature => f.write_str("package is not signed"),
            Self::FormatTooOld { minimum, actual } => {
                write!(f, "format version {actual} is older than minimum {minimum}")
            }
            Self::PolicyMissing => f.write_str("manifest has no security_policy field"),
            Self::PolicyTooOld { minimum, actual } => {
                write!(
                    f,
                    "security policy {actual} is older than minimum {minimum}"
                )
            }
        }
    }
}

/// Lowercase hex helper used in error messages and by the CLI tools.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}
