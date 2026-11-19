//! Integrity and authenticity verification for LMFK `.drv` packages.
//!
//! The signed region is defined as every byte before `signature_offset`,
//! i.e. `DrvFile::signed_region()`. It includes the fixed header, the section
//! table, all section payloads and the CBOR manifest. Only the signature blob
//! itself is excluded.
//!
//! Ed25519 (RFC 8032) and SHA-256 (FIPS 180-4) are provided by the
//! `ed25519-dalek` and `sha2` crates. No cryptographic primitive is
//! implemented in this workspace.

pub mod error;
pub mod signature;
pub mod trust;
pub mod verify;

#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests;

pub use error::{CryptoError, hex};
pub use trust::{KeyStatus, Policy, TrustStore, TrustedKey, key_id};
pub use verify::{
    Authentication, IntegrityReport, VerificationLevel, VerificationReport, verify_all,
    verify_authenticity, verify_integrity,
};
