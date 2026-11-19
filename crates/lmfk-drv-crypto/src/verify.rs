//! Three-stage verification. The stages are deliberately kept separate:
//! a valid SHA-256 digest never implies authenticity.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use lmfk_drv_format::SECTION_TYPE_BSS;
use lmfk_drv_parser::DrvFile;
use sha2::{Digest, Sha256};

use crate::{
    error::CryptoError,
    signature::{self, ALG_ED25519},
    trust::{Policy, TrustStore},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityReport {
    pub sections_checked: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication {
    pub key_id: [u8; 32],
}

/// Highest stage reached. A package with a valid signature but corrupt
/// section hashes is reported as `Structure`, never as `Authenticated`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationLevel {
    Structure,
    Integrity,
    Authenticated,
}

#[derive(Clone, Debug)]
pub struct VerificationReport {
    pub structure_valid: bool,
    pub integrity: Result<IntegrityReport, CryptoError>,
    pub authenticity: Result<Authentication, CryptoError>,
}

impl VerificationReport {
    pub fn level(&self) -> VerificationLevel {
        if self.authenticity.is_ok() && self.integrity.is_ok() {
            VerificationLevel::Authenticated
        } else if self.integrity.is_ok() {
            VerificationLevel::Integrity
        } else {
            VerificationLevel::Structure
        }
    }

    /// True only when both integrity and authenticity succeeded.
    pub fn accepted(&self) -> bool {
        self.integrity.is_ok() && self.authenticity.is_ok()
    }
}

/// Verify every non-BSS section against the SHA-256 digest stored in the
/// section table. This detects corruption and tampering with payloads, but
/// says nothing about who produced those digests.
pub fn verify_integrity(package: &DrvFile<'_>) -> Result<IntegrityReport, CryptoError> {
    let mut checked = 0usize;
    let mut mismatched = Vec::new();
    for (index, section) in package.sections().iter().enumerate() {
        if section.header.ty == SECTION_TYPE_BSS {
            continue;
        }
        checked += 1;
        let digest = Sha256::digest(section.data);
        if digest.as_slice() != section.header.sha256 {
            mismatched.push(index);
        }
    }
    if !mismatched.is_empty() {
        return Err(CryptoError::IntegrityMismatch(mismatched));
    }
    Ok(IntegrityReport {
        sections_checked: checked,
    })
}

/// Verify the Ed25519 signature over the signed region, the trust store and
/// the downgrade policy. This stage does NOT check section hashes.
pub fn verify_authenticity(
    package: &DrvFile<'_>,
    trust: &TrustStore,
    policy: &Policy,
) -> Result<Authentication, CryptoError> {
    let header = package.header();
    if header.format_version < policy.min_format_version {
        return Err(CryptoError::FormatTooOld {
            minimum: policy.min_format_version,
            actual: header.format_version,
        });
    }

    let security_policy = package
        .manifest()
        .security_policy
        .ok_or(CryptoError::PolicyMissing)?;
    if security_policy < policy.min_security_policy {
        return Err(CryptoError::PolicyTooOld {
            minimum: policy.min_security_policy,
            actual: security_policy,
        });
    }

    if package.signature().is_empty() {
        return Err(CryptoError::MissingSignature);
    }
    let blob = signature::decode(package.signature())?;
    if blob.alg != ALG_ED25519 {
        return Err(CryptoError::UnsupportedAlgorithm(blob.alg.to_owned()));
    }

    let key = trust.trusted_key(&blob.key_id)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key.public).map_err(|_| CryptoError::MalformedKey)?;
    let signature =
        Signature::from_slice(&blob.signature).map_err(|_| CryptoError::MalformedSignature)?;
    verifying_key
        .verify(package.signed_region(), &signature)
        .map_err(|_| CryptoError::InvalidSignature)?;

    Ok(Authentication {
        key_id: blob.key_id,
    })
}

/// Run both stages independently and report each outcome. Never short-circuit:
/// callers need to see exactly which stage failed.
pub fn verify_all(
    package: &DrvFile<'_>,
    trust: &TrustStore,
    policy: &Policy,
) -> VerificationReport {
    VerificationReport {
        structure_valid: true,
        integrity: verify_integrity(package),
        authenticity: verify_authenticity(package, trust, policy),
    }
}
