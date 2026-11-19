//! Trust store, key lifecycle and verification policy.

use sha2::{Digest, Sha256};

use crate::error::CryptoError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: [u8; 32],
    pub public: [u8; 32],
    pub status: KeyStatus,
    pub label: String,
}

/// Deterministic key identifier: SHA-256 over the raw 32-byte public key.
/// This avoids trusting a self-declared identifier from the package.
pub fn key_id(public: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(public).into()
}

#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    keys: Vec<TrustedKey>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted key. Multiple active keys are allowed so that a new key
    /// can be deployed before the old one is revoked (rotation).
    pub fn add(&mut self, public: [u8; 32], label: impl Into<String>) -> [u8; 32] {
        let id = key_id(&public);
        if !self.keys.iter().any(|k| k.key_id == id) {
            self.keys.push(TrustedKey {
                key_id: id,
                public,
                status: KeyStatus::Active,
                label: label.into(),
            });
        }
        id
    }

    /// Revoke a key by id. Returns false if the key was not known.
    pub fn revoke(&mut self, id: &[u8; 32]) -> bool {
        match self.keys.iter_mut().find(|k| &k.key_id == id) {
            Some(key) => {
                key.status = KeyStatus::Revoked;
                true
            }
            None => false,
        }
    }

    pub fn lookup(&self, id: &[u8; 32]) -> Option<&TrustedKey> {
        self.keys.iter().find(|k| &k.key_id == id)
    }

    /// Resolve a key and reject revoked or unknown keys.
    pub fn trusted_key(&self, id: &[u8; 32]) -> Result<&TrustedKey, CryptoError> {
        let key = self.lookup(id).ok_or(CryptoError::UnknownKey(*id))?;
        if key.status == KeyStatus::Revoked {
            return Err(CryptoError::RevokedKey(*id));
        }
        Ok(key)
    }

    pub fn keys(&self) -> &[TrustedKey] {
        &self.keys
    }
}

/// Policy floor enforced before any authenticity decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub min_format_version: u16,
    pub min_security_policy: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_format_version: 1,
            min_security_policy: 1,
        }
    }
}
