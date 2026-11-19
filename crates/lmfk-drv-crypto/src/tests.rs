//! Security properties: separation of integrity/authenticity, tampering,
//! key substitution, revocation, rotation and downgrade.

use ed25519_dalek::SigningKey;
use lmfk_drv_format::le;
use lmfk_drv_parser::parse;
use sha2::{Digest, Sha256};

use super::{
    CryptoError, Policy, TrustStore, VerificationLevel, key_id, testkit, verify_all,
    verify_authenticity, verify_integrity,
};

const SEED_A: [u8; 32] = [0x11; 32];
const SEED_B: [u8; 32] = [0x22; 32];

fn trust(seed: &[u8; 32]) -> (TrustStore, [u8; 32]) {
    let key = SigningKey::from_bytes(seed);
    let public = key.verifying_key().to_bytes();
    let mut store = TrustStore::new();
    let id = store.add(public, "test-key");
    (store, id)
}

#[test]
fn valid_signed_package_is_accepted() {
    let data = testkit::build(&SEED_A, Some(1), true);
    let package = parse(&data).unwrap();
    let (store, id) = trust(&SEED_A);

    let report = verify_all(&package, &store, &Policy::default());
    assert!(report.structure_valid);
    assert_eq!(report.integrity.as_ref().unwrap().sections_checked, 1);
    assert_eq!(report.authenticity.as_ref().unwrap().key_id, id);
    assert_eq!(report.level(), VerificationLevel::Authenticated);
    assert!(report.accepted());
}

#[test]
fn integrity_never_implies_authenticity() {
    let data = testkit::build(&SEED_A, Some(1), true);
    let package = parse(&data).unwrap();
    let empty = TrustStore::new();

    assert!(verify_integrity(&package).is_ok());
    let result = verify_authenticity(&package, &empty, &Policy::default());
    assert!(matches!(result, Err(CryptoError::UnknownKey(_))));

    let report = verify_all(&package, &empty, &Policy::default());
    assert_eq!(report.level(), VerificationLevel::Integrity);
    assert!(!report.accepted());
}

#[test]
fn unsigned_package_is_not_authenticated() {
    let data = testkit::build(&SEED_A, Some(1), false);
    let package = parse(&data).unwrap();
    let (store, _) = trust(&SEED_A);

    let report = verify_all(&package, &store, &Policy::default());
    assert!(report.integrity.is_ok());
    assert_eq!(
        report.authenticity.as_ref().unwrap_err(),
        &CryptoError::MissingSignature
    );
    assert!(!report.accepted());
}

#[test]
fn payload_corruption_fails_integrity() {
    let mut data = testkit::build(&SEED_A, Some(1), true);
    data[testkit::PAYLOAD_OFFSET] ^= 0xff;
    let package = parse(&data).unwrap();
    let (store, _) = trust(&SEED_A);

    let report = verify_all(&package, &store, &Policy::default());
    assert_eq!(
        report.integrity.as_ref().unwrap_err(),
        &CryptoError::IntegrityMismatch(vec![0])
    );
    assert!(report.authenticity.is_err());
    assert_eq!(report.level(), VerificationLevel::Structure);
    assert!(!report.accepted());
}

#[test]
fn recomputed_hash_does_not_forgive_a_bad_signature() {
    let mut data = testkit::build(&SEED_A, Some(1), true);
    data[testkit::PAYLOAD_OFFSET] ^= 0xff;
    let digest = Sha256::digest(
        &data[testkit::PAYLOAD_OFFSET..testkit::PAYLOAD_OFFSET + testkit::PAYLOAD_LEN],
    );
    data[96 + 48..96 + 80].copy_from_slice(digest.as_slice());

    let package = parse(&data).unwrap();
    let (store, _) = trust(&SEED_A);
    assert!(verify_integrity(&package).is_ok());
    assert_eq!(
        verify_authenticity(&package, &store, &Policy::default()).unwrap_err(),
        CryptoError::InvalidSignature
    );
    let report = verify_all(&package, &store, &Policy::default());
    assert_eq!(report.level(), VerificationLevel::Integrity);
    assert!(!report.accepted());
}

#[test]
fn untrusted_and_revoked_keys_are_rejected() {
    let data_a = testkit::build(&SEED_A, Some(1), true);
    let data_b = testkit::build(&SEED_B, Some(1), true);
    let package_a = parse(&data_a).unwrap();
    let package_b = parse(&data_b).unwrap();

    let (store, id_a) = trust(&SEED_A);
    assert!(matches!(
        verify_authenticity(&package_b, &store, &Policy::default()),
        Err(CryptoError::UnknownKey(_))
    ));

    let mut store = store;
    assert!(store.revoke(&id_a));
    assert_eq!(
        verify_authenticity(&package_a, &store, &Policy::default()).unwrap_err(),
        CryptoError::RevokedKey(id_a)
    );
    assert!(store.revoke(&id_a)); // already known; revoking again is idempotent
}

#[test]
fn key_rotation_accepts_old_and_new_before_revocation() {
    let data_a = testkit::build(&SEED_A, Some(1), true);
    let data_b = testkit::build(&SEED_B, Some(1), true);
    let package_a = parse(&data_a).unwrap();
    let package_b = parse(&data_b).unwrap();

    let (mut store, id_a) = trust(&SEED_A);
    let new_key = SigningKey::from_bytes(&SEED_B).verifying_key().to_bytes();
    let id_b = store.add(new_key, "rotated-key");
    assert_ne!(id_a, id_b);

    assert!(verify_authenticity(&package_a, &store, &Policy::default()).is_ok());
    assert!(verify_authenticity(&package_b, &store, &Policy::default()).is_ok());

    store.revoke(&id_a);
    assert!(matches!(
        verify_authenticity(&package_a, &store, &Policy::default()),
        Err(CryptoError::RevokedKey(_))
    ));
    assert!(verify_authenticity(&package_b, &store, &Policy::default()).is_ok());
}

#[test]
fn corrupted_signature_is_rejected() {
    let data = testkit::build(&SEED_A, Some(1), true);
    let mut corrupted = data.clone();
    let offset = testkit::signature_offset(&corrupted);
    // First byte of the 64-byte signature inside the CBOR blob.
    corrupted[offset + 66] ^= 0x01;
    let package = parse(&corrupted).unwrap();
    let (store, _) = trust(&SEED_A);
    assert_eq!(
        verify_authenticity(&package, &store, &Policy::default()).unwrap_err(),
        CryptoError::InvalidSignature
    );

    let mut garbage = data;
    let offset = testkit::signature_offset(&garbage);
    garbage[offset..].fill(0xff);
    let package = parse(&garbage).unwrap();
    assert!(matches!(
        verify_authenticity(&package, &store, &Policy::default()),
        Err(CryptoError::MalformedSignatureBlob(_))
    ));
}

#[test]
fn unknown_algorithm_is_rejected() {
    let mut data = testkit::build(&SEED_A, Some(1), true);
    let offset = testkit::signature_offset(&data);
    let region = &mut data[offset..];
    let pos = region
        .windows(7)
        .position(|w| w == b"ed25519")
        .expect("algorithm string must be present");
    region[pos..pos + 7].copy_from_slice(b"ed25518");

    let package = parse(&data).unwrap();
    let (store, _) = trust(&SEED_A);
    assert_eq!(
        verify_authenticity(&package, &store, &Policy::default()).unwrap_err(),
        CryptoError::UnsupportedAlgorithm("ed25518".to_owned())
    );
}

#[test]
fn downgrade_attempts_are_rejected() {
    let (store, _) = trust(&SEED_A);

    let missing_bytes = testkit::build(&SEED_A, None, true);
    let missing = parse(&missing_bytes).unwrap();
    assert_eq!(
        verify_authenticity(&missing, &store, &Policy::default()).unwrap_err(),
        CryptoError::PolicyMissing
    );

    let old_bytes = testkit::build(&SEED_A, Some(1), true);
    let old = parse(&old_bytes).unwrap();
    let strict = Policy {
        min_format_version: 1,
        min_security_policy: 2,
    };
    assert_eq!(
        verify_authenticity(&old, &store, &strict).unwrap_err(),
        CryptoError::PolicyTooOld {
            minimum: 2,
            actual: 1
        }
    );

    let future = Policy {
        min_format_version: 2,
        min_security_policy: 1,
    };
    assert_eq!(
        verify_authenticity(&old, &store, &future).unwrap_err(),
        CryptoError::FormatTooOld {
            minimum: 2,
            actual: 1
        }
    );
}

#[test]
fn key_id_is_sha256_of_public_key() {
    let key_a = SigningKey::from_bytes(&SEED_A).verifying_key().to_bytes();
    let key_b = SigningKey::from_bytes(&SEED_B).verifying_key().to_bytes();
    assert_eq!(key_id(&key_a).as_slice(), Sha256::digest(key_a).as_slice());
    assert_ne!(key_id(&key_a), key_id(&key_b));

    let data = testkit::build(&SEED_A, Some(1), true);
    let offset = testkit::signature_offset(&data);
    let declared = lmfk_drv_format::cbor::decode(&data[offset..]).unwrap();
    let lmfk_drv_format::cbor::Value::Map(entries) = declared else {
        panic!("blob must be a map")
    };
    let id = entries
        .iter()
        .find_map(|(k, v)| match k {
            lmfk_drv_format::cbor::Value::Text("key_id") => match v {
                lmfk_drv_format::cbor::Value::Bytes(bytes) => Some(bytes),
                _ => None,
            },
            _ => None,
        })
        .unwrap();
    assert_eq!(*id, key_id(&key_a).as_slice());
    assert_eq!(le::u64le(&data[80..]), 130); // signature blob length
}
