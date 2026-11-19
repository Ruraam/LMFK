//! Official cryptographic test vectors.
//!
//! SHA-256: FIPS 180-4 examples.
//! Ed25519: RFC 8032, TEST 1 (empty message).

use ed25519_dalek::{Signer, SigningKey, Verifier};
use lmfk_drv_crypto::key_id;
use sha2::{Digest, Sha256};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn sha256_fips_180_4_vectors() {
    let cases = [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ];
    for (message, expected) in cases {
        let digest = Sha256::digest(message.as_bytes());
        assert_eq!(hex_encode(digest.as_slice()), expected);
    }
}

#[test]
fn ed25519_rfc8032_test_1() {
    let seed: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .try_into()
        .unwrap();
    let expected_public = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected_signature = unhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015\
         55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key();
    assert_eq!(public.to_bytes().as_slice(), expected_public);

    let message = b"";
    let signature = signing.sign(message);
    assert_eq!(signature.to_bytes().as_slice(), expected_signature);
    public.verify(message, &signature).unwrap();
}

#[test]
fn key_id_matches_sha256_of_rfc8032_public_key() {
    let public: [u8; 32] =
        unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .try_into()
            .unwrap();
    assert_eq!(
        key_id(&public).as_slice(),
        Sha256::digest(public).as_slice()
    );
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}
