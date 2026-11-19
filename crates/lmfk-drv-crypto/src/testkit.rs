//! Minimal signed-package builder used by the security tests.
//! It reuses the production format code; it does not bypass any verification.

use ed25519_dalek::{Signer, SigningKey};
use lmfk_drv_format::{
    HEADER_SIZE, Header, PKG_F_SIGNED, SECTION_ENTRY_SIZE, SECTION_F_ALLOC, SECTION_F_EXEC,
    SECTION_TYPE_TEXT, SectionHeader, arch_bit,
    cbor::{self, Value},
    le,
};
use sha2::{Digest, Sha256};

use crate::{signature, trust::key_id};

pub const ABI_MIN: u32 = 0x0001_0000;
pub const ABI_MAX: u32 = 0x0001_ffff;
pub const PAYLOAD_OFFSET: usize = 176;
pub const PAYLOAD_LEN: usize = 32;

fn base_manifest() -> Vec<u8> {
    let id = [0x33u8; 16];
    let device = Value::Map(vec![
        (Value::Text("bus"), Value::Uint(1)),
        (Value::Text("vendor"), Value::Uint(0x8086)),
        (Value::Text("device"), Value::Uint(0x9bc4)),
    ]);
    cbor::encode_vec(&Value::Map(vec![
        (Value::Text("id"), Value::Bytes(&id)),
        (Value::Text("name"), Value::Text("test-driver")),
        (Value::Text("version"), Value::Text("1.0.0")),
        (Value::Text("abi_min"), Value::Uint(ABI_MIN as u64)),
        (Value::Text("abi_max"), Value::Uint(ABI_MAX as u64)),
        (Value::Text("arch"), Value::Array(vec![Value::Uint(1)])),
        (Value::Text("devices"), Value::Array(vec![device])),
        (Value::Text("caps"), Value::Array(vec![])),
        (Value::Text("deps"), Value::Array(vec![])),
        (Value::Text("mode"), Value::Uint(1)),
        (Value::Text("entry"), Value::Text("lmfk_driver_entry")),
    ]))
}

fn with_policy(manifest: &[u8], policy: Option<u64>) -> Vec<u8> {
    let root = cbor::decode(manifest).unwrap();
    let Value::Map(mut entries) = root else {
        panic!("manifest must be a map")
    };
    entries.retain(|(key, _)| !matches!(key, Value::Text("security_policy")));
    if let Some(level) = policy {
        entries.push((Value::Text("security_policy"), Value::Uint(level)));
    }
    cbor::encode_vec(&Value::Map(entries))
}

/// Build a package with one `.text` section and, optionally, a valid Ed25519
/// signature over everything before the signature blob.
pub fn build(seed: &[u8; 32], security_policy: Option<u64>, sign: bool) -> Vec<u8> {
    let manifest = with_policy(&base_manifest(), security_policy);
    let payload = [0x5au8; PAYLOAD_LEN];
    let manifest_offset = PAYLOAD_OFFSET + PAYLOAD_LEN;
    let manifest_end = manifest_offset + manifest.len();
    let sig_offset = (manifest_end as u64 + 7) & !7;

    let signing_key = SigningKey::from_bytes(seed);
    let public = signing_key.verifying_key().to_bytes();
    let placeholder = signature::encode(&signature::SignatureBlob {
        alg: signature::ALG_ED25519,
        key_id: key_id(&public),
        signature: [0u8; 64],
    });
    let sig_len = if sign { placeholder.len() as u64 } else { 0 };
    let total = if sign {
        sig_offset + sig_len
    } else {
        manifest_end as u64
    };

    let mut data = vec![0u8; total as usize];
    let section = SectionHeader {
        name: b".text",
        ty: SECTION_TYPE_TEXT,
        flags: SECTION_F_ALLOC | SECTION_F_EXEC,
        offset: PAYLOAD_OFFSET as u64,
        size: PAYLOAD_LEN as u64,
        align: 8,
        sha256: Sha256::digest(payload).into(),
    };
    section.to_bytes(&mut data[HEADER_SIZE..HEADER_SIZE + SECTION_ENTRY_SIZE]);
    data[PAYLOAD_OFFSET..PAYLOAD_OFFSET + PAYLOAD_LEN].copy_from_slice(&payload);
    data[manifest_offset..manifest_end].copy_from_slice(&manifest);

    let header = Header {
        format_version: 1,
        flags: if sign { PKG_F_SIGNED } else { 0 },
        abi_min: ABI_MIN,
        abi_max: ABI_MAX,
        section_count: 1,
        arch_mask: arch_bit(1).unwrap(),
        total_size: total,
        section_table_offset: HEADER_SIZE as u64,
        manifest_offset: manifest_offset as u64,
        manifest_length: manifest.len() as u64,
        signature_offset: if sign { sig_offset } else { 0 },
        signature_length: sig_len,
    };
    header.to_bytes(&mut data[..HEADER_SIZE]);

    if sign {
        let signed_region = &data[..sig_offset as usize];
        let sig = signing_key.sign(signed_region);
        let blob = signature::encode(&signature::SignatureBlob {
            alg: signature::ALG_ED25519,
            key_id: key_id(&public),
            signature: sig.to_bytes(),
        });
        debug_assert_eq!(blob.len(), sig_len as usize);
        data[sig_offset as usize..].copy_from_slice(&blob);
    }
    data
}

pub fn signature_offset(data: &[u8]) -> usize {
    le::u64le(&data[72..]) as usize
}
