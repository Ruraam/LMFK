//! The Ed25519 signature blob and its strict CBOR encoding.
//!
//! Blob schema: `{ "alg": "ed25519", "key_id": bytes(32), "signature": bytes(64) }`
//! Unknown keys are ignored (the blob itself is covered by nothing else, but
//! it lives outside the signed region by design).

use lmfk_drv_format::cbor::{self, Value};

use crate::error::CryptoError;

pub const ALG_ED25519: &str = "ed25519";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureBlob<'a> {
    pub alg: &'a str,
    pub key_id: [u8; 32],
    pub signature: [u8; 64],
}

fn field<'m, 'd>(
    map: &'m [(Value<'d>, Value<'d>)],
    key: &'static str,
) -> Result<&'m Value<'d>, CryptoError> {
    map.iter()
        .find_map(|(k, v)| match k {
            Value::Text(t) if *t == key => Some(v),
            _ => None,
        })
        .ok_or(CryptoError::MissingField(key))
}

fn text<'d>(v: &Value<'d>, key: &'static str) -> Result<&'d str, CryptoError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(CryptoError::WrongType(key)),
    }
}

fn fixed_bytes<const N: usize>(v: &Value<'_>, key: &'static str) -> Result<[u8; N], CryptoError> {
    match v {
        Value::Bytes(b) if b.len() == N => {
            let mut out = [0u8; N];
            out.copy_from_slice(b);
            Ok(out)
        }
        _ => Err(CryptoError::WrongType(key)),
    }
}

pub fn decode(bytes: &[u8]) -> Result<SignatureBlob<'_>, CryptoError> {
    let root = cbor::decode(bytes).map_err(CryptoError::MalformedSignatureBlob)?;
    let map = match root {
        Value::Map(entries) => entries,
        _ => return Err(CryptoError::WrongType("root")),
    };
    Ok(SignatureBlob {
        alg: text(field(&map, "alg")?, "alg")?,
        key_id: fixed_bytes(field(&map, "key_id")?, "key_id")?,
        signature: fixed_bytes(field(&map, "signature")?, "signature")?,
    })
}

pub fn encode(blob: &SignatureBlob<'_>) -> Vec<u8> {
    cbor::encode_vec(&Value::Map(vec![
        (Value::Text("alg"), Value::Text(blob.alg)),
        (Value::Text("key_id"), Value::Bytes(&blob.key_id)),
        (Value::Text("signature"), Value::Bytes(&blob.signature)),
    ]))
}
