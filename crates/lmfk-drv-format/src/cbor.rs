//! Minimal, strict CBOR decoder/encoder for `.drv` manifests.
//!
//! A deliberately limited subset: definite lengths, minimal encoding, and
//! bounded depth and item count. This avoids encoding ambiguities and
//! nesting attacks on an untrusted file.

use alloc::vec::Vec;
use core::convert::TryFrom;

const MAX_DEPTH: usize = 16;
const MAX_ITEMS: usize = 8192;
const MAX_LEN: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub enum Value<'a> {
    Uint(u64),
    /// Negative value: `-1 - n`.
    Nint(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Value<'a>>),
    Map(Vec<(Value<'a>, Value<'a>)>),
    Bool(bool),
    Null,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnexpectedEof,
    UnsupportedMajor(u8),
    UnsupportedSimple(u8),
    IndefiniteLength,
    ReservedAdditionalInfo(u8),
    NonMinimalEncoding,
    InvalidUtf8,
    DepthLimit,
    TooManyItems,
    LengthTooLarge,
    TrailingData,
    DuplicateKey,
    NonCanonicalOrder,
}

pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    depth: usize,
    items: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            depth: 0,
            items: MAX_ITEMS,
        }
    }

    pub fn decode(mut self) -> Result<Value<'a>, Error> {
        let value = self.value()?;
        if self.pos != self.data.len() {
            return Err(Error::TrailingData);
        }
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.data.get(self.pos).ok_or(Error::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if len > MAX_LEN {
            return Err(Error::LengthTooLarge);
        }
        let end = self.pos.checked_add(len).ok_or(Error::UnexpectedEof)?;
        let slice = self.data.get(self.pos..end).ok_or(Error::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    /// Decodes the argument of a CBOR head and requires its minimal form.
    fn arg(&mut self, ai: u8) -> Result<u64, Error> {
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => {
                let b = u64::from(self.byte()?);
                if b < 24 {
                    return Err(Error::NonMinimalEncoding);
                }
                Ok(b)
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().map_err(|_| Error::UnexpectedEof)?,
                ));
                if v <= 0xff {
                    return Err(Error::NonMinimalEncoding);
                }
                Ok(v)
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().map_err(|_| Error::UnexpectedEof)?,
                ));
                if v <= 0xffff {
                    return Err(Error::NonMinimalEncoding);
                }
                Ok(v)
            }
            27 => {
                let v =
                    u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Error::UnexpectedEof)?);
                if v <= u64::from(u32::MAX) {
                    return Err(Error::NonMinimalEncoding);
                }
                Ok(v)
            }
            28..=30 => Err(Error::ReservedAdditionalInfo(ai)),
            31 => Err(Error::IndefiniteLength),
            other => Err(Error::ReservedAdditionalInfo(other)),
        }
    }

    fn count(&mut self, ai: u8) -> Result<usize, Error> {
        let n = self.arg(ai)?;
        usize::try_from(n).map_err(|_| Error::LengthTooLarge)
    }

    fn value(&mut self) -> Result<Value<'a>, Error> {
        self.items = self.items.checked_sub(1).ok_or(Error::TooManyItems)?;
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 => Ok(Value::Uint(self.arg(ai)?)),
            1 => Ok(Value::Nint(self.arg(ai)?)),
            2 => {
                let n = self.count(ai)?;
                Ok(Value::Bytes(self.take(n)?))
            }
            3 => {
                let n = self.count(ai)?;
                let raw = self.take(n)?;
                let text = core::str::from_utf8(raw).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Text(text))
            }
            4 => {
                let n = self.count(ai)?;
                self.enter()?;
                let mut out = Vec::new();
                for _ in 0..n {
                    out.push(self.value()?);
                }
                self.depth -= 1;
                Ok(Value::Array(out))
            }
            5 => {
                let n = self.count(ai)?;
                self.enter()?;
                let mut out: Vec<(Value<'a>, Value<'a>)> = Vec::new();
                let mut previous_key: Option<&[u8]> = None;
                for _ in 0..n {
                    let key_start = self.pos;
                    let key = self.value()?;
                    let key_bytes = &self.data[key_start..self.pos];
                    if out.iter().any(|(k, _)| *k == key) {
                        return Err(Error::DuplicateKey);
                    }
                    if let Some(previous) = previous_key {
                        if canonical_cmp(previous, key_bytes) != core::cmp::Ordering::Less {
                            return Err(Error::NonCanonicalOrder);
                        }
                    }
                    previous_key = Some(key_bytes);
                    let val = self.value()?;
                    out.push((key, val));
                }
                self.depth -= 1;
                Ok(Value::Map(out))
            }
            7 => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                23 => Err(Error::UnsupportedSimple(23)),
                0..=19 | 24..=31 => Err(Error::UnsupportedSimple(ai)),
                _ => unreachable!(),
            },
            _ => Err(Error::UnsupportedMajor(major)),
        }
    }

    fn enter(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Error::DepthLimit);
        }
        Ok(())
    }
}

pub fn decode(data: &[u8]) -> Result<Value<'_>, Error> {
    Decoder::new(data).decode()
}

/* ------------------------------------------------------------------------- */
/* Deterministic encoding (used by fixtures and, later, drvpack)              */
/* ------------------------------------------------------------------------- */

/// Deterministic map key order: shortest encoded key first, then bytewise.
/// This is the order the encoder emits and the decoder requires.
fn canonical_cmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    (a.len(), a).cmp(&(b.len(), b))
}

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

pub fn encode(value: &Value<'_>, out: &mut Vec<u8>) {
    match value {
        Value::Uint(n) => write_head(out, 0, *n),
        Value::Nint(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode(item, out);
            }
        }
        Value::Map(entries) => {
            let mut ordered: Vec<(Vec<u8>, &Value<'_>)> = entries
                .iter()
                .map(|(key, val)| (encode_vec(key), val))
                .collect();
            ordered.sort_by(|a, b| canonical_cmp(&a.0, &b.0));
            write_head(out, 5, ordered.len() as u64);
            for (key, val) in ordered {
                out.extend_from_slice(&key);
                encode(val, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

pub fn encode_vec(value: &Value<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    encode(value, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn txt(s: &str) -> Value<'_> {
        Value::Text(s)
    }

    #[test]
    fn roundtrip_scalars_and_containers() {
        // Keys are listed in canonical order: shortest first, then bytewise.
        let value = Value::Map(vec![
            (txt("id"), Value::Bytes(&[1, 2, 3, 4])),
            (txt("ok"), Value::Bool(true)),
            (Value::Text("abi"), Value::Uint(0x0001_0000)),
            (
                txt("arch"),
                Value::Array(vec![Value::Uint(1), Value::Uint(2)]),
            ),
            (txt("name"), txt("intel-gpu")),
            (txt("none"), Value::Null),
        ]);
        let bytes = encode_vec(&value);
        assert_eq!(decode(&bytes).unwrap(), value);
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x9f = indefinite-length array.
        assert_eq!(decode(&[0x9f, 0xff]).unwrap_err(), Error::IndefiniteLength);
    }

    #[test]
    fn rejects_non_minimal_integer() {
        // 0x18 0x17 -> 23 must be encoded as 0x17.
        assert_eq!(
            decode(&[0x18, 0x17]).unwrap_err(),
            Error::NonMinimalEncoding
        );
    }

    #[test]
    fn rejects_trailing_data() {
        assert_eq!(decode(&[0x01, 0x02]).unwrap_err(), Error::TrailingData);
    }

    #[test]
    fn rejects_duplicate_map_key() {
        let bytes = [
            0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02, // {"a":1,"a":2}
        ];
        assert_eq!(decode(&bytes).unwrap_err(), Error::DuplicateKey);
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(decode(&[0x61, 0xff]).unwrap_err(), Error::InvalidUtf8);
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(
            decode(&[0x1a, 0x00, 0x01]).unwrap_err(),
            Error::UnexpectedEof
        );
    }

    #[test]
    fn rejects_non_canonical_map_order() {
        // {"b": 1, "a": 2} - "a" must come before "b".
        let bytes = [0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert_eq!(decode(&bytes).unwrap_err(), Error::NonCanonicalOrder);
    }

    #[test]
    fn encoder_emits_canonical_order() {
        let value = Value::Map(vec![
            (txt("a"), Value::Uint(2)),
            (txt("bb"), Value::Uint(3)),
            (txt("zz"), Value::Uint(1)),
        ]);
        let bytes = encode_vec(&value);
        // Shortest key first: "a", then "bb" and "zz" in bytewise order.
        assert_eq!(bytes[1], 0x61);
        assert_eq!(bytes[2], b'a');
        assert_eq!(decode(&bytes).unwrap(), value);
    }
}
