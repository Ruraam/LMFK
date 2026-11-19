//! Hand-built fixtures and malformed-file tests.

use super::*;
use lmfk_drv_format::{
    Header, MAX_SECTIONS, PKG_F_COMPRESSED, PKG_F_SIGNED, SECTION_ENTRY_SIZE, SECTION_F_ALLOC,
    SECTION_F_EXEC, SECTION_F_WRITE, SECTION_TYPE_RODATA, SECTION_TYPE_TEXT, SectionHeader,
    cbor::{self, Value},
    le,
};

const ABI_MIN: u32 = 0x0001_0000;
const ABI_MAX: u32 = 0x0001_ffff;
const PAYLOAD_LEN: usize = 16;
const SIG_LEN: u64 = 64;

fn manifest_cbor() -> Vec<u8> {
    let id = [0x11u8; 16];
    let device = Value::Map(vec![
        (Value::Text("bus"), Value::Uint(1)),
        (Value::Text("vendor"), Value::Uint(0x8086)),
        (Value::Text("device"), Value::Uint(0x9bc4)),
    ]);
    let value = Value::Map(vec![
        (Value::Text("id"), Value::Bytes(&id)),
        (Value::Text("name"), Value::Text("test-driver")),
        (Value::Text("version"), Value::Text("1.0.0")),
        (Value::Text("abi_min"), Value::Uint(ABI_MIN as u64)),
        (Value::Text("abi_max"), Value::Uint(ABI_MAX as u64)),
        (Value::Text("arch"), Value::Array(vec![Value::Uint(1)])),
        (Value::Text("devices"), Value::Array(vec![device])),
        (
            Value::Text("caps"),
            Value::Array(vec![Value::Text("mmio:bar0")]),
        ),
        (Value::Text("deps"), Value::Array(vec![])),
        (Value::Text("mode"), Value::Uint(1)),
        (Value::Text("entry"), Value::Text("lmfk_driver_entry")),
    ]);
    cbor::encode_vec(&value)
}

fn build_with(names: &[&[u8]], manifest: &[u8]) -> Vec<u8> {
    let n = names.len();
    let table_off = HEADER_SIZE as u64;
    let payload_off = table_off + (n as u64) * (SECTION_ENTRY_SIZE as u64);
    let manifest_off = payload_off + (n as u64) * (PAYLOAD_LEN as u64);
    let sig_off = (manifest_off + manifest.len() as u64 + 7) & !7;
    let total = sig_off + SIG_LEN;

    let mut data = vec![0u8; total as usize];
    for (index, name) in names.iter().enumerate() {
        let off = payload_off + (index as u64) * (PAYLOAD_LEN as u64);
        let flags = match *name {
            b".text" => SECTION_F_ALLOC | SECTION_F_EXEC,
            b".rodata" => SECTION_F_ALLOC,
            b".data" | b".bss" => SECTION_F_ALLOC | SECTION_F_WRITE,
            _ => 0,
        };
        let sh = SectionHeader {
            name,
            ty: SECTION_TYPE_TEXT,
            flags,
            offset: off,
            size: PAYLOAD_LEN as u64,
            align: 8,
            sha256: [0u8; 32],
        };
        let entry_start = table_off as usize + index * SECTION_ENTRY_SIZE;
        sh.to_bytes(&mut data[entry_start..entry_start + SECTION_ENTRY_SIZE]);
        data[off as usize..off as usize + PAYLOAD_LEN].fill(0x90);
    }
    data[manifest_off as usize..manifest_off as usize + manifest.len()].copy_from_slice(manifest);
    data[sig_off as usize..].fill(0x42);

    let header = Header {
        format_version: 1,
        flags: PKG_F_SIGNED,
        abi_min: ABI_MIN,
        abi_max: ABI_MAX,
        section_count: n as u32,
        arch_mask: arch_bit(1).unwrap(),
        total_size: total,
        section_table_offset: table_off,
        manifest_offset: manifest_off,
        manifest_length: manifest.len() as u64,
        signature_offset: sig_off,
        signature_length: SIG_LEN,
    };
    header.to_bytes(&mut data[..HEADER_SIZE]);
    data
}

fn build(names: &[&[u8]]) -> Vec<u8> {
    build_with(names, &manifest_cbor())
}

fn put32(data: &mut [u8], offset: usize, value: u32) {
    le::put_u32(&mut data[offset..], value);
}

fn put64(data: &mut [u8], offset: usize, value: u64) {
    le::put_u64(&mut data[offset..], value);
}

fn manifest_range(data: &[u8]) -> (usize, usize) {
    let off = le::u64le(&data[56..]) as usize;
    let len = le::u64le(&data[64..]) as usize;
    (off, off + len)
}

#[test]
fn accepts_valid_package() {
    let data = build(&[b".text"]);
    let pkg = parse(&data).unwrap();
    assert_eq!(pkg.header().section_count, 1);
    assert_eq!(pkg.header().abi_min, ABI_MIN);
    assert_eq!(pkg.manifest().name, "test-driver");
    assert_eq!(pkg.manifest().entry, "lmfk_driver_entry");
    assert_eq!(pkg.manifest().caps, vec!["mmio:bar0"]);
    assert_eq!(pkg.manifest().devices[0].vendor, 0x8086);
    assert_eq!(pkg.sections().len(), 1);
    assert_eq!(pkg.section(b".text").unwrap().data.len(), PAYLOAD_LEN);
    assert_eq!(pkg.signature().len(), SIG_LEN as usize);
    assert_eq!(
        pkg.signed_region().len(),
        pkg.header().signature_offset as usize
    );
    assert_eq!(pkg.raw().len(), data.len());
}

#[test]
fn accepts_unsigned_development_package() {
    let mut data = build(&[b".text"]);
    let sig_off = le::u64le(&data[72..]);
    put32(&mut data, 12, 0);
    put64(&mut data, 72, 0);
    put64(&mut data, 80, 0);
    put64(&mut data, 40, sig_off);
    data.truncate(sig_off as usize);
    let pkg = parse(&data).unwrap();
    assert!(pkg.signature().is_empty());
    assert_eq!(pkg.signed_region().len(), data.len());
}

#[test]
fn rejects_empty_or_short_file() {
    assert_eq!(
        parse(&[]).unwrap_err(),
        ParseError::Header(HeaderError::TooShort)
    );
    let data = build(&[b".text"]);
    assert_eq!(
        parse(&data[..HEADER_SIZE - 1]).unwrap_err(),
        ParseError::Header(HeaderError::TooShort)
    );
}

#[test]
fn rejects_bad_magic_version_and_header_size() {
    let mut data = build(&[b".text"]);
    data[0] = 0;
    assert_eq!(
        parse(&data).unwrap_err(),
        ParseError::Header(HeaderError::BadMagic)
    );

    let mut data = build(&[b".text"]);
    le::put_u16(&mut data[8..], 2);
    assert_eq!(
        parse(&data).unwrap_err(),
        ParseError::Header(HeaderError::UnsupportedVersion(2))
    );

    let mut data = build(&[b".text"]);
    le::put_u16(&mut data[10..], 64);
    assert_eq!(
        parse(&data).unwrap_err(),
        ParseError::Header(HeaderError::BadHeaderSize(64))
    );
}

#[test]
fn rejects_total_size_mismatch() {
    let data = build(&[b".text"]);
    let len = data.len() as u64;
    for wrong in [len - 1, len + 1] {
        let mut data = data.clone();
        put64(&mut data, 40, wrong);
        assert!(matches!(
            parse(&data).unwrap_err(),
            ParseError::SizeMismatch { .. }
        ));
    }
}

#[test]
fn rejects_unsupported_flags() {
    let mut data = build(&[b".text"]);
    put32(&mut data, 12, 1 << 3);
    assert!(matches!(
        parse(&data).unwrap_err(),
        ParseError::UnsupportedFlag(_)
    ));

    let mut data = build(&[b".text"]);
    put32(&mut data, 12, PKG_F_SIGNED | PKG_F_COMPRESSED);
    assert!(matches!(
        parse(&data).unwrap_err(),
        ParseError::UnsupportedFlag(_)
    ));
}

#[test]
fn rejects_invalid_section_counts() {
    let mut data = build(&[b".text"]);
    put32(&mut data, 24, 0);
    assert_eq!(parse(&data).unwrap_err(), ParseError::TooManySections);

    let mut data = build(&[b".text"]);
    put32(&mut data, 24, MAX_SECTIONS + 1);
    assert_eq!(parse(&data).unwrap_err(), ParseError::TooManySections);
}

#[test]
fn rejects_bad_section_table() {
    let data = build(&[b".text"]);
    let total = data.len() as u64;

    let mut data = data.clone();
    put64(&mut data, 48, total);
    assert_eq!(parse(&data).unwrap_err(), ParseError::TableOutOfBounds);

    put64(&mut data, 48, 100); // not aligned on 8
    assert_eq!(parse(&data).unwrap_err(), ParseError::TableOutOfBounds);
}

#[test]
fn rejects_bad_section_entries() {
    let data = build(&[b".text"]);

    let mut d = data.clone();
    put32(&mut d, 96 + 16, 99);
    assert_eq!(parse(&d).unwrap_err(), ParseError::UnknownSectionType(99));

    let mut d = data.clone();
    d[96] = 0x01;
    assert_eq!(
        parse(&d).unwrap_err(),
        ParseError::Section(SectionError::InvalidName)
    );

    let mut d = data.clone();
    put64(&mut d, 96 + 40, 3);
    assert_eq!(parse(&d).unwrap_err(), ParseError::InvalidAlignment);

    let mut d = data.clone();
    put64(
        &mut d,
        96 + 24,
        HEADER_SIZE as u64 + SECTION_ENTRY_SIZE as u64 + 1,
    );
    assert_eq!(parse(&d).unwrap_err(), ParseError::UnalignedOffset);
}

#[test]
fn rejects_out_of_bounds_and_overflowing_payload() {
    let data = build(&[b".text"]);
    let total = data.len() as u64;

    let mut d = data.clone();
    put64(&mut d, 96 + 24, total);
    assert_eq!(parse(&d).unwrap_err(), ParseError::SectionOutOfBounds);

    let mut d = data;
    put64(&mut d, 96 + 24, u64::MAX - 7);
    assert_eq!(parse(&d).unwrap_err(), ParseError::SectionOutOfBounds);
}

#[test]
fn rejects_duplicate_section_names_and_overlaps() {
    let data = build(&[b".text", b".text"]);
    assert_eq!(parse(&data).unwrap_err(), ParseError::DuplicateSectionName);

    let mut data = build(&[b".text", b".rodata"]);
    // With two sections the first payload starts at 96 + 2*80 = 256.
    put32(
        &mut data,
        96 + SECTION_ENTRY_SIZE + 16,
        lmfk_drv_format::SECTION_TYPE_RODATA,
    );
    put64(&mut data, 96 + SECTION_ENTRY_SIZE + 24, 256);
    assert!(matches!(
        parse(&data).unwrap_err(),
        ParseError::Overlap { .. }
    ));
}

#[test]
fn rejects_package_without_text_section() {
    let mut data = build(&[b".rodata"]);
    put32(&mut data, 96 + 16, SECTION_TYPE_RODATA);
    put32(&mut data, 96 + 20, SECTION_F_ALLOC);
    assert_eq!(parse(&data).unwrap_err(), ParseError::MissingTextSection);
}

#[test]
fn rejects_bad_manifest_region() {
    let data = build(&[b".text"]);
    let total = data.len() as u64;

    let mut d = data.clone();
    put64(&mut d, 56, total + 8);
    assert_eq!(parse(&d).unwrap_err(), ParseError::ManifestOutOfBounds);

    let mut d = data.clone();
    put64(&mut d, 64, 0);
    assert_eq!(parse(&d).unwrap_err(), ParseError::ManifestOutOfBounds);

    let mut d = data;
    let (off, _) = manifest_range(&d);
    put64(&mut d, 56, 176); // overlaps the .text section
    assert!(matches!(parse(&d).unwrap_err(), ParseError::Overlap { .. }));
    assert!(off > 176);
}

#[test]
fn rejects_bad_signature_region_and_flag() {
    let data = build(&[b".text"]);
    let total = data.len() as u64;

    let mut d = data.clone();
    put64(&mut d, 72, total);
    assert_eq!(parse(&d).unwrap_err(), ParseError::SignatureOutOfBounds);

    let mut d = data;
    put32(&mut d, 12, 0); // signature present without the flag
    assert_eq!(parse(&d).unwrap_err(), ParseError::SignatureFlagMismatch);
}

#[test]
fn rejects_inconsistent_header_fields() {
    let data = build(&[b".text"]);

    let mut d = data.clone();
    put32(&mut d, 16, 0x0002_0000);
    assert_eq!(parse(&d).unwrap_err(), ParseError::AbiMismatch);

    let mut d = data;
    put32(&mut d, 28, arch_bit(2).unwrap());
    assert_eq!(parse(&d).unwrap_err(), ParseError::ArchMaskMismatch);
}

#[test]
fn rejects_corrupt_manifest_payload() {
    let data = build(&[b".text"]);
    let (off, end) = manifest_range(&data);

    let mut d = data.clone();
    d[off..end].fill(0xff);
    assert!(matches!(parse(&d).unwrap_err(), ParseError::Manifest(_)));
}

#[test]
fn rejects_manifest_with_duplicate_key() {
    let id = [0x22u8; 16];
    let manifest = cbor::encode_vec(&Value::Map(vec![
        (Value::Text("id"), Value::Bytes(&id)),
        (Value::Text("name"), Value::Text("first")),
        (Value::Text("name"), Value::Text("second")),
    ]));
    let data = build_with(&[b".text"], &manifest);
    assert!(matches!(parse(&data).unwrap_err(), ParseError::Manifest(_)));
}

#[test]
fn rejects_data_after_signature() {
    let mut data = build(&[b".text"]);
    let original_len = data.len();
    data.extend_from_slice(&[0xaa; 8]);
    let new_len = data.len() as u64;
    put64(&mut data, 40, new_len);
    assert!(matches!(
        parse(&data).unwrap_err(),
        ParseError::SignatureNotAtEnd { end, total }
            if end == original_len as u64 && total == data.len() as u64
    ));
}

#[test]
fn rejects_invalid_section_flags() {
    let data = build(&[b".text"]);

    let mut missing = data.clone();
    put32(&mut missing, 96 + 20, 0);
    assert!(matches!(
        parse(&missing).unwrap_err(),
        ParseError::InvalidSectionFlags { .. }
    ));

    let mut extra = data;
    put32(
        &mut extra,
        96 + 20,
        SECTION_F_ALLOC | SECTION_F_EXEC | SECTION_F_WRITE,
    );
    assert!(matches!(
        parse(&extra).unwrap_err(),
        ParseError::InvalidSectionFlags { .. }
    ));
}

#[test]
fn rejects_every_truncation() {
    let data = build(&[b".text"]);
    for length in 0..data.len() {
        assert!(
            parse(&data[..length]).is_err(),
            "truncation at {length} accepted"
        );
    }
}

#[test]
fn deterministic_mutation_fuzz_does_not_panic() {
    let original = build(&[b".text", b".rodata"]);
    let mut state = 0x1234_5678_9abc_def0u64;
    for _ in 0..2000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut data = original.clone();
        let index = (state >> 33) as usize % data.len();
        data[index] ^= (state >> 11) as u8 | 1;
        let _ = parse(&data);
    }
}

#[test]
fn rejects_manifest_schema_errors() {
    let id_short = [0x33u8; 15];
    let base = |id: Value<'_>| -> Vec<u8> {
        cbor::encode_vec(&Value::Map(vec![
            (Value::Text("id"), id),
            (Value::Text("name"), Value::Text("test-driver")),
            (Value::Text("version"), Value::Text("1.0.0")),
            (Value::Text("abi_min"), Value::Uint(ABI_MIN as u64)),
            (Value::Text("abi_max"), Value::Uint(ABI_MAX as u64)),
            (Value::Text("arch"), Value::Array(vec![Value::Uint(1)])),
            (
                Value::Text("devices"),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("bus"), Value::Uint(1)),
                    (Value::Text("vendor"), Value::Uint(0x8086)),
                    (Value::Text("device"), Value::Uint(0x9bc4)),
                ])]),
            ),
            (Value::Text("caps"), Value::Array(vec![])),
            (Value::Text("deps"), Value::Array(vec![])),
            (Value::Text("mode"), Value::Uint(1)),
            (Value::Text("entry"), Value::Text("lmfk_driver_entry")),
        ]))
    };

    let data = build_with(&[b".text"], &base(Value::Bytes(&id_short)));
    assert_eq!(
        parse(&data).unwrap_err(),
        ParseError::Manifest(ManifestError::InvalidIdLen(15))
    );

    let inverted = cbor::encode_vec(&Value::Map(vec![
        (Value::Text("id"), Value::Bytes(&[0x44u8; 16])),
        (Value::Text("name"), Value::Text("test-driver")),
        (Value::Text("version"), Value::Text("1.0.0")),
        (Value::Text("abi_min"), Value::Uint(ABI_MAX as u64)),
        (Value::Text("abi_max"), Value::Uint(ABI_MIN as u64)),
        (Value::Text("arch"), Value::Array(vec![Value::Uint(1)])),
        (
            Value::Text("devices"),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("bus"), Value::Uint(1)),
                (Value::Text("vendor"), Value::Uint(0x8086)),
                (Value::Text("device"), Value::Uint(0x9bc4)),
            ])]),
        ),
        (Value::Text("caps"), Value::Array(vec![])),
        (Value::Text("deps"), Value::Array(vec![])),
        (Value::Text("mode"), Value::Uint(1)),
        (Value::Text("entry"), Value::Text("lmfk_driver_entry")),
    ]));
    let data = build_with(&[b".text"], &inverted);
    // The header still carries ABI_MIN/ABI_MAX: the inconsistency is detected
    // even before manifest validation, which is acceptable.
    assert!(matches!(
        parse(&data).unwrap_err(),
        ParseError::AbiMismatch | ParseError::Manifest(ManifestError::InvalidAbiRange)
    ));

    let mut missing = base(Value::Bytes(&[0x55u8; 16]));
    // Remove the last pair ("entry") from the CBOR map.
    let decoded = cbor::decode(&missing).unwrap();
    if let Value::Map(mut entries) = decoded {
        entries.retain(|(key, _)| !matches!(key, Value::Text("entry")));
        missing = cbor::encode_vec(&Value::Map(entries));
    }
    let data = build_with(&[b".text"], &missing);
    assert_eq!(
        parse(&data).unwrap_err(),
        ParseError::Manifest(ManifestError::MissingField("entry"))
    );
}
