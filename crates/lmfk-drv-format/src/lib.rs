#![no_std]

//! Binary definitions of the `.drv` v1 package.
//!
//! The container is little-endian; the CBOR manifest is big-endian and
//! deterministic. This crate does not validate relationships between regions:
//! that is the role of `lmfk-drv-parser`.

extern crate alloc;

pub mod cbor;
pub mod manifest;

pub use manifest::{Dependency, DeviceMatch, DriverMode, Manifest};

use core::convert::TryFrom;

/* ------------------------------------------------------------------------- */
/* Container constants                                                        */
/* ------------------------------------------------------------------------- */

pub const DRV_MAGIC: &[u8; 8] = b"LMFKDRV\0";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 96;
pub const SECTION_ENTRY_SIZE: usize = 80;
pub const SECTION_NAME_LEN: usize = 16;
pub const MAX_SECTIONS: u32 = 256;

pub const ARCH_X86_64: u32 = 1;
pub const ARCH_AARCH64: u32 = 2;
pub const ARCH_ARMV7: u32 = 3;
pub const ARCH_RISCV64: u32 = 4;
pub const ARCH_COUNT: u32 = 4;

pub const SECTION_TYPE_TEXT: u32 = 1;
pub const SECTION_TYPE_RODATA: u32 = 2;
pub const SECTION_TYPE_DATA: u32 = 3;
pub const SECTION_TYPE_BSS: u32 = 4;
pub const SECTION_TYPE_RELOC: u32 = 5;
pub const SECTION_TYPE_RESOURCE: u32 = 6;

pub const SECTION_F_ALLOC: u32 = 1;
pub const SECTION_F_EXEC: u32 = 2;
pub const SECTION_F_WRITE: u32 = 4;

pub const PKG_F_SIGNED: u32 = 1;
pub const PKG_F_COMPRESSED: u32 = 2;
pub const PKG_F_RELOCATABLE: u32 = 4;
pub const PKG_F_KNOWN: u32 = PKG_F_SIGNED | PKG_F_COMPRESSED | PKG_F_RELOCATABLE;

/* ------------------------------------------------------------------------- */
/* Little-endian read/write                                                  */
/* ------------------------------------------------------------------------- */

pub mod le {
    use core::convert::TryInto;

    /// Reads a u16 at offset 0 of the slice. The slice must contain 2 bytes.
    pub fn u16le(bytes: &[u8]) -> u16 {
        u16::from_le_bytes(bytes[..2].try_into().unwrap())
    }

    pub fn u32le(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    pub fn u64le(bytes: &[u8]) -> u64 {
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }

    pub fn put_u16(buf: &mut [u8], value: u16) {
        buf[..2].copy_from_slice(&value.to_le_bytes());
    }

    pub fn put_u32(buf: &mut [u8], value: u32) {
        buf[..4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn put_u64(buf: &mut [u8], value: u64) {
        buf[..8].copy_from_slice(&value.to_le_bytes());
    }
}

/* ------------------------------------------------------------------------- */
/* Header                                                                     */
/* ------------------------------------------------------------------------- */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u16),
    BadHeaderSize(u16),
    ReservedNotNull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub format_version: u16,
    pub flags: u32,
    pub abi_min: u32,
    pub abi_max: u32,
    pub section_count: u32,
    pub arch_mask: u32,
    pub total_size: u64,
    pub section_table_offset: u64,
    pub manifest_offset: u64,
    pub manifest_length: u64,
    pub signature_offset: u64,
    pub signature_length: u64,
}

impl Header {
    /// Decodes the header and validates the self-contained fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderError> {
        if bytes.len() < HEADER_SIZE {
            return Err(HeaderError::TooShort);
        }
        if &bytes[0..8] != DRV_MAGIC {
            return Err(HeaderError::BadMagic);
        }
        let format_version = le::u16le(&bytes[8..]);
        if format_version != FORMAT_VERSION {
            return Err(HeaderError::UnsupportedVersion(format_version));
        }
        let header_size = le::u16le(&bytes[10..]);
        if header_size as usize != HEADER_SIZE {
            return Err(HeaderError::BadHeaderSize(header_size));
        }
        if le::u32le(&bytes[32..]) != 0
            || le::u32le(&bytes[36..]) != 0
            || le::u64le(&bytes[88..]) != 0
        {
            return Err(HeaderError::ReservedNotNull);
        }

        Ok(Self {
            format_version,
            flags: le::u32le(&bytes[12..]),
            abi_min: le::u32le(&bytes[16..]),
            abi_max: le::u32le(&bytes[20..]),
            section_count: le::u32le(&bytes[24..]),
            arch_mask: le::u32le(&bytes[28..]),
            total_size: le::u64le(&bytes[40..]),
            section_table_offset: le::u64le(&bytes[48..]),
            manifest_offset: le::u64le(&bytes[56..]),
            manifest_length: le::u64le(&bytes[64..]),
            signature_offset: le::u64le(&bytes[72..]),
            signature_length: le::u64le(&bytes[80..]),
        })
    }

    /// Writes a header into a 96-byte buffer.
    pub fn to_bytes(&self, out: &mut [u8]) {
        debug_assert!(out.len() >= HEADER_SIZE);
        out[..HEADER_SIZE].fill(0);
        out[0..8].copy_from_slice(DRV_MAGIC);
        le::put_u16(&mut out[8..], self.format_version);
        le::put_u16(&mut out[10..], HEADER_SIZE as u16);
        le::put_u32(&mut out[12..], self.flags);
        le::put_u32(&mut out[16..], self.abi_min);
        le::put_u32(&mut out[20..], self.abi_max);
        le::put_u32(&mut out[24..], self.section_count);
        le::put_u32(&mut out[28..], self.arch_mask);
        le::put_u64(&mut out[40..], self.total_size);
        le::put_u64(&mut out[48..], self.section_table_offset);
        le::put_u64(&mut out[56..], self.manifest_offset);
        le::put_u64(&mut out[64..], self.manifest_length);
        le::put_u64(&mut out[72..], self.signature_offset);
        le::put_u64(&mut out[80..], self.signature_length);
    }
}

/* ------------------------------------------------------------------------- */
/* Section table entry                                                       */
/* ------------------------------------------------------------------------- */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionError {
    TooShort,
    InvalidName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionHeader<'a> {
    /// Name without the padding NUL.
    pub name: &'a [u8],
    pub ty: u32,
    pub flags: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u64,
    pub sha256: [u8; 32],
}

impl<'a> SectionHeader<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, SectionError> {
        if bytes.len() < SECTION_ENTRY_SIZE {
            return Err(SectionError::TooShort);
        }
        let raw = &bytes[..SECTION_NAME_LEN];
        let nul = raw.iter().position(|&b| b == 0).unwrap_or(SECTION_NAME_LEN);
        if nul == 0 || raw[..nul].iter().any(|&b| !(0x20..=0x7e).contains(&b)) {
            return Err(SectionError::InvalidName);
        }
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&bytes[48..80]);
        Ok(Self {
            name: &raw[..nul],
            ty: le::u32le(&bytes[16..]),
            flags: le::u32le(&bytes[20..]),
            offset: le::u64le(&bytes[24..]),
            size: le::u64le(&bytes[32..]),
            align: le::u64le(&bytes[40..]),
            sha256,
        })
    }

    pub fn to_bytes(&self, out: &mut [u8]) {
        debug_assert!(out.len() >= SECTION_ENTRY_SIZE);
        out[..SECTION_ENTRY_SIZE].fill(0);
        let n = self.name.len().min(SECTION_NAME_LEN);
        out[..n].copy_from_slice(&self.name[..n]);
        le::put_u32(&mut out[16..], self.ty);
        le::put_u32(&mut out[20..], self.flags);
        le::put_u64(&mut out[24..], self.offset);
        le::put_u64(&mut out[32..], self.size);
        le::put_u64(&mut out[40..], self.align);
        out[48..80].copy_from_slice(&self.sha256);
    }
}

/// Converts an architecture code into a mask bit.
pub const fn arch_bit(code: u32) -> Option<u32> {
    if code == 0 || code > ARCH_COUNT {
        None
    } else {
        Some(1u32 << (code - 1))
    }
}

/// Checks that a `u64` size is representable as `usize` on the target.
pub fn fits_usize(value: u64) -> bool {
    usize::try_from(value).is_ok()
}
