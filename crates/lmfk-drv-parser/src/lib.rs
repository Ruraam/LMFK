//! Parser and validator for `.drv` packages.
//!
//! All reads are bounded and all offset calculations use checked
//! arithmetic. No section is executed and nothing is cryptographically
//! verified here: the parser only guarantees that the container is
//! consistent and securable.

use core::convert::TryFrom;

use lmfk_drv_format::{
    HEADER_SIZE, Header, HeaderError, MAX_SECTIONS, Manifest, PKG_F_COMPRESSED, PKG_F_KNOWN,
    PKG_F_SIGNED, SECTION_ENTRY_SIZE, SECTION_TYPE_BSS, SECTION_TYPE_DATA, SECTION_TYPE_RELOC,
    SECTION_TYPE_RESOURCE, SECTION_TYPE_RODATA, SECTION_TYPE_TEXT, SectionError, SectionHeader,
    arch_bit,
};

pub use lmfk_drv_format::manifest::Error as ManifestError;

use lmfk_drv_format::manifest::decode as decode_manifest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    Header(HeaderError),
    Section(SectionError),
    Manifest(ManifestError),
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    UnsupportedFlag(u32),
    TooManySections,
    TableOutOfBounds,
    SectionOutOfBounds,
    UnalignedOffset,
    InvalidAlignment,
    UnknownSectionType(u32),
    InvalidSectionFlags {
        ty: u32,
        flags: u32,
    },
    DuplicateSectionName,
    Overlap {
        first: &'static str,
        second: &'static str,
    },
    MissingTextSection,
    ManifestOutOfBounds,
    SignatureOutOfBounds,
    SignatureNotAtEnd {
        end: u64,
        total: u64,
    },
    SignatureFlagMismatch,
    AbiMismatch,
    ArchMaskMismatch,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Header(e) => write!(f, "invalid header: {e:?}"),
            Self::Section(e) => write!(f, "invalid section: {e:?}"),
            Self::Manifest(e) => write!(f, "invalid manifest: {e:?}"),
            Self::SizeMismatch { expected, actual } => {
                write!(f, "size mismatch: header says {expected}, file is {actual}")
            }
            Self::UnsupportedFlag(f0) => write!(f, "unsupported package flag: {f0:#x}"),
            Self::TooManySections => f.write_str("too many sections"),
            Self::TableOutOfBounds => f.write_str("section table out of bounds"),
            Self::SectionOutOfBounds => f.write_str("section payload out of bounds"),
            Self::UnalignedOffset => f.write_str("unaligned section offset"),
            Self::InvalidAlignment => f.write_str("invalid section alignment"),
            Self::UnknownSectionType(t) => write!(f, "unknown section type: {t}"),
            Self::InvalidSectionFlags { ty, flags } => {
                write!(f, "invalid flags {flags:#x} for section type {ty}")
            }
            Self::DuplicateSectionName => f.write_str("duplicate section name"),
            Self::Overlap { first, second } => write!(f, "overlap between {first} and {second}"),
            Self::MissingTextSection => f.write_str("no TEXT section"),
            Self::ManifestOutOfBounds => f.write_str("manifest out of bounds"),
            Self::SignatureOutOfBounds => f.write_str("signature out of bounds"),
            Self::SignatureNotAtEnd { end, total } => {
                write!(f, "signature ends at {end} but file is {total} bytes")
            }
            Self::SignatureFlagMismatch => f.write_str("signature flag/length mismatch"),
            Self::AbiMismatch => f.write_str("header/manifest ABI mismatch"),
            Self::ArchMaskMismatch => f.write_str("header/manifest architecture mismatch"),
        }
    }
}

/// View of a section of the package. `data` is empty for a BSS section.
#[derive(Clone, Copy, Debug)]
pub struct Section<'a> {
    pub header: SectionHeader<'a>,
    pub data: &'a [u8],
}

/// Valid `.drv` package. All slices point into the source buffer.
#[derive(Clone, Debug)]
pub struct DrvFile<'a> {
    data: &'a [u8],
    header: Header,
    sections: Vec<Section<'a>>,
    manifest: Manifest<'a>,
    signature: &'a [u8],
}

impl<'a> DrvFile<'a> {
    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn manifest(&self) -> &Manifest<'a> {
        &self.manifest
    }

    pub fn sections(&self) -> &[Section<'a>] {
        &self.sections
    }

    pub fn section(&self, name: &[u8]) -> Option<&Section<'a>> {
        self.sections.iter().find(|s| s.header.name == name)
    }

    /// Raw bytes of the signature area (not verified here).
    pub fn signature(&self) -> &'a [u8] {
        self.signature
    }

    /// Region covered by the signature: everything before the area.
    pub fn signed_region(&self) -> &'a [u8] {
        if self.header.signature_length == 0 {
            self.data
        } else {
            let end = self.header.signature_offset as usize;
            &self.data[..end]
        }
    }

    pub fn raw(&self) -> &'a [u8] {
        self.data
    }
}

/* ------------------------------------------------------------------------- */
/* Internal utilities                                                         */
/* ------------------------------------------------------------------------- */

fn is_aligned(value: u64, align: u64) -> bool {
    align != 0 && value % align == 0
}

fn byte_slice(data: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(len).ok()?;
    let end = start.checked_add(len)?;
    data.get(start..end)
}

#[derive(Clone, Copy)]
struct Region {
    start: u64,
    end: u64,
    kind: &'static str,
}

fn check_overlaps(regions: &mut [Region]) -> Result<(), ParseError> {
    regions.sort_unstable_by_key(|r| r.start);
    for pair in regions.windows(2) {
        if pair[0].end > pair[1].start {
            return Err(ParseError::Overlap {
                first: pair[0].kind,
                second: pair[1].kind,
            });
        }
    }
    Ok(())
}

fn known_section_type(ty: u32) -> bool {
    matches!(
        ty,
        SECTION_TYPE_TEXT
            | SECTION_TYPE_RODATA
            | SECTION_TYPE_DATA
            | SECTION_TYPE_BSS
            | SECTION_TYPE_RELOC
            | SECTION_TYPE_RESOURCE
    )
}

/// (allowed mask, required mask) for each section type.
fn section_flags(ty: u32) -> (u32, u32) {
    use lmfk_drv_format::{SECTION_F_ALLOC, SECTION_F_EXEC, SECTION_F_WRITE};
    match ty {
        SECTION_TYPE_TEXT => (
            SECTION_F_ALLOC | SECTION_F_EXEC,
            SECTION_F_ALLOC | SECTION_F_EXEC,
        ),
        SECTION_TYPE_RODATA => (SECTION_F_ALLOC, SECTION_F_ALLOC),
        SECTION_TYPE_DATA => (
            SECTION_F_ALLOC | SECTION_F_WRITE,
            SECTION_F_ALLOC | SECTION_F_WRITE,
        ),
        SECTION_TYPE_BSS => (
            SECTION_F_ALLOC | SECTION_F_WRITE,
            SECTION_F_ALLOC | SECTION_F_WRITE,
        ),
        SECTION_TYPE_RELOC | SECTION_TYPE_RESOURCE => (0, 0),
        _ => (0, 0),
    }
}

/* ------------------------------------------------------------------------- */
/* Main parse                                                                 */
/* ------------------------------------------------------------------------- */

/// Parses and validates a package. No data is copied.
pub fn parse(data: &[u8]) -> Result<DrvFile<'_>, ParseError> {
    let header = Header::from_bytes(data).map_err(ParseError::Header)?;

    let actual = match u64::try_from(data.len()) {
        Ok(v) => v,
        Err(_) => {
            return Err(ParseError::SizeMismatch {
                expected: header.total_size,
                actual: 0,
            });
        }
    };
    if header.total_size != actual {
        return Err(ParseError::SizeMismatch {
            expected: header.total_size,
            actual,
        });
    }
    if header.flags & !PKG_F_KNOWN != 0 || header.flags & PKG_F_COMPRESSED != 0 {
        return Err(ParseError::UnsupportedFlag(header.flags));
    }
    if header.section_count == 0 || header.section_count > MAX_SECTIONS {
        return Err(ParseError::TooManySections);
    }

    let mut regions = vec![Region {
        start: 0,
        end: HEADER_SIZE as u64,
        kind: "header",
    }];

    // Section table.
    let table_size = (header.section_count as u64)
        .checked_mul(SECTION_ENTRY_SIZE as u64)
        .ok_or(ParseError::TableOutOfBounds)?;
    let table_end = header
        .section_table_offset
        .checked_add(table_size)
        .ok_or(ParseError::TableOutOfBounds)?;
    if header.section_table_offset < HEADER_SIZE as u64
        || !is_aligned(header.section_table_offset, 8)
        || table_end > actual
    {
        return Err(ParseError::TableOutOfBounds);
    }
    let table = byte_slice(data, header.section_table_offset, table_size)
        .ok_or(ParseError::TableOutOfBounds)?;
    regions.push(Region {
        start: header.section_table_offset,
        end: table_end,
        kind: "section table",
    });

    // Sections.
    let mut sections: Vec<Section<'_>> = Vec::with_capacity(header.section_count as usize);
    let mut names: Vec<&[u8]> = Vec::with_capacity(header.section_count as usize);
    for index in 0..header.section_count as usize {
        let start = index * SECTION_ENTRY_SIZE;
        let entry = &table[start..start + SECTION_ENTRY_SIZE];
        let sh = SectionHeader::from_bytes(entry).map_err(ParseError::Section)?;
        if !known_section_type(sh.ty) {
            return Err(ParseError::UnknownSectionType(sh.ty));
        }
        let (allowed, required) = section_flags(sh.ty);
        if sh.flags & !allowed != 0 || sh.flags & required != required {
            return Err(ParseError::InvalidSectionFlags {
                ty: sh.ty,
                flags: sh.flags,
            });
        }
        if sh.align == 0 || !sh.align.is_power_of_two() {
            return Err(ParseError::InvalidAlignment);
        }
        if !is_aligned(sh.offset, sh.align) {
            return Err(ParseError::UnalignedOffset);
        }
        if names.contains(&sh.name) {
            return Err(ParseError::DuplicateSectionName);
        }
        names.push(sh.name);

        let payload = if sh.ty == SECTION_TYPE_BSS {
            &[][..]
        } else {
            let end = sh
                .offset
                .checked_add(sh.size)
                .ok_or(ParseError::SectionOutOfBounds)?;
            if end > actual {
                return Err(ParseError::SectionOutOfBounds);
            }
            let slice =
                byte_slice(data, sh.offset, sh.size).ok_or(ParseError::SectionOutOfBounds)?;
            regions.push(Region {
                start: sh.offset,
                end,
                kind: "section",
            });
            slice
        };
        sections.push(Section {
            header: sh,
            data: payload,
        });
    }
    if !sections.iter().any(|s| s.header.ty == SECTION_TYPE_TEXT) {
        return Err(ParseError::MissingTextSection);
    }

    // Manifest.
    let manifest_end = header
        .manifest_offset
        .checked_add(header.manifest_length)
        .ok_or(ParseError::ManifestOutOfBounds)?;
    if header.manifest_length == 0
        || header.manifest_offset < HEADER_SIZE as u64
        || !is_aligned(header.manifest_offset, 8)
        || manifest_end > actual
    {
        return Err(ParseError::ManifestOutOfBounds);
    }
    let manifest_bytes = byte_slice(data, header.manifest_offset, header.manifest_length)
        .ok_or(ParseError::ManifestOutOfBounds)?;
    regions.push(Region {
        start: header.manifest_offset,
        end: manifest_end,
        kind: "manifest",
    });

    // Signature.
    let signature = if header.signature_length == 0 {
        if header.signature_offset != 0 {
            return Err(ParseError::SignatureOutOfBounds);
        }
        &[][..]
    } else {
        if !is_aligned(header.signature_offset, 8) {
            return Err(ParseError::SignatureOutOfBounds);
        }
        let sig_end = header
            .signature_offset
            .checked_add(header.signature_length)
            .ok_or(ParseError::SignatureOutOfBounds)?;
        if sig_end > actual {
            return Err(ParseError::SignatureOutOfBounds);
        }
        let bytes = byte_slice(data, header.signature_offset, header.signature_length)
            .ok_or(ParseError::SignatureOutOfBounds)?;
        regions.push(Region {
            start: header.signature_offset,
            end: sig_end,
            kind: "signature",
        });
        bytes
    };
    if (header.flags & PKG_F_SIGNED != 0) != (header.signature_length != 0) {
        return Err(ParseError::SignatureFlagMismatch);
    }
    if header.signature_length != 0 {
        let end = header
            .signature_offset
            .checked_add(header.signature_length)
            .ok_or(ParseError::SignatureOutOfBounds)?;
        if end != actual {
            return Err(ParseError::SignatureNotAtEnd { end, total: actual });
        }
    }

    check_overlaps(&mut regions)?;

    let manifest = decode_manifest(manifest_bytes).map_err(ParseError::Manifest)?;

    if manifest.abi_min != header.abi_min || manifest.abi_max != header.abi_max {
        return Err(ParseError::AbiMismatch);
    }
    let arch_mask = manifest
        .arch
        .iter()
        .fold(0u32, |mask, &code| mask | arch_bit(code).unwrap_or(0));
    if arch_mask != header.arch_mask {
        return Err(ParseError::ArchMaskMismatch);
    }

    Ok(DrvFile {
        data,
        header,
        sections,
        manifest,
        signature,
    })
}

#[cfg(test)]
mod tests;
