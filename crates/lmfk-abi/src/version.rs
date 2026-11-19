/// Native ABI profile selected by the target pointer width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiProfile {
    /// 32-bit pointers (armv7): function pointers are 4 bytes.
    Ilp32,
    /// 64-bit pointers (x86_64, aarch64): function pointers are 8 bytes.
    Lp64,
}

/// Query the ABI profile of the current compilation target.
pub const fn abi_profile() -> AbiProfile {
    if cfg!(target_pointer_width = "64") {
        AbiProfile::Lp64
    } else {
        AbiProfile::Ilp32
    }
}

/// Encoded ABI version: `major << 16 | minor`.
pub const ABI_V1: u32 = 0x0001_0000;

/// Version currently implemented by this crate.
pub const ABI_VERSION: u32 = ABI_V1;

/// Wildcard for "any minor within this major" (used in a range).
pub const ABI_ANY_MINOR: u16 = 0xffff;

pub const fn make_version(major: u16, minor: u16) -> u32 {
    ((major as u32) << 16) | (minor as u32)
}

pub const fn abi_major(version: u32) -> u16 {
    (version >> 16) as u16
}

pub const fn abi_minor(version: u32) -> u16 {
    version as u16
}

/// Range of versions accepted by a driver, declared in its manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRange {
    pub min: u32,
    pub max: u32,
}

impl VersionRange {
    pub const fn new(min: u32, max: u32) -> Self {
        Self { min, max }
    }

    /// `1.0 .. 1.x`: any minor of major 1.
    pub const fn v1() -> Self {
        Self::new(ABI_V1, make_version(1, ABI_ANY_MINOR))
    }

    /// True if `provided` satisfies the range.
    ///
    /// A different major is rejected immediately; otherwise the minor
    /// bounds apply only to the extreme majors of the range.
    pub const fn accepts(self, provided: u32) -> bool {
        let pmaj = abi_major(provided) as u32;
        let pmin = abi_minor(provided) as u32;
        let minmaj = abi_major(self.min) as u32;
        let minmin = abi_minor(self.min) as u32;
        let maxmaj = abi_major(self.max) as u32;
        let maxmin = abi_minor(self.max) as u32;

        if pmaj < minmaj || pmaj > maxmaj {
            return false;
        }
        if pmaj == minmaj && pmin < minmin {
            return false;
        }
        if pmaj == maxmaj && pmin > maxmin {
            return false;
        }
        true
    }
}

pub const fn is_compatible(min: u32, max: u32, provided: u32) -> bool {
    VersionRange::new(min, max).accepts(provided)
}
