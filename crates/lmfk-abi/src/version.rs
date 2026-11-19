/// Version de l'ABI encodee : `major << 16 | minor`.
pub const ABI_V1: u32 = 0x0001_0000;

/// Version actuellement implementee par cette crate.
pub const ABI_VERSION: u32 = ABI_V1;

/// Joker pour « tout minor dans ce major » (utilise dans une plage).
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

/// Plage de versions acceptee par un pilote, declaree dans son manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRange {
    pub min: u32,
    pub max: u32,
}

impl VersionRange {
    pub const fn new(min: u32, max: u32) -> Self {
        Self { min, max }
    }

    /// `1.0 .. 1.x` : tout minor de la majeure 1.
    pub const fn v1() -> Self {
        Self::new(ABI_V1, make_version(1, ABI_ANY_MINOR))
    }

    /// True si `provided` satisfait la plage.
    ///
    /// Un major different est rejete immediatement ; sinon les bornes de
    /// minor ne s'appliquent qu'aux majors extremes de la plage.
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
