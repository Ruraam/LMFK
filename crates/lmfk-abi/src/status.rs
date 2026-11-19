use core::fmt;

/// Stable return code. The values are fixed by the ABI contract and must
/// never be reused for another meaning.
///
/// `repr(transparent)` on `i32` guarantees the C representation (`int32_t`)
/// without relying on a Rust enum whose discriminants could change.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Status(pub i32);

impl Status {
    pub const OK: Self = Self(0);
    pub const ERR_UNKNOWN: Self = Self(-1);
    pub const ERR_INVAL: Self = Self(-2);
    pub const ERR_NOMEM: Self = Self(-3);
    pub const ERR_NOTSUP: Self = Self(-4);
    pub const ERR_NOSYS: Self = Self(-5);
    pub const ERR_BUSY: Self = Self(-6);
    pub const ERR_TIMEOUT: Self = Self(-7);
    pub const ERR_IO: Self = Self(-8);
    pub const ERR_PERM: Self = Self(-9);
    pub const ERR_NOTFOUND: Self = Self(-10);
    pub const ERR_ABI_MISMATCH: Self = Self(-11);
    pub const ERR_ALREADY: Self = Self(-12);
    pub const ERR_AGAIN: Self = Self(-13);

    /// Constructs a status from a value received from the ABI.
    pub const fn from_raw(code: i32) -> Self {
        Self(code)
    }

    pub const fn code(self) -> i32 {
        self.0
    }

    pub const fn is_ok(self) -> bool {
        self.0 == 0
    }

    pub const fn is_err(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::OK => Some("OK"),
            Self::ERR_UNKNOWN => Some("ERR_UNKNOWN"),
            Self::ERR_INVAL => Some("ERR_INVAL"),
            Self::ERR_NOMEM => Some("ERR_NOMEM"),
            Self::ERR_NOTSUP => Some("ERR_NOTSUP"),
            Self::ERR_NOSYS => Some("ERR_NOSYS"),
            Self::ERR_BUSY => Some("ERR_BUSY"),
            Self::ERR_TIMEOUT => Some("ERR_TIMEOUT"),
            Self::ERR_IO => Some("ERR_IO"),
            Self::ERR_PERM => Some("ERR_PERM"),
            Self::ERR_NOTFOUND => Some("ERR_NOTFOUND"),
            Self::ERR_ABI_MISMATCH => Some("ERR_ABI_MISMATCH"),
            Self::ERR_ALREADY => Some("ERR_ALREADY"),
            Self::ERR_AGAIN => Some("ERR_AGAIN"),
            _ => None,
        };
        match name {
            Some(n) => f.write_str(n),
            None => write!(f, "Status({})", self.0),
        }
    }
}
