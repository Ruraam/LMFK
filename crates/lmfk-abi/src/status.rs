use core::fmt;

/// Code de retour stable. Les valeurs sont fixees par le contrat ABI et ne
/// doivent jamais etre reutilisees pour un autre sens.
///
/// `repr(transparent)` sur `i32` garantit la representation C (`int32_t`)
/// sans deposer sur une enum Rust dont les discriminants pourraient changer.
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

    /// Construit un statut a partir d'une valeur recue de l'ABI.
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
