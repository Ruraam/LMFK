use core::fmt;

/// Jeton opaque representant une ressource du framework (memoire, device,
/// evenement, canal IPC, ...).
///
/// Ce n'est **jamais** un pointeur : la valeur n'a aucune signification
/// hors du framework qui l'a emise, est stable quelle que soit l'architecture
/// (toujours 64 bits) et 0 est reserve pour « invalide ».
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(u64);

impl Handle {
    pub const INVALID: Self = Self(0);

    pub const fn is_invalid(self) -> bool {
        self.0 == 0
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }

    /// Valeur brute, utile pour le debogage ou le protocole IPC interne.
    /// Ne pas la reinterpretter comme une adresse.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Construit un handle a partir d'une valeur brute.
    ///
    /// # Safety
    /// La valeur doit avoir ete emise par le framework pour ce contexte.
    /// Fabriquer un handle arbitraire est une violation du contrat ABI.
    pub const unsafe fn from_raw_unchecked(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle(0x{:016x})", self.0)
    }
}
