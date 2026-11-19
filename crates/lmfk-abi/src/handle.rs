use core::fmt;

/// Opaque token representing a framework resource (memory, device,
/// event, IPC channel, ...).
///
/// This is **never** a pointer: the value has no meaning outside the
/// framework that issued it, is stable regardless of the architecture
/// (always 64 bits), and 0 is reserved for "invalid".
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

    /// Raw value, useful for debugging or the internal IPC protocol.
    /// Do not reinterpret it as an address.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Constructs a handle from a raw value.
    ///
    /// # Safety
    /// The value must have been issued by the framework for this context.
    /// Fabricating an arbitrary handle is a violation of the ABI contract.
    pub const unsafe fn from_raw_unchecked(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle(0x{:016x})", self.0)
    }
}
