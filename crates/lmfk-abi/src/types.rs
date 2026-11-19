use core::mem::size_of;

/// Length of the `name` field of [`DeviceDesc`], in bytes.
pub const DEVICE_NAME_LEN: usize = 64;

/// Bus identifier. Newtype over `u16`: no Rust enum crosses
/// the ABI boundary (its representation is not guaranteed).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Bus(pub u16);

impl Bus {
    pub const UNKNOWN: Self = Self(0);
    pub const PCI: Self = Self(1);
    pub const USB: Self = Self(2);
    pub const ACPI: Self = Self(3);
    pub const DT: Self = Self(4);
    pub const PLATFORM: Self = Self(5);
}

/// Description of a device, filled in by the framework and read by
/// the driver. No pointers, no architecture-dependent types.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct DeviceDesc {
    /// Always `size_of::<DeviceDesc>()` when writing.
    pub size: u32,
    pub bus: Bus,
    /// Reserved, must be 0.
    pub reserved0: u16,
    pub vendor_id: u32,
    pub device_id: u32,
    pub sub_vendor_id: u32,
    pub sub_device_id: u32,
    pub class_code: u32,
    /// Unique index on the bus.
    pub instance: u32,
    /// UTF-8, not guaranteed to be NUL-terminated: use the producer's
    /// useful length (unused bytes are zeroed).
    pub name: [u8; DEVICE_NAME_LEN],
}

impl DeviceDesc {
    pub const SIZE: usize = size_of::<Self>();

    /// Constructs a properly initialized descriptor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bus: Bus,
        vendor_id: u32,
        device_id: u32,
        sub_vendor_id: u32,
        sub_device_id: u32,
        class_code: u32,
        instance: u32,
        name: &[u8],
    ) -> Self {
        let mut out = Self {
            size: Self::SIZE as u32,
            bus,
            reserved0: 0,
            vendor_id,
            device_id,
            sub_vendor_id,
            sub_device_id,
            class_code,
            instance,
            name: [0; DEVICE_NAME_LEN],
        };
        let n = name.len().min(DEVICE_NAME_LEN);
        out.name[..n].copy_from_slice(&name[..n]);
        out
    }
}
