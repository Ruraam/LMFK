use core::mem::size_of;

/// Longueur du champ `name` de [`DeviceDesc`], en octets.
pub const DEVICE_NAME_LEN: usize = 64;

/// Identifiant de bus. Nouveau type sur `u16` : aucune enum Rust ne
/// traverse la frontiere ABI (sa representation n'est pas garantie).
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

/// Description d'un peripherique, remplie par le framework et lue par le
/// pilote. Aucun pointeur, aucun type dependant de l'architecture.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct DeviceDesc {
    /// Toujours `size_of::<DeviceDesc>()` a l'ecriture.
    pub size: u32,
    pub bus: Bus,
    /// Reserve, doit etre 0.
    pub reserved0: u16,
    pub vendor_id: u32,
    pub device_id: u32,
    pub sub_vendor_id: u32,
    pub sub_device_id: u32,
    pub class_code: u32,
    /// Index unique sur le bus.
    pub instance: u32,
    /// UTF-8, non garanti NUL-termine : utiliser la longueur utile du
    /// producteur (les octets non utilises sont zeroes).
    pub name: [u8; DEVICE_NAME_LEN],
}

impl DeviceDesc {
    pub const SIZE: usize = size_of::<Self>();

    /// Construit un descripteur correctement initialise.
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
