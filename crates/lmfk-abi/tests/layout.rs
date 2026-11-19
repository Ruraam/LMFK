use lmfk_abi::{ABI_V1, Bus, DEVICE_NAME_LEN, DeviceDesc, DriverApi, DriverEntry, Handle, Status};
use std::mem::{align_of, offset_of, size_of};

#[test]
fn scalar_abi_types_have_fixed_size() {
    assert_eq!(size_of::<Handle>(), 8);
    assert_eq!(size_of::<Status>(), 4);
    assert_eq!(size_of::<Bus>(), 2);
}

#[test]
fn device_desc_layout_matches_c_header() {
    assert_eq!(DEVICE_NAME_LEN, 64);
    assert_eq!(size_of::<DeviceDesc>(), 96);
    assert_eq!(align_of::<DeviceDesc>(), 8);
    assert_eq!(offset_of!(DeviceDesc, size), 0);
    assert_eq!(offset_of!(DeviceDesc, bus), 4);
    assert_eq!(offset_of!(DeviceDesc, vendor_id), 8);
    assert_eq!(offset_of!(DeviceDesc, name), 32);
}

#[test]
fn driver_api_layout_matches_c_header() {
    assert_eq!(size_of::<DriverApi>(), 96);
    assert_eq!(align_of::<DriverApi>(), 8);
    assert_eq!(offset_of!(DriverApi, size), 0);
    assert_eq!(offset_of!(DriverApi, abi_version), 4);
    assert_eq!(offset_of!(DriverApi, log), 8);
    assert_eq!(offset_of!(DriverApi, mem_alloc), 16);
    assert_eq!(offset_of!(DriverApi, mmio_map), 32);
    assert_eq!(offset_of!(DriverApi, irq_register), 40);
    assert_eq!(offset_of!(DriverApi, dma_alloc), 56);
    assert_eq!(offset_of!(DriverApi, ipc_open), 64);
    assert_eq!(offset_of!(DriverApi, device_register), 72);
    assert_eq!(offset_of!(DriverApi, device_read), 80);
    assert_eq!(offset_of!(DriverApi, device_write), 88);
}

#[test]
fn driver_entry_layout_matches_c_header() {
    assert_eq!(size_of::<DriverEntry>(), 80);
    assert_eq!(align_of::<DriverEntry>(), 8);
    assert_eq!(offset_of!(DriverEntry, size), 0);
    assert_eq!(offset_of!(DriverEntry, init), 8);
    assert_eq!(offset_of!(DriverEntry, probe), 16);
    assert_eq!(offset_of!(DriverEntry, irq), 32);
    assert_eq!(offset_of!(DriverEntry, stop), 56);
    assert_eq!(offset_of!(DriverEntry, shutdown), 72);
}

#[test]
fn constructors_publish_their_size() {
    let api = DriverApi::new(ABI_V1);
    assert_eq!(api.size as usize, size_of::<DriverApi>());
    assert_eq!(api.abi_version, ABI_V1);
    assert!(api.log.is_none());
    assert!(api.meets_v1());

    let entry = DriverEntry::new(ABI_V1);
    assert_eq!(entry.size as usize, size_of::<DriverEntry>());
    assert_eq!(entry.abi_version, ABI_V1);
    assert!(entry.init.is_none());

    let desc = DeviceDesc::new(Bus::PCI, 0x8086, 0x9bc4, 0, 0, 0x030000, 0, b"eth0");
    assert_eq!(desc.size as usize, size_of::<DeviceDesc>());
    assert_eq!(desc.vendor_id, 0x8086);
    assert_eq!(&desc.name[..4], b"eth0");
    assert_eq!(desc.name[4], 0);
    assert_eq!(desc.reserved0, 0);
}

#[test]
fn undersized_structures_are_rejected() {
    let mut api = DriverApi::new(ABI_V1);
    api.size = 8;
    assert!(!api.meets_v1());
    assert!(api.meets_min_size(8));
    assert!(api.supports(lmfk_abi::VersionRange::v1()));
}
