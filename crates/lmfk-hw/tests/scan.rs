//! Phase 1 tests: synthetic sysfs trees, no real hardware and no root.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use lmfk_core::{DriverState, Host, SCHEMA_VERSION, SecureBoot, validate_json};
use lmfk_hw::{ScanOptions, scan};

const SCHEMA_JSON: &str = include_str!("../../../docs/en/06-inventory-schema.json");

fn schema_validator() -> jsonschema::Validator {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA_JSON).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("lmfk-hw-{name}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn symlink(&self, relative: &str, target: &str) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &path).unwrap();
    }

    fn snapshot(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        visit(&self.root, &self.root, &mut out);
        out
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn visit(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let key = path.strip_prefix(base).unwrap().display().to_string();
        let metadata = fs::symlink_metadata(&path).unwrap();
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path).unwrap();
            out.insert(key, format!("symlink:{}", target.display()));
        } else if metadata.is_dir() {
            out.insert(key, "dir".to_owned());
            visit(base, &path, out);
        } else {
            out.insert(key, fs::read_to_string(&path).unwrap_or_default());
        }
    }
}

fn host() -> Host {
    Host {
        kernel_release: "6.1.0-test".to_owned(),
        kernel_version: "#1 SMP test".to_owned(),
        arch: "x86_64".to_owned(),
        distro_id: "example-distro".to_owned(),
        distro_version: "1".to_owned(),
        secure_boot: SecureBoot::Unknown,
    }
}

fn scan_fixture(fixture: &Fixture) -> lmfk_core::Inventory {
    let options = ScanOptions::new(&fixture.root, host(), "2026-11-20T10:00:00Z");
    scan(&options)
}

fn build_full_fixture() -> Fixture {
    let fixture = Fixture::new("full");
    // PCI VGA with a bound driver.
    fixture.write("bus/pci/devices/0000:00:02.0/vendor", "0x8086\n");
    fixture.write("bus/pci/devices/0000:00:02.0/device", "0x9bc4\n");
    fixture.write("bus/pci/devices/0000:00:02.0/subsystem_vendor", "0x8086\n");
    fixture.write("bus/pci/devices/0000:00:02.0/subsystem_device", "0x0000\n");
    fixture.write("bus/pci/devices/0000:00:02.0/class", "0x030000\n");
    fixture.write(
        "bus/pci/devices/0000:00:02.0/modalias",
        "pci:v00008086d00009BC4sv00008086sd00000000bc03sc00i00\n",
    );
    fixture.symlink(
        "bus/pci/devices/0000:00:02.0/driver",
        "../../../../drivers/i915",
    );
    // PCI network, no driver.
    fixture.write("bus/pci/devices/0000:03:00.0/vendor", "0x8086\n");
    fixture.write("bus/pci/devices/0000:03:00.0/device", "0x157b\n");
    fixture.write("bus/pci/devices/0000:03:00.0/class", "0x020000\n");
    fixture.write(
        "bus/pci/devices/0000:03:00.0/modalias",
        "pci:v00008086d0000157Bsv00008086sd00000000bc02sc00i00\n",
    );
    // USB composite device with two interfaces.
    fixture.write("bus/usb/devices/1-4/idVendor", "0x0bda\n");
    fixture.write("bus/usb/devices/1-4/idProduct", "0x8812\n");
    fixture.write("bus/usb/devices/1-4/bDeviceClass", "0x00\n");
    fixture.write(
        "bus/usb/devices/1-4/modalias",
        "usb:v0BDAp8812d0000dc00dsc00dp00ic00isc00if00\n",
    );
    fixture.write("bus/usb/devices/1-4/1-4:1.0/bInterfaceClass", "0x02\n");
    fixture.write(
        "bus/usb/devices/1-4/1-4:1.0/modalias",
        "usb:v0BDAp8812d0000dc02dsc00dp00ic02isc00if00\n",
    );
    fixture.symlink(
        "bus/usb/devices/1-4/1-4:1.0/driver",
        "../../../../../drivers/cdc_acm",
    );
    fixture.write("bus/usb/devices/1-4/1-4:1.1/bInterfaceClass", "0xe0\n");
    fixture.write(
        "bus/usb/devices/1-4/1-4:1.1/modalias",
        "usb:v0BDAp8812d0000dc0adsc00dp00ic0aisc00if00\n",
    );
    // USB single-interface device.
    fixture.write("bus/usb/devices/1-2/idVendor", "0x046d\n");
    fixture.write("bus/usb/devices/1-2/idProduct", "0x0825\n");
    fixture.write("bus/usb/devices/1-2/bDeviceClass", "0x03\n");
    fixture.write(
        "bus/usb/devices/1-2/modalias",
        "usb:v046Dp0825d0000dc00dsc00dp00ic03isc01if02\n",
    );
    fixture.write("bus/usb/devices/1-2/1-2:1.0/bInterfaceClass", "0x03\n");
    fixture.write(
        "bus/usb/devices/1-2/1-2:1.0/modalias",
        "usb:v046Dp0825d0000dc00dsc00dp00ic03isc01if02\n",
    );
    fixture
}

#[test]
fn pci_and_usb_fixtures_are_inventoried() {
    let fixture = build_full_fixture();
    let inventory = scan_fixture(&fixture);

    assert_eq!(inventory.devices.len(), 4);
    let vga = inventory
        .devices
        .iter()
        .find(|d| d.id == "pci:0000:00:02.0")
        .unwrap();
    assert_eq!(vga.vendor.id, "0x8086");
    assert_eq!(vga.device.id, "0x9bc4");
    assert_eq!(vga.class.code, "0x030000");
    assert_eq!(vga.class.name, "Graphics controller");
    assert_eq!(vga.subsystem.vendor, "0x8086");
    assert_eq!(vga.driver.bound.as_deref(), Some("i915"));
    assert_eq!(vga.driver.state, DriverState::Bound);
    assert!(vga.parent.is_none());

    let nic = inventory
        .devices
        .iter()
        .find(|d| d.id == "pci:0000:03:00.0")
        .unwrap();
    assert_eq!(nic.class.name, "Network controller");
    assert_eq!(nic.driver.state, DriverState::Unbound);

    let usb = inventory
        .devices
        .iter()
        .find(|d| d.id == "usb:1-4")
        .unwrap();
    assert_eq!(usb.class.name, "USB device");
    assert_eq!(usb.parent.as_deref(), Some("usb:1"));
    assert_eq!(usb.interfaces.len(), 2);
    assert_eq!(usb.interfaces[0].id, "usb:1-4:1.0");
    assert_eq!(usb.interfaces[0].device_id, "usb:1-4");
    assert_eq!(usb.interfaces[0].interface_number, 0);
    assert_eq!(usb.interfaces[0].driver.bound.as_deref(), Some("cdc_acm"));
    assert_eq!(usb.interfaces[1].id, "usb:1-4:1.1");
    assert_eq!(usb.interfaces[1].driver.state, DriverState::Unbound);

    let mouse = inventory
        .devices
        .iter()
        .find(|d| d.id == "usb:1-2")
        .unwrap();
    assert_eq!(mouse.interfaces.len(), 1);
    assert_eq!(mouse.parent.as_deref(), Some("usb:1"));

    assert_eq!(inventory.summary.devices, 4);
    assert_eq!(inventory.summary.with_driver, 2);
    assert_eq!(inventory.summary.without_driver, 2);
}

#[test]
fn invalid_and_missing_attributes_are_reported() {
    let fixture = Fixture::new("invalid");
    fixture.write("bus/pci/devices/0000:00:01.0/device", "0x1234\n");
    fixture.write("bus/pci/devices/0000:00:01.0/modalias", "not-a-modalias\n");
    fixture.write("bus/pci/devices/0000:00:01.0/class", "0xff0000\n");
    let inventory = scan_fixture(&fixture);

    let device = &inventory.devices[0];
    assert_eq!(device.vendor.id, "");
    assert_eq!(device.device.id, "0x1234");
    assert_eq!(device.modalias, "");
    assert_eq!(device.class.name, "Other device");
    assert!(
        inventory
            .scan
            .errors
            .iter()
            .any(|e| e.message.contains("cannot read"))
    );
    assert!(
        inventory
            .scan
            .errors
            .iter()
            .any(|e| e.message.contains("invalid or empty modalias"))
    );
}

#[test]
fn unreadable_and_disappearing_entries_do_not_abort_the_scan() {
    let fixture = Fixture::new("errors");
    // A directory where a file is expected produces a read error.
    fs::create_dir_all(fixture.path("bus/pci/devices/0000:00:04.0/vendor")).unwrap();
    fixture.write(
        "bus/pci/devices/0000:00:04.0/modalias",
        "pci:v00008086d00000001\n",
    );
    // A dangling symlink simulates a device disappearing during the scan.
    fixture.symlink(
        "bus/pci/devices/0000:00:05.0/modalias",
        "/nonexistent/modalias",
    );
    let inventory = scan_fixture(&fixture);

    assert_eq!(inventory.devices.len(), 2);
    assert!(!inventory.scan.errors.is_empty());
    assert!(inventory.devices.iter().all(|d| d.id.starts_with("pci:")));
}

#[test]
fn stable_ids_are_logical_and_path_free() {
    let fixture = build_full_fixture();
    let inventory = scan_fixture(&fixture);
    for device in &inventory.devices {
        assert!(device.id.starts_with("pci:") || device.id.starts_with("usb:"));
        assert!(!device.id.contains('/'));
        assert!(!device.path.is_empty());
        for interface in &device.interfaces {
            assert!(interface.id.starts_with("usb:"));
            assert!(!interface.id.contains('/'));
        }
    }
}

#[test]
fn scan_writes_nothing() {
    let fixture = build_full_fixture();
    let before = fixture.snapshot();
    let inventory = scan_fixture(&fixture);
    let after = fixture.snapshot();
    assert_eq!(before, after);
    assert!(inventory.scan.read_only);
}

#[test]
fn enumeration_errors_are_recorded_not_silently_ignored() {
    let fixture = Fixture::new("enum-errors");
    let inventory = scan_fixture(&fixture);
    assert!(inventory.devices.is_empty());
    assert!(
        inventory
            .scan
            .errors
            .iter()
            .any(|e| e.message.contains("cannot enumerate PCI devices"))
    );
    assert!(
        inventory
            .scan
            .errors
            .iter()
            .any(|e| e.message.contains("cannot enumerate USB devices"))
    );
    assert_eq!(inventory.summary.errors, inventory.scan.errors.len());
}

#[test]
fn inaccessible_usb_interface_is_reported_as_unknown() {
    let fixture = Fixture::new("usb-iface-error");
    fixture.write("bus/usb/devices/1-3/idVendor", "0x1234\n");
    fixture.write("bus/usb/devices/1-3/idProduct", "0x5678\n");
    fixture.write("bus/usb/devices/1-3/bDeviceClass", "0x00\n");
    fixture.write(
        "bus/usb/devices/1-3/modalias",
        "usb:v1234p5678d0000dc00dsc00dp00ic00isc00if00\n",
    );
    // A directory where bInterfaceClass is expected produces a read error.
    fs::create_dir_all(fixture.path("bus/usb/devices/1-3/1-3:1.0/bInterfaceClass")).unwrap();
    fixture.write(
        "bus/usb/devices/1-3/1-3:1.0/modalias",
        "usb:v1234p5678d0000dc00dsc00dp00ic00isc00if00\n",
    );

    let inventory = scan_fixture(&fixture);
    let device = &inventory.devices[0];
    assert_eq!(device.interfaces.len(), 1);
    assert_eq!(device.interfaces[0].class.code, "");
    assert_eq!(device.interfaces[0].class.name, "Unknown interface");
    assert!(
        inventory
            .scan
            .errors
            .iter()
            .any(|e| e.message.contains("cannot read"))
    );
    assert!(validate_json(&serde_json::to_value(inventory).unwrap()).is_ok());
}

#[test]
fn usb_absent_optional_attributes_are_not_errors() {
    let fixture = Fixture::new("usb-optional");
    fs::create_dir_all(fixture.path("bus/pci/devices")).unwrap();
    // No modalias and no bDeviceClass on the device; no bInterfaceClass and
    // no modalias on the interface. All are legitimate on real USB hardware.
    fixture.write("bus/usb/devices/3-1/idVendor", "0x046d\n");
    fixture.write("bus/usb/devices/3-1/idProduct", "0x0825\n");
    fixture.symlink(
        "bus/usb/devices/3-1/3-1:1.0/driver",
        "../../../../../drivers/usbhid",
    );
    // Create the interface directory itself by writing a harmless file.
    fixture.write("bus/usb/devices/3-1/3-1:1.0/.keep", "");

    let inventory = scan_fixture(&fixture);
    assert!(
        inventory.scan.errors.is_empty(),
        "{:?}",
        inventory.scan.errors
    );
    let device = &inventory.devices[0];
    assert_eq!(device.modalias, "");
    assert_eq!(device.class.code, "");
    assert_eq!(device.class.name, "USB device");
    assert_eq!(device.interfaces.len(), 1);
    let interface = &device.interfaces[0];
    assert_eq!(interface.modalias, "");
    assert_eq!(interface.class.code, "");
    assert_eq!(interface.class.name, "Unknown interface");
    assert_eq!(device.diagnosis.len(), 1);
    assert_eq!(device.diagnosis[0].code, "PACKAGE_UNKNOWN");
    assert!(
        inventory.scan.sources.iter().any(|source| source.ends_with("/bDeviceClass")),
        "missing optional attributes must still be auditable"
    );
    assert!(
        inventory.scan.sources.iter().any(|source| source.ends_with("/driver")),
        "absent driver links must still be auditable"
    );
    assert!(validate_json(&serde_json::to_value(inventory).unwrap()).is_ok());
}

#[test]
fn usb_present_but_invalid_attributes_are_errors() {
    let fixture = Fixture::new("usb-invalid");
    fixture.write("bus/usb/devices/4-1/idVendor", "0x046d\n");
    fixture.write("bus/usb/devices/4-1/idProduct", "0x0825\n");
    fixture.write("bus/usb/devices/4-1/bDeviceClass", "not-hex\n");
    fixture.write("bus/usb/devices/4-1/modalias", "garbage\n");
    fixture.write("bus/usb/devices/4-1/4-1:1.0/bInterfaceClass", "0xZZ\n");
    fixture.write("bus/usb/devices/4-1/4-1:1.0/modalias", "bad\n");

    let inventory = scan_fixture(&fixture);
    let messages: Vec<&str> = inventory
        .scan
        .errors
        .iter()
        .map(|error| error.message.as_str())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("invalid USB class value"))
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("invalid or empty modalias"))
    );
    assert_eq!(inventory.devices[0].class.code, "");
    assert_eq!(inventory.devices[0].interfaces[0].class.code, "");
}

#[test]
fn malformed_hardware_ids_are_reported_instead_of_silently_discarded() {
    let fixture = Fixture::new("malformed-ids");
    fixture.write("bus/pci/devices/0000:00:01.0/vendor", "0xGGGG\n");
    fixture.write("bus/pci/devices/0000:00:01.0/device", "0x12345\n");
    fixture.write("bus/pci/devices/0000:00:01.0/class", "0xZZ0000\n");
    fixture.write("bus/pci/devices/0000:00:01.0/subsystem_vendor", "bad\n");
    fixture.write("bus/pci/devices/0000:00:01.0/subsystem_device", "0x12345\n");
    fixture.write("bus/usb/devices/2-1/idVendor", "0xGGGG\n");
    fixture.write("bus/usb/devices/2-1/idProduct", "0x12345\n");

    let inventory = scan_fixture(&fixture);
    let pci = inventory
        .devices
        .iter()
        .find(|device| device.bus == lmfk_core::Bus::Pci)
        .unwrap();
    let usb = inventory
        .devices
        .iter()
        .find(|device| device.bus == lmfk_core::Bus::Usb)
        .unwrap();

    assert_eq!(pci.vendor.id, "");
    assert_eq!(pci.device.id, "");
    assert_eq!(pci.class.code, "");
    assert_eq!(usb.vendor.id, "");
    assert_eq!(usb.device.id, "");
    for field in [
        "vendor",
        "device",
        "class",
        "subsystem_vendor",
        "subsystem_device",
        "idVendor",
        "idProduct",
    ] {
        assert!(
            inventory
                .scan
                .errors
                .iter()
                .any(|error| error.message.contains(field)),
            "missing invalid-value diagnostic for {field}: {:?}",
            inventory.scan.errors
        );
    }
}

#[test]
fn device_tree_compatible_nodes_are_discovered_read_only() {
    let fixture = Fixture::new("device-tree");
    fixture.write(
        "firmware/devicetree/base/compatible",
        "acme,board\0acme,board-rev2\0",
    );
    fixture.write(
        "firmware/devicetree/base/soc/compatible",
        "simple-bus\0",
    );
    fixture.write(
        "firmware/devicetree/base/soc/serial@1000/compatible",
        "acme,uart-v2\0",
    );

    let before = fixture.snapshot();
    let inventory = scan_fixture(&fixture);
    let after = fixture.snapshot();

    assert_eq!(before, after, "Device Tree scan must not modify its fixture");
    assert_eq!(inventory.devices.len(), 3);
    let board = inventory
        .devices
        .iter()
        .find(|device| device.id == "dt:root")
        .unwrap();
    assert_eq!(board.bus, lmfk_core::Bus::Dt);
    assert_eq!(board.vendor.name, "acme");
    assert_eq!(board.device.name, "acme,board");
    assert!(board.parent.is_none());
    let uart = inventory
        .devices
        .iter()
        .find(|device| device.id == "dt:soc:serial@1000")
        .unwrap();
    assert_eq!(uart.parent.as_deref(), Some("dt:soc"));
    assert!(
        inventory
            .scan
            .sources
            .iter()
            .any(|source| source.ends_with("/compatible"))
    );
    assert!(validate_json(&serde_json::to_value(inventory).unwrap()).is_ok());
}

#[test]
fn json_matches_schema_v1() {
    let fixture = build_full_fixture();
    let inventory = scan_fixture(&fixture);
    let json = inventory.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    let validator = schema_validator();
    let schema_errors: Vec<_> = validator.iter_errors(&value).collect();
    assert!(
        schema_errors.is_empty(),
        "JSON Schema v1.0 violations: {schema_errors:?}"
    );
    let violations = validate_json(&value);
    assert!(
        violations.is_ok(),
        "contract violations: {:?}",
        violations.err()
    );
    assert_eq!(value["schema_version"], SCHEMA_VERSION);
    assert_eq!(value["scan"]["read_only"], true);
    assert_eq!(value["summary"]["devices"], 4);
    let devices = value["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 4);
    for device in devices {
        for field in [
            "id",
            "bus",
            "class",
            "vendor",
            "device",
            "subsystem",
            "modalias",
            "path",
            "parent",
            "interfaces",
            "driver",
            "modules",
            "firmwares",
            "package_suggestions",
            "diagnosis",
        ] {
            assert!(device.get(field).is_some(), "missing field {field}");
        }
        assert!(device["modules"].as_array().unwrap().is_empty());
        assert!(device["package_suggestions"].as_array().unwrap().is_empty());
        let diagnoses = device["diagnosis"].as_array().unwrap();
        assert_eq!(diagnoses.len(), 1);
        assert_eq!(diagnoses[0]["code"], "PACKAGE_UNKNOWN");
        assert!(
            diagnoses[0]["title"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        assert!(
            diagnoses[0]["advised_action"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
    }
}
