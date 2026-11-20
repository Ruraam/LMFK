//! Read-only PCI/USB hardware discovery.
//!
//! All filesystem access is `read`, `read_dir` or `read_link`. The scanner
//! never writes, creates caches, compiles modules or invokes commands.
//! A caller-supplied root makes the scanner testable with synthetic trees.

use std::{fs, io::ErrorKind, path::Path};

use lmfk_core::{
    Bus, Category, ClassInfo, Device, Diagnosis, Driver, DriverState, Host, IdName, Inventory,
    ScanError, ScanMeta, Subsystem, UsbInterface,
};

#[derive(Debug, Clone)]
pub struct ScanOptions<'a> {
    pub root: &'a Path,
    pub host: Host,
    pub generated_at: String,
}

impl<'a> ScanOptions<'a> {
    pub fn new(root: &'a Path, host: Host, generated_at: impl Into<String>) -> Self {
        Self {
            root,
            host,
            generated_at: generated_at.into(),
        }
    }
}

fn record_source(sources: &mut Vec<String>, source: String) {
    if !sources.contains(&source) {
        sources.push(source);
    }
}

fn record_error(
    errors: &mut Vec<ScanError>,
    source: impl Into<String>,
    message: impl Into<String>,
) {
    errors.push(ScanError {
        source: source.into(),
        message: message.into(),
    });
}

fn read_required(
    dir: &Path,
    name: &str,
    sources: &mut Vec<String>,
    errors: &mut Vec<ScanError>,
) -> Option<String> {
    let path = dir.join(name);
    match fs::read_to_string(&path) {
        Ok(value) => {
            record_source(sources, path.display().to_string());
            Some(value.trim().to_owned())
        }
        Err(error) => {
            record_error(
                errors,
                path.display().to_string(),
                format!("cannot read: {error}"),
            );
            None
        }
    }
}

fn read_optional(
    dir: &Path,
    name: &str,
    sources: &mut Vec<String>,
    errors: &mut Vec<ScanError>,
) -> Option<String> {
    let path = dir.join(name);
    match fs::read_to_string(&path) {
        Ok(value) => {
            record_source(sources, path.display().to_string());
            Some(value.trim().to_owned())
        }
        // A missing optional attribute is normal; any other access problem is
        // recorded instead of being silently treated as an absence.
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => {
            record_error(
                errors,
                path.display().to_string(),
                format!("cannot read optional attribute: {error}"),
            );
            None
        }
    }
}

fn read_driver(dir: &Path, sources: &mut Vec<String>, errors: &mut Vec<ScanError>) -> Driver {
    let path = dir.join("driver");
    match fs::read_link(&path) {
        Ok(target) => {
            record_source(sources, path.display().to_string());
            match target.file_name().and_then(|name| name.to_str()) {
                Some(name) => Driver {
                    bound: Some(name.to_owned()),
                    state: DriverState::Bound,
                },
                None => Driver::unknown(),
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Driver::unbound(),
        Err(error) => {
            record_error(
                errors,
                path.display().to_string(),
                format!("cannot read driver link: {error}"),
            );
            Driver::unknown()
        }
    }
}

fn parse_hex_id(
    raw: Option<String>,
    width: usize,
    source: &Path,
    field: &str,
    errors: &mut Vec<ScanError>,
) -> Option<String> {
    let raw = raw?;
    let digits = raw.trim().strip_prefix("0x").or_else(|| raw.trim().strip_prefix("0X"))
        .unwrap_or(raw.trim());
    if digits.len() != width || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        record_error(
            errors,
            source.join(field).display().to_string(),
            format!("invalid hexadecimal {field} value: {raw}"),
        );
        return None;
    }
    Some(format!("0x{}", digits.to_ascii_lowercase()))
}

fn clean_modalias(raw: Option<String>, source: &Path, errors: &mut Vec<ScanError>) -> String {
    let Some(value) = raw else {
        return String::new();
    };
    let valid =
        !value.is_empty() && value.contains(':') && value.bytes().all(|b| b.is_ascii_graphic());
    if valid {
        value
    } else {
        record_error(
            errors,
            source.display().to_string(),
            "invalid or empty modalias; value discarded",
        );
        String::new()
    }
}

fn classify_pci(code: &str) -> Category {
    let digits = code.trim_start_matches("0x");
    let Ok(value) = u64::from_str_radix(digits, 16) else {
        return Category::Unknown;
    };
    let base = value >> 16;
    let sub = (value >> 8) & 0xff;
    match (base, sub) {
        (0x01, _) => Category::Storage,
        (0x02, _) => Category::Network,
        (0x03, _) => Category::Graphics,
        (0x04, _) => Category::Audio,
        (0x0c, 0x03) => Category::Usb,
        _ => Category::Other,
    }
}

fn parse_usb_class(
    raw: Option<String>,
    source: &Path,
    errors: &mut Vec<ScanError>,
) -> Option<String> {
    let raw = raw?;
    match parse_hex_id(Some(raw.clone()), 2, source, "USB class", errors) {
        Some(value) => Some(value),
        None => {
            record_error(
                errors,
                source.display().to_string(),
                format!("invalid USB class value: {raw}"),
            );
            None
        }
    }
}

fn classify_usb_interface(code: Option<String>) -> Category {
    let Some(code) = code else {
        return Category::Unknown;
    };
    let digits = code.trim_start_matches("0x");
    let Ok(value) = u64::from_str_radix(digits, 16) else {
        return Category::Unknown;
    };
    match value & 0xff {
        0x01 => Category::Audio,
        0x02 | 0xe0 => Category::Network,
        0x08 => Category::Storage,
        0x0e => Category::Graphics,
        _ => Category::Other,
    }
}

fn pci_parent(root: &Path, dir: &Path) -> Option<String> {
    let canonical = fs::canonicalize(dir).ok()?;
    let parent = canonical.parent()?;
    let bus_root = fs::canonicalize(root.join("bus/pci/devices")).ok()?;
    if parent == bus_root {
        return None;
    }
    Some(format!("pci:{}", parent.file_name()?.to_str()?))
}

fn usb_parent(id: &str) -> Option<String> {
    if id.starts_with("usb") {
        return None;
    }
    let (bus, port) = id.split_once('-')?;
    match port.rsplit_once('.') {
        Some((parent, _)) => Some(format!("usb:{bus}-{parent}")),
        None => Some(format!("usb:{bus}")),
    }
}

fn empty_device(id: String, bus: Bus, path: &Path) -> Device {
    Device {
        id,
        bus,
        class: ClassInfo {
            code: String::new(),
            name: Category::Unknown.label().to_owned(),
        },
        vendor: IdName {
            id: String::new(),
            name: String::new(),
        },
        device: IdName {
            id: String::new(),
            name: String::new(),
        },
        subsystem: Subsystem {
            vendor: String::new(),
            device: String::new(),
        },
        modalias: String::new(),
        path: path.display().to_string(),
        parent: None,
        interfaces: Vec::new(),
        driver: Driver::unknown(),
        modules: Vec::new(),
        firmwares: Vec::new(),
        package_suggestions: Vec::new(),
        diagnosis: Vec::new(),
    }
}

fn scan_pci(root: &Path, sources: &mut Vec<String>, errors: &mut Vec<ScanError>) -> Vec<Device> {
    let bus_root = root.join("bus/pci/devices");
    let entries = match fs::read_dir(&bus_root) {
        Ok(entries) => {
            record_source(sources, bus_root.display().to_string());
            entries
        }
        Err(error) => {
            record_error(
                errors,
                bus_root.display().to_string(),
                format!("cannot enumerate PCI devices: {error}"),
            );
            return Vec::new();
        }
    };

    let mut devices = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                record_error(
                    errors,
                    bus_root.display().to_string(),
                    format!("cannot read PCI directory entry: {error}"),
                );
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let dir = entry.path();
        let mut device = empty_device(format!("pci:{name}"), Bus::Pci, &dir);

        let vendor = read_required(&dir, "vendor", sources, errors);
        let device_id = read_required(&dir, "device", sources, errors);
        let class = read_required(&dir, "class", sources, errors);
        let modalias = read_required(&dir, "modalias", sources, errors);
        device.vendor.id = parse_hex_id(vendor, 4, &dir, "vendor", errors).unwrap_or_default();
        device.device.id = parse_hex_id(device_id, 4, &dir, "device", errors).unwrap_or_default();
        device.class.code = parse_hex_id(class, 6, &dir, "class", errors).unwrap_or_default();
        device.modalias = clean_modalias(modalias, &dir, errors);
        device.class.name = classify_pci(&device.class.code).label().to_owned();
        device.subsystem.vendor =
            parse_hex_id(
                read_optional(&dir, "subsystem_vendor", sources, errors),
                4, &dir, "subsystem_vendor", errors,
            ).unwrap_or_default();
        device.subsystem.device =
            parse_hex_id(
                read_optional(&dir, "subsystem_device", sources, errors),
                4, &dir, "subsystem_device", errors,
            ).unwrap_or_default();
        device.driver = read_driver(&dir, sources, errors);
        device.parent = pci_parent(root, &dir);
        devices.push(device);
    }
    devices
}

fn scan_usb_interface(
    dir: &Path,
    device_id: &str,
    name: &str,
    sources: &mut Vec<String>,
    errors: &mut Vec<ScanError>,
) -> UsbInterface {
    let interface_number = name
        .rsplit('.')
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    // bInterfaceClass and modalias are legitimately absent on some USB
    // interfaces. A present but malformed value is an error; a missing file
    // is simply unknown.
    let raw_class = read_optional(dir, "bInterfaceClass", sources, errors);
    let class_id = parse_usb_class(raw_class, dir, errors);
    let category = classify_usb_interface(class_id.clone());
    let modalias = clean_modalias(read_optional(dir, "modalias", sources, errors), dir, errors);
    UsbInterface {
        id: format!("usb:{name}"),
        device_id: device_id.to_owned(),
        interface_number,
        class: ClassInfo {
            code: class_id.unwrap_or_default(),
            name: category.interface_label().to_owned(),
        },
        modalias,
        driver: read_driver(dir, sources, errors),
    }
}

fn scan_usb(root: &Path, sources: &mut Vec<String>, errors: &mut Vec<ScanError>) -> Vec<Device> {
    let bus_root = root.join("bus/usb/devices");
    let entries = match fs::read_dir(&bus_root) {
        Ok(entries) => {
            record_source(sources, bus_root.display().to_string());
            entries
        }
        Err(error) => {
            record_error(
                errors,
                bus_root.display().to_string(),
                format!("cannot enumerate USB devices: {error}"),
            );
            return Vec::new();
        }
    };

    let mut devices = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                record_error(
                    errors,
                    bus_root.display().to_string(),
                    format!("cannot read USB directory entry: {error}"),
                );
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        // Entries containing ':' are USB interfaces, enumerated from their
        // parent device below. Root hubs such as "usb1" are devices.
        if name.contains(':') {
            continue;
        }
        let dir = entry.path();
        let id = format!("usb:{name}");
        let mut device = empty_device(id.clone(), Bus::Usb, &dir);

        // bDeviceClass is 0x00 (unspecified) or absent on many devices; that
        // is normal. Only an unreadable or malformed value is an error.
        let raw_class = read_optional(&dir, "bDeviceClass", sources, errors);
        device.class.code = parse_usb_class(raw_class, &dir, errors).unwrap_or_default();
        // The USB device itself is always classified as USB; a more specific
        // category is assigned to each interface using its interface class.
        device.class.name = Category::Usb.label().to_owned();
        device.vendor.id =
            parse_hex_id(read_required(&dir, "idVendor", sources, errors), 4, &dir, "idVendor", errors).unwrap_or_default();
        device.device.id =
            parse_hex_id(read_required(&dir, "idProduct", sources, errors), 4, &dir, "idProduct", errors).unwrap_or_default();
        device.modalias = clean_modalias(
            read_optional(&dir, "modalias", sources, errors),
            &dir,
            errors,
        );
        device.driver = read_driver(&dir, sources, errors);
        device.parent = usb_parent(&name);

        let prefix = format!("{name}:");
        match fs::read_dir(&dir) {
            Ok(children) => {
                let mut names = Vec::new();
                for child in children {
                    match child {
                        Ok(child) => {
                            let child_name = child.file_name().to_string_lossy().into_owned();
                            if child_name.starts_with(&prefix) {
                                names.push(child_name);
                            }
                        }
                        Err(error) => record_error(
                            errors,
                            dir.display().to_string(),
                            format!("cannot read USB interface entry: {error}"),
                        ),
                    }
                }
                names.sort();
                for child in names {
                    let child_dir = dir.join(&child);
                    if !child_dir.is_dir() {
                        record_error(
                            errors,
                            child_dir.display().to_string(),
                            "USB interface disappeared or is not a directory",
                        );
                        continue;
                    }
                    device
                        .interfaces
                        .push(scan_usb_interface(&child_dir, &id, &child, sources, errors));
                }
            }
            Err(error) => record_error(
                errors,
                dir.display().to_string(),
                format!("cannot enumerate USB interfaces: {error}"),
            ),
        }
        devices.push(device);
    }
    devices
}

/// Scan a sysfs-like tree. The root is a parameter so tests can use fixtures.
pub fn scan(options: &ScanOptions<'_>) -> Inventory {
    let mut sources = Vec::new();
    let mut errors = Vec::new();
    let mut devices = scan_pci(options.root, &mut sources, &mut errors);
    devices.extend(scan_usb(options.root, &mut sources, &mut errors));
    devices.sort_by(|a, b| a.id.cmp(&b.id));

    // Schema v1.0 requires an explicit PACKAGE_UNKNOWN diagnosis whenever
    // no package suggestion exists. Phase 1 has no package backends, so this
    // records an absence of information; it never invents a module or package.
    for device in &mut devices {
        if device.package_suggestions.is_empty() {
            device.diagnosis.push(Diagnosis::package_unknown());
        }
    }

    let meta = ScanMeta {
        sources,
        read_only: true,
        errors,
    };
    Inventory::new(&options.generated_at, options.host.clone(), meta, devices)
}
