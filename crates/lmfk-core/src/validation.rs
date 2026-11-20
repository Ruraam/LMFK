//! Validation of serialized inventories against the JSON contract v1.0.
//!
//! This is a real contract check (required fields, types, closed enums and
//! cross-field relationships), not a presence-only assertion. It does not
//! modify or extend the documented schema.

use serde_json::{Map, Value};

const REQUIRED_DEVICE_FIELDS: &[&str] = &[
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
];

pub fn validate_json(value: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let root = match value.as_object() {
        Some(object) => object,
        None => {
            errors.push("root must be a JSON object".to_owned());
            return Err(errors);
        }
    };

    let schema_version = require(root, "schema_version", &mut errors)
        .and_then(|v| expect_str(v, "schema_version", &mut errors));
    if schema_version != Some(crate::SCHEMA_VERSION) {
        errors.push(format!("schema_version must be {}", crate::SCHEMA_VERSION));
    }
    if let Some(timestamp) = require(root, "generated_at", &mut errors)
        .and_then(|value| expect_str(value, "generated_at", &mut errors))
    {
        if !is_rfc3339_timestamp(timestamp) {
            errors.push("generated_at must be a valid RFC 3339 date-time".to_owned());
        }
    }

    let host =
        require(root, "host", &mut errors).and_then(|v| expect_object(v, "host", &mut errors));
    if let Some(host) = host {
        for field in [
            "kernel_release",
            "kernel_version",
            "arch",
            "distro_id",
            "distro_version",
            "secure_boot",
        ] {
            if let Some(value) = require(host, field, &mut errors) {
                expect_str(value, &format!("host.{field}"), &mut errors);
            }
        }
        if let Some(state) = host.get("secure_boot") {
            expect_enum(
                state,
                &["enabled", "disabled", "unknown"],
                "host.secure_boot",
                &mut errors,
            );
        }
    }

    let scan =
        require(root, "scan", &mut errors).and_then(|v| expect_object(v, "scan", &mut errors));
    if let Some(scan) = scan {
        if let Some(sources) = require(scan, "sources", &mut errors)
            .and_then(|v| expect_array(v, "scan.sources", &mut errors))
        {
            for (index, source) in sources.iter().enumerate() {
                expect_str(source, &format!("scan.sources[{index}]"), &mut errors);
            }
        }
        if let Some(read_only) = require(scan, "read_only", &mut errors) {
            if expect_bool(read_only, "scan.read_only", &mut errors) == Some(false) {
                errors.push("scan.read_only must be true".to_owned());
            }
        }
        if let Some(scan_errors) = require(scan, "errors", &mut errors)
            .and_then(|v| expect_array(v, "scan.errors", &mut errors))
        {
            for (index, error) in scan_errors.iter().enumerate() {
                if let Some(error) = error.as_object() {
                    for field in ["source", "message"] {
                        if let Some(value) = require(error, field, &mut errors) {
                            expect_str(
                                value,
                                &format!("scan.errors[{index}].{field}"),
                                &mut errors,
                            );
                        }
                    }
                } else {
                    errors.push(format!("scan.errors[{index}] must be an object"));
                }
            }
        }
    }

    let devices =
        require(root, "devices", &mut errors).and_then(|v| expect_array(v, "devices", &mut errors));
    let devices = devices.map_or(&[][..], |values| values.as_slice());
    for (index, device) in devices.iter().enumerate() {
        let path = format!("devices[{index}]");
        let object = match device.as_object() {
            Some(object) => object,
            None => {
                errors.push(format!("{path} must be an object"));
                continue;
            }
        };
        for field in REQUIRED_DEVICE_FIELDS {
            require(object, field, &mut errors);
        }

        let id = require(object, "id", &mut errors)
            .and_then(|v| expect_str(v, &format!("{path}.id"), &mut errors));
        let bus = require(object, "bus", &mut errors)
            .and_then(|v| expect_str(v, &format!("{path}.bus"), &mut errors));
        if let (Some(id), Some(bus)) = (id, bus) {
            let prefix = match bus {
                "pci" => "pci:",
                "usb" => "usb:",
                "dt" => "dt:",
                _ => {
                    errors.push(format!("{path}.bus has unknown value {bus:?}"));
                    ""
                }
            };
            if !prefix.is_empty() && !id.starts_with(prefix) {
                errors.push(format!("{path}.id must start with {prefix:?}"));
            }
            if id.contains('/') {
                errors.push(format!("{path}.id must not contain an absolute path"));
            }
        }

        if let Some(class) = object.get("class") {
            validate_class(class, &format!("{path}.class"), &mut errors);
        }
        if let Some(vendor) = object.get("vendor") {
            validate_id_name(vendor, &format!("{path}.vendor"), &mut errors);
        }
        if let Some(device_id) = object.get("device") {
            validate_id_name(device_id, &format!("{path}.device"), &mut errors);
        }
        if let Some(subsystem) = object.get("subsystem") {
            if let Some(subsystem) = subsystem.as_object() {
                for field in ["vendor", "device"] {
                    if let Some(value) = require(subsystem, field, &mut errors) {
                        expect_str(value, &format!("{path}.subsystem.{field}"), &mut errors);
                    }
                }
            } else {
                errors.push(format!("{path}.subsystem must be an object"));
            }
        }
        for field in ["modalias", "path"] {
            if let Some(value) = object.get(field) {
                expect_str(value, &format!("{path}.{field}"), &mut errors);
            }
        }
        if let Some(parent) = object.get("parent") {
            if !parent.is_null() {
                expect_str(parent, &format!("{path}.parent"), &mut errors);
            }
        }
        if let Some(driver) = object.get("driver") {
            validate_driver(driver, &format!("{path}.driver"), &mut errors);
        }
        if let Some(interfaces) = object.get("interfaces") {
            for (interface_index, interface) in
                expect_array(interfaces, &format!("{path}.interfaces"), &mut errors)
                    .map_or(&[][..], |values| values.as_slice())
                    .iter()
                    .enumerate()
            {
                let ipath = format!("{path}.interfaces[{interface_index}]");
                let Some(interface) = interface.as_object() else {
                    errors.push(format!("{ipath} must be an object"));
                    continue;
                };
                for field in [
                    "id",
                    "device_id",
                    "interface_number",
                    "class",
                    "modalias",
                    "driver",
                ] {
                    require(interface, field, &mut errors);
                }
                if let Some(value) = require(interface, "id", &mut errors) {
                    let id = expect_str(value, &format!("{ipath}.id"), &mut errors);
                    if id.is_some_and(|id| id.contains('/')) {
                        errors.push(format!("{ipath}.id must not contain an absolute path"));
                    }
                }
                if let Some(value) = require(interface, "device_id", &mut errors) {
                    let interface_device =
                        expect_str(value, &format!("{ipath}.device_id"), &mut errors);
                    if let (Some(id), Some(interface_device)) = (id, interface_device) {
                        if interface_device != id {
                            errors.push(format!("{ipath}.device_id must equal {path}.id"));
                        }
                    }
                }
                if let Some(value) = require(interface, "interface_number", &mut errors) {
                    if value.as_u64().is_none() {
                        errors.push(format!(
                            "{ipath}.interface_number must be an unsigned integer"
                        ));
                    }
                }
                if let Some(class) = interface.get("class") {
                    validate_class(class, &format!("{ipath}.class"), &mut errors);
                }
                if let Some(driver) = interface.get("driver") {
                    validate_driver(driver, &format!("{ipath}.driver"), &mut errors);
                }
            }
        }
        if let Some(modules) = object.get("modules") {
            for (module_index, module) in
                expect_array(modules, &format!("{path}.modules"), &mut errors)
                    .map_or(&[][..], |values| values.as_slice())
                    .iter()
                    .enumerate()
            {
                let mpath = format!("{path}.modules[{module_index}]");
                let Some(module) = module.as_object() else {
                    errors.push(format!("{mpath} must be an object"));
                    continue;
                };
                if let Some(value) = require(module, "match_source", &mut errors) {
                    expect_enum(
                        value,
                        &[
                            "modules.alias",
                            "modules.builtin",
                            "driver_link",
                            "modalias",
                        ],
                        &format!("{mpath}.match_source"),
                        &mut errors,
                    );
                }
                if let Some(value) = require(module, "state", &mut errors) {
                    expect_enum(
                        value,
                        &["loaded", "available", "builtin", "missing", "unknown"],
                        &format!("{mpath}.state"),
                        &mut errors,
                    );
                }
                require(module, "name", &mut errors);
                require(module, "dependencies", &mut errors);
                require(module, "firmwares", &mut errors);
            }
        }
        if let Some(firmwares) = object.get("firmwares") {
            validate_firmwares(firmwares, &format!("{path}.firmwares"), &mut errors);
        }
        let suggestions = object
            .get("package_suggestions")
            .and_then(|v| expect_array(v, &format!("{path}.package_suggestions"), &mut errors));
        if let Some(suggestions) = suggestions {
            for (suggestion_index, suggestion) in suggestions.iter().enumerate() {
                let spath = format!("{path}.package_suggestions[{suggestion_index}]");
                let Some(suggestion) = suggestion.as_object() else {
                    errors.push(format!("{spath} must be an object"));
                    continue;
                };
                for field in ["backend", "package", "reason", "confidence"] {
                    require(suggestion, field, &mut errors)
                        .and_then(|v| expect_str(v, &format!("{spath}.{field}"), &mut errors));
                }
                if let Some(confidence) = suggestion.get("confidence") {
                    expect_enum(
                        confidence,
                        &["high", "medium", "low"],
                        &format!("{spath}.confidence"),
                        &mut errors,
                    );
                }
            }
            if suggestions.is_empty() {
                let has_unknown = object
                    .get("diagnosis")
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        items.iter().filter_map(Value::as_object).any(|diagnosis| {
                            diagnosis.get("code").and_then(Value::as_str) == Some("PACKAGE_UNKNOWN")
                        })
                    });
                if !has_unknown {
                    errors.push(format!(
                        "{path}: empty package_suggestions requires a PACKAGE_UNKNOWN diagnosis"
                    ));
                }
            }
        }
        if let Some(diagnosis) = object.get("diagnosis") {
            for (diagnosis_index, item) in
                expect_array(diagnosis, &format!("{path}.diagnosis"), &mut errors)
                    .map_or(&[][..], |values| values.as_slice())
                    .iter()
                    .enumerate()
            {
                let dpath = format!("{path}.diagnosis[{diagnosis_index}]");
                let Some(item) = item.as_object() else {
                    errors.push(format!("{dpath} must be an object"));
                    continue;
                };
                for field in ["code", "title", "explanation", "advised_action", "message"] {
                    require(item, field, &mut errors)
                        .and_then(|v| expect_str(v, &format!("{dpath}.{field}"), &mut errors));
                }
                if let Some(severity) = require(item, "severity", &mut errors) {
                    expect_enum(
                        severity,
                        &["error", "warning", "info"],
                        &format!("{dpath}.severity"),
                        &mut errors,
                    );
                }
                if let Some(evidence) = require(item, "evidence", &mut errors) {
                    for (index, value) in
                        expect_array(evidence, &format!("{dpath}.evidence"), &mut errors)
                            .map_or(&[][..], |values| values.as_slice())
                            .iter()
                            .enumerate()
                    {
                        expect_str(value, &format!("{dpath}.evidence[{index}]"), &mut errors);
                    }
                }
            }
        }
    }

    if let Some(summary) =
        require(root, "summary", &mut errors).and_then(|v| expect_object(v, "summary", &mut errors))
    {
        let count = |field: &str| {
            summary
                .get(field)
                .and_then(Value::as_u64)
                .unwrap_or(usize::MAX as u64) as usize
        };
        if count("devices") != devices.len() {
            errors.push("summary.devices must equal the number of devices".to_owned());
        }
        let with_driver = devices
            .iter()
            .filter_map(Value::as_object)
            .filter(|device| device_has_driver(device))
            .count();
        if count("with_driver") != with_driver {
            errors.push("summary.with_driver does not match the devices".to_owned());
        }
        if count("without_driver") != devices.len() - with_driver {
            errors.push("summary.without_driver does not match the devices".to_owned());
        }
        let missing_firmware = devices
            .iter()
            .filter_map(Value::as_object)
            .filter(|device| {
                device
                    .get("firmwares")
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        items.iter().filter_map(Value::as_object).any(|firmware| {
                            firmware.get("present").and_then(Value::as_bool) == Some(false)
                        })
                    })
            })
            .count();
        if count("missing_firmware") != missing_firmware {
            errors.push("summary.missing_firmware does not match the devices".to_owned());
        }
        let scan_errors = root
            .get("scan")
            .and_then(Value::as_object)
            .and_then(|scan| scan.get("errors"))
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if count("errors") != scan_errors {
            errors.push("summary.errors must equal scan.errors length".to_owned());
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn device_has_driver(device: &Map<String, Value>) -> bool {
    let bound = |driver: &Value| {
        driver
            .as_object()
            .and_then(|driver| driver.get("state"))
            .and_then(Value::as_str)
            == Some("bound")
    };
    device.get("driver").is_some_and(bound)
        || device
            .get("interfaces")
            .and_then(Value::as_array)
            .is_some_and(|interfaces| {
                interfaces.iter().any(|interface| {
                    interface
                        .as_object()
                        .and_then(|object| object.get("driver"))
                        .and_then(Value::as_object)
                        .and_then(|driver| driver.get("state"))
                        .and_then(Value::as_str)
                        == Some("bound")
                })
            })
}

fn validate_class(value: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(object) = expect_object(value, path, errors) else {
        return;
    };
    for field in ["code", "name"] {
        require_at(object, field, path, errors)
            .and_then(|v| expect_str(v, &format!("{path}.{field}"), errors));
    }
}

fn validate_id_name(value: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(object) = expect_object(value, path, errors) else {
        return;
    };
    for field in ["id", "name"] {
        require_at(object, field, path, errors)
            .and_then(|v| expect_str(v, &format!("{path}.{field}"), errors));
    }
}

fn validate_driver(value: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(object) = expect_object(value, path, errors) else {
        return;
    };
    if let Some(bound) = require(object, "bound", errors) {
        if !bound.is_null() {
            expect_str(bound, &format!("{path}.bound"), errors);
        }
    }
    if let Some(state) = require(object, "state", errors) {
        expect_enum(
            state,
            &["bound", "unbound", "unknown"],
            &format!("{path}.state"),
            errors,
        );
    }
}

fn validate_firmwares(value: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(items) = expect_array(value, path, errors) else {
        return;
    };
    for (index, item) in items.iter().enumerate() {
        let fpath = format!("{path}[{index}]");
        let Some(firmware) = expect_object(item, &fpath, errors) else {
            continue;
        };
        require(firmware, "alias", errors)
            .and_then(|v| expect_str(v, &format!("{fpath}.alias"), errors));
        let present = require(firmware, "present", errors)
            .and_then(|v| expect_bool(v, &format!("{fpath}.present"), errors));
        let paths = require(firmware, "paths", errors)
            .and_then(|v| expect_array(v, &format!("{fpath}.paths"), errors));
        if present == Some(false) && paths.is_some_and(|paths| !paths.is_empty()) {
            errors.push(format!("{fpath}: absent firmware must have empty paths"));
        }
    }
}

fn is_rfc3339_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }

    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .is_some_and(|part| part.iter().all(u8::is_ascii_digit))
    };
    if !digits(0..4) || !digits(5..7) || !digits(8..10)
        || !digits(11..13) || !digits(14..16) || !digits(17..19)
    {
        return false;
    }

    let number = |range: std::ops::Range<usize>| {
        std::str::from_utf8(&bytes[range]).ok()?.parse::<u32>().ok()
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0..4),
        number(5..7),
        number(8..10),
        number(11..13),
        number(14..16),
        number(17..19),
    ) else {
        return false;
    };
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return false;
    }

    let mut position = 19;
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        let fraction_start = position;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
        if position == fraction_start {
            return false;
        }
    }

    let Some(suffix) = bytes.get(position..) else {
        return false;
    };
    if suffix == b"Z" {
        return true;
    }
    if suffix.len() != 6
        || !matches!(suffix[0], b'+' | b'-')
        || suffix[3] != b':'
        || !suffix[1..3].iter().all(u8::is_ascii_digit)
        || !suffix[4..6].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let offset_hour = u32::from(suffix[1] - b'0') * 10 + u32::from(suffix[2] - b'0');
    let offset_minute = u32::from(suffix[4] - b'0') * 10 + u32::from(suffix[5] - b'0');
    offset_hour <= 23 && offset_minute <= 59
}

fn require<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<&'a Value> {
    object.get(field).or_else(|| {
        errors.push(format!("missing required field {field}"));
        None
    })
}

fn require_at<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    errors: &mut Vec<String>,
) -> Option<&'a Value> {
    object.get(field).or_else(|| {
        errors.push(format!("missing required field {path}.{field}"));
        None
    })
}

fn expect_str<'a>(value: &'a Value, path: &str, errors: &mut Vec<String>) -> Option<&'a str> {
    match value.as_str() {
        Some(value) => Some(value),
        None => {
            errors.push(format!("{path} must be a string"));
            None
        }
    }
}

fn expect_bool(value: &Value, path: &str, errors: &mut Vec<String>) -> Option<bool> {
    match value.as_bool() {
        Some(value) => Some(value),
        None => {
            errors.push(format!("{path} must be a boolean"));
            None
        }
    }
}

fn expect_array<'a>(
    value: &'a Value,
    path: &str,
    errors: &mut Vec<String>,
) -> Option<&'a Vec<Value>> {
    match value.as_array() {
        Some(value) => Some(value),
        None => {
            errors.push(format!("{path} must be an array"));
            None
        }
    }
}

fn expect_object<'a>(
    value: &'a Value,
    path: &str,
    errors: &mut Vec<String>,
) -> Option<&'a Map<String, Value>> {
    match value.as_object() {
        Some(value) => Some(value),
        None => {
            errors.push(format!("{path} must be an object"));
            None
        }
    }
}

fn expect_enum(value: &Value, allowed: &[&str], path: &str, errors: &mut Vec<String>) {
    let Some(value) = value.as_str() else {
        errors.push(format!("{path} must be a string enum"));
        return;
    };
    if !allowed.contains(&value) {
        errors.push(format!("{path} has invalid value {value:?}"));
    }
}
