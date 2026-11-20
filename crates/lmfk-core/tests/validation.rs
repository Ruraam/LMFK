//! Contract validation tests for JSON schema v1.0.

use lmfk_core::validate_json;
use serde_json::{Value, json};

const SCHEMA_JSON: &str = include_str!("../../../docs/en/06-inventory-schema.json");

fn schema_validator() -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(SCHEMA_JSON).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn assert_schema_valid(doc: &Value) {
    let validator = schema_validator();
    let errors: Vec<_> = validator.iter_errors(doc).collect();
    assert!(errors.is_empty(), "unexpected schema errors: {errors:?}");
}

fn assert_schema_invalid(doc: &Value) {
    let validator = schema_validator();
    let errors: Vec<_> = validator.iter_errors(doc).collect();
    assert!(
        !errors.is_empty(),
        "schema should have rejected the document"
    );
}

fn valid_inventory() -> Value {
    json!({
        "schema_version": "1.0",
        "generated_at": "2026-11-20T10:00:00Z",
        "host": {
            "kernel_release": "6.1.0-test",
            "kernel_version": "#1 SMP test",
            "arch": "x86_64",
            "distro_id": "example-distro",
            "distro_version": "1",
            "secure_boot": "unknown"
        },
        "scan": {
            "sources": ["/sys/bus/pci/devices"],
            "read_only": true,
            "errors": []
        },
        "devices": [{
            "id": "pci:0000:00:02.0",
            "bus": "pci",
            "class": { "code": "0x030000", "name": "Graphics controller" },
            "vendor": { "id": "0x8086", "name": "Intel Corporation" },
            "device": { "id": "0x9bc4", "name": "UHD Graphics 630" },
            "subsystem": { "vendor": "0x8086", "device": "0x0000" },
            "modalias": "pci:v00008086d00009BC4sv00008086sd00000000bc03sc00i00",
            "path": "/sys/bus/pci/devices/0000:00:02.0",
            "parent": null,
            "interfaces": [],
            "driver": { "bound": "i915", "state": "bound" },
            "modules": [],
            "firmwares": [],
            "package_suggestions": [],
            "diagnosis": [{
                "code": "PACKAGE_UNKNOWN",
                "title": "No package could be identified",
                "explanation": "No package lookup was performed.",
                "severity": "info",
                "evidence": ["no package backend queried"],
                "advised_action": "Search your distribution packages.",
                "message": "No package could be identified. No lookup was performed."
            }]
        }],
        "summary": {
            "devices": 1,
            "with_driver": 1,
            "without_driver": 0,
            "missing_firmware": 0,
            "errors": 0
        }
    })
}

#[test]
fn accepts_a_valid_inventory() {
    let doc = valid_inventory();
    assert_schema_valid(&doc);
    assert!(validate_json(&doc).is_ok());
}

#[test]
fn rejects_invalid_rfc3339_timestamp() {
    let mut doc = valid_inventory();
    doc["generated_at"] = json!("yesterday at noon");
    assert_schema_invalid(&doc);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|error| error.contains("RFC 3339")));
}

#[test]
fn rejects_missing_required_field() {
    let mut doc = valid_inventory();
    doc.as_object_mut().unwrap().remove("schema_version");
    assert_schema_invalid(&doc);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("schema_version")));
}

#[test]
fn rejects_wrong_types() {
    let mut doc = valid_inventory();
    doc["scan"]["read_only"] = json!("yes");
    assert_schema_invalid(&doc);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("scan.read_only")));
}

#[test]
fn rejects_unknown_enum_values() {
    let mut doc = valid_inventory();
    doc["host"]["secure_boot"] = json!("maybe");
    assert_schema_invalid(&doc);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("host.secure_boot")));

    let mut doc = valid_inventory();
    doc["devices"][0]["driver"]["state"] = json!("installed");
    assert_schema_invalid(&doc);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("driver.state")));
}

#[test]
fn rejects_class_id_instead_of_class_code() {
    let mut doc = valid_inventory();
    doc["devices"][0]["class"]
        .as_object_mut()
        .unwrap()
        .remove("code");
    doc["devices"][0]["class"]["id"] = json!("0x030000");
    assert_schema_invalid(&doc);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("class.code")));
}

#[test]
fn rejects_empty_suggestions_without_package_unknown() {
    let mut doc = valid_inventory();
    doc["devices"][0]["diagnosis"] = json!([]);
    assert_schema_invalid(&doc);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("PACKAGE_UNKNOWN")));
}

#[test]
fn rejects_absolute_or_wrongly_prefixed_ids() {
    let mut doc = valid_inventory();
    doc["devices"][0]["id"] = json!("/sys/bus/pci/devices/0000:00:02.0");
    assert_schema_invalid(&doc);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("absolute path")));

    let mut doc = valid_inventory();
    doc["devices"][0]["id"] = json!("usb:1-4");
    assert_schema_invalid(&doc);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("must start with")));
}

#[test]
fn rejects_inconsistent_summary() {
    // Cross-field arithmetic cannot be expressed by JSON Schema; the manual
    // contract validator covers it.
    let mut doc = valid_inventory();
    doc["summary"]["devices"] = json!(12);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("summary.devices")));
}

#[test]
fn rejects_interface_with_wrong_parent_reference() {
    // JSON Schema cannot reference a sibling object's id; this relationship
    // is checked by the manual contract validator.
    let mut doc = valid_inventory();
    doc["devices"][0]["bus"] = json!("usb");
    doc["devices"][0]["id"] = json!("usb:1-4");
    doc["devices"][0]["interfaces"] = json!([{
        "id": "usb:1-4:1.0",
        "device_id": "usb:1-2",
        "interface_number": 0,
        "class": { "code": "0x000200", "name": "Network interface" },
        "modalias": "usb:v0BDAp8812d0000dc02dsc00dp00ic02isc00if00",
        "driver": { "bound": null, "state": "unbound" }
    }]);
    let errors = validate_json(&doc).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("device_id")));
}
