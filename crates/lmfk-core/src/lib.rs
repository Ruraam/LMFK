//! Shared immutable types for the LMFK hardware inventory.
//!
//! The structure mirrors the JSON schema v1.0 defined in
//! `docs/en/06-inventory-schema.md`. Field names and enum values are part of
//! the public contract; no additional fields are emitted by Phase 1.

use serde::Serialize;

pub mod validation;

pub use validation::validate_json;

/// Current inventory schema version. Readers must check it before use.
pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureBoot {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Host {
    pub kernel_release: String,
    pub kernel_version: String,
    pub arch: String,
    pub distro_id: String,
    pub distro_version: String,
    pub secure_boot: SecureBoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanError {
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanMeta {
    pub sources: Vec<String>,
    pub read_only: bool,
    pub errors: Vec<ScanError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bus {
    Pci,
    Usb,
    Dt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverState {
    Bound,
    Unbound,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Driver {
    pub bound: Option<String>,
    pub state: DriverState,
}

impl Driver {
    pub fn unbound() -> Self {
        Self {
            bound: None,
            state: DriverState::Unbound,
        }
    }

    pub fn unknown() -> Self {
        Self {
            bound: None,
            state: DriverState::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdName {
    pub id: String,
    pub name: String,
}

/// Schema v1.0 uses `code` for class objects, not `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClassInfo {
    pub code: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Subsystem {
    pub vendor: String,
    pub device: String,
}

/// Initial classification. It is intentionally internal: schema v1.0 has no
/// dedicated classification field, so the label is exposed as `class.name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Network,
    Graphics,
    Audio,
    Storage,
    Usb,
    Other,
    Unknown,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Self::Network => "Network controller",
            Self::Graphics => "Graphics controller",
            Self::Audio => "Audio device",
            Self::Storage => "Storage controller",
            Self::Usb => "USB device",
            Self::Other => "Other device",
            Self::Unknown => "Unknown device",
        }
    }

    pub fn interface_label(self) -> &'static str {
        match self {
            Self::Network => "Network interface",
            Self::Graphics => "Video interface",
            Self::Audio => "Audio interface",
            Self::Storage => "Storage interface",
            Self::Usb => "USB interface",
            Self::Other => "Other interface",
            Self::Unknown => "Unknown interface",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbInterface {
    pub id: String,
    pub device_id: String,
    pub interface_number: u32,
    pub class: ClassInfo,
    pub modalias: String,
    pub driver: Driver,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Device {
    pub id: String,
    pub bus: Bus,
    pub class: ClassInfo,
    pub vendor: IdName,
    pub device: IdName,
    pub subsystem: Subsystem,
    pub modalias: String,
    pub path: String,
    pub parent: Option<String>,
    pub interfaces: Vec<UsbInterface>,
    pub driver: Driver,
    pub modules: Vec<Module>,
    pub firmwares: Vec<Firmware>,
    pub package_suggestions: Vec<Suggestion>,
    pub diagnosis: Vec<Diagnosis>,
}

impl Device {
    pub fn has_bound_driver(&self) -> bool {
        self.driver.state == DriverState::Bound
            || self
                .interfaces
                .iter()
                .any(|i| i.driver.state == DriverState::Bound)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    Loaded,
    Available,
    Builtin,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchSource {
    ModulesAlias,
    ModulesBuiltin,
    DriverLink,
    Modalias,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Module {
    pub name: String,
    pub match_source: MatchSource,
    pub state: ModuleState,
    pub dependencies: Vec<String>,
    pub firmwares: Vec<Firmware>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Firmware {
    pub alias: String,
    pub present: bool,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    /// Open string: a new distribution may use any identifier.
    pub backend: String,
    pub package: String,
    pub reason: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnosis {
    pub code: String,
    pub title: String,
    pub explanation: String,
    pub severity: Severity,
    pub evidence: Vec<String>,
    pub advised_action: String,
    pub message: String,
}

impl Diagnosis {
    /// Required by schema v1.0 whenever `package_suggestions` is empty.
    /// It states an absence of information, not a hardware problem.
    pub fn package_unknown() -> Self {
        Self {
            code: "PACKAGE_UNKNOWN".to_owned(),
            title: "No package could be identified".to_owned(),
            explanation:
                "No distribution package lookup was performed in this phase, so no package can be named."
                    .to_owned(),
            severity: Severity::Info,
            evidence: vec!["no package backend queried in Phase 1".to_owned()],
            advised_action:
                "Search your distribution's packages using the hardware IDs or modalias."
                    .to_owned(),
            message:
                "No package could be identified. No distribution package lookup was performed, \
                 so none is suggested. Search your distribution's packages with the hardware IDs."
                    .to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub devices: usize,
    pub with_driver: usize,
    pub without_driver: usize,
    pub missing_firmware: usize,
    pub errors: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Inventory {
    pub schema_version: String,
    pub generated_at: String,
    pub host: Host,
    pub scan: ScanMeta,
    pub devices: Vec<Device>,
    pub summary: Summary,
}

impl Inventory {
    pub fn new(
        generated_at: impl Into<String>,
        host: Host,
        scan: ScanMeta,
        devices: Vec<Device>,
    ) -> Self {
        let with_driver = devices.iter().filter(|d| d.has_bound_driver()).count();
        let missing_firmware = devices
            .iter()
            .filter(|d| d.firmwares.iter().any(|f| !f.present))
            .count();
        let summary = Summary {
            devices: devices.len(),
            with_driver,
            without_driver: devices.len() - with_driver,
            missing_firmware,
            errors: scan.errors.len(),
        };
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            generated_at: generated_at.into(),
            host,
            scan,
            devices,
            summary,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
