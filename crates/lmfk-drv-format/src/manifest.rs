//! Manifeste typé d'un paquet `.drv`, décodé depuis un map CBOR.

use alloc::vec::Vec;
use core::convert::TryFrom;

use crate::cbor::{self, Error as CborError, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverMode {
    Kernel = 0,
    Userspace = 1,
    Isolated = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceMatch {
    pub bus: u16,
    pub vendor: u32,
    pub device: u32,
    pub sub_vendor: u32,
    pub sub_device: u32,
    pub class: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dependency<'a> {
    pub name: &'a str,
    pub min: Option<&'a str>,
    pub max: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest<'a> {
    pub id: [u8; 16],
    pub name: &'a str,
    pub version: &'a str,
    pub abi_min: u32,
    pub abi_max: u32,
    pub arch: Vec<u32>,
    pub devices: Vec<DeviceMatch>,
    pub caps: Vec<&'a str>,
    pub deps: Vec<Dependency<'a>>,
    pub mode: DriverMode,
    pub entry: &'a str,
    pub license: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Cbor(CborError),
    NotMap,
    MissingField(&'static str),
    WrongType(&'static str),
    InvalidIdLen(usize),
    InvalidAbiRange,
    UnknownArch(u32),
    UnknownMode(u32),
    LimitExceeded(&'static str),
    EmptyText(&'static str),
}

impl From<CborError> for Error {
    fn from(err: CborError) -> Self {
        Self::Cbor(err)
    }
}

/* ------------------------------------------------------------------------- */
/* Accès aux champs                                                           */
/* ------------------------------------------------------------------------- */

fn field<'m, 'd>(
    map: &'m [(Value<'d>, Value<'d>)],
    key: &'static str,
) -> Result<&'m Value<'d>, Error> {
    map.iter()
        .find_map(|(k, v)| match k {
            Value::Text(t) if *t == key => Some(v),
            _ => None,
        })
        .ok_or(Error::MissingField(key))
}

fn optional_field<'m, 'd>(
    map: &'m [(Value<'d>, Value<'d>)],
    key: &'static str,
) -> Option<&'m Value<'d>> {
    map.iter().find_map(|(k, v)| match k {
        Value::Text(t) if *t == key => Some(v),
        _ => None,
    })
}

fn uint(v: &Value<'_>, field: &'static str) -> Result<u32, Error> {
    match v {
        Value::Uint(n) => u32::try_from(*n).map_err(|_| Error::WrongType(field)),
        _ => Err(Error::WrongType(field)),
    }
}

fn text<'d>(v: &Value<'d>, field: &'static str) -> Result<&'d str, Error> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(Error::WrongType(field)),
    }
}

fn bytes<'d>(v: &Value<'d>, field: &'static str) -> Result<&'d [u8], Error> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(Error::WrongType(field)),
    }
}

fn array<'v, 'd>(v: &'v Value<'d>, field: &'static str) -> Result<&'v [Value<'d>], Error> {
    match v {
        Value::Array(items) => Ok(items.as_slice()),
        _ => Err(Error::WrongType(field)),
    }
}

fn map<'v, 'd>(
    v: &'v Value<'d>,
    field: &'static str,
) -> Result<&'v [(Value<'d>, Value<'d>)], Error> {
    match v {
        Value::Map(entries) => Ok(entries.as_slice()),
        _ => Err(Error::WrongType(field)),
    }
}

fn bounded_text<'d>(v: &Value<'d>, field: &'static str, max: usize) -> Result<&'d str, Error> {
    let s = text(v, field)?;
    if s.is_empty() {
        return Err(Error::EmptyText(field));
    }
    if s.len() > max {
        return Err(Error::LimitExceeded(field));
    }
    Ok(s)
}

/* ------------------------------------------------------------------------- */
/* Décodage                                                                    */
/* ------------------------------------------------------------------------- */

pub fn decode(data: &[u8]) -> Result<Manifest<'_>, Error> {
    let root = cbor::decode(data)?;
    let root = map(&root, "root")?;

    let id_bytes = bytes(field(root, "id")?, "id")?;
    if id_bytes.len() != 16 {
        return Err(Error::InvalidIdLen(id_bytes.len()));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(id_bytes);

    let name = bounded_text(field(root, "name")?, "name", 128)?;
    let version = bounded_text(field(root, "version")?, "version", 64)?;
    let entry = bounded_text(field(root, "entry")?, "entry", 128)?;
    let license = match optional_field(root, "license") {
        Some(v) => Some(bounded_text(v, "license", 128)?),
        None => None,
    };

    let abi_min = uint(field(root, "abi_min")?, "abi_min")?;
    let abi_max = uint(field(root, "abi_max")?, "abi_max")?;
    if abi_min > abi_max {
        return Err(Error::InvalidAbiRange);
    }
    if abi_min == 0 {
        return Err(Error::InvalidAbiRange);
    }

    let arch_values = array(field(root, "arch")?, "arch")?;
    if arch_values.is_empty() || arch_values.len() > 8 {
        return Err(Error::LimitExceeded("arch"));
    }
    let mut arch = Vec::with_capacity(arch_values.len());
    for value in arch_values {
        let code = uint(value, "arch")?;
        if crate::arch_bit(code).is_none() {
            return Err(Error::UnknownArch(code));
        }
        if !arch.contains(&code) {
            arch.push(code);
        }
    }

    let device_values = array(field(root, "devices")?, "devices")?;
    if device_values.is_empty() || device_values.len() > 256 {
        return Err(Error::LimitExceeded("devices"));
    }
    let mut devices = Vec::with_capacity(device_values.len());
    for value in device_values {
        let m = map(value, "devices[]")?;
        let bus = uint(field(m, "bus")?, "bus")?;
        let bus = u16::try_from(bus).map_err(|_| Error::WrongType("bus"))?;
        devices.push(DeviceMatch {
            bus,
            vendor: uint(field(m, "vendor")?, "vendor")?,
            device: uint(field(m, "device")?, "device")?,
            sub_vendor: optional_field(m, "sub_vendor")
                .map(|v| uint(v, "sub_vendor"))
                .transpose()?
                .unwrap_or(0),
            sub_device: optional_field(m, "sub_device")
                .map(|v| uint(v, "sub_device"))
                .transpose()?
                .unwrap_or(0),
            class: optional_field(m, "class")
                .map(|v| uint(v, "class"))
                .transpose()?
                .unwrap_or(0),
        });
    }

    let cap_values = array(field(root, "caps")?, "caps")?;
    if cap_values.len() > 64 {
        return Err(Error::LimitExceeded("caps"));
    }
    let mut caps = Vec::with_capacity(cap_values.len());
    for value in cap_values {
        caps.push(bounded_text(value, "caps", 128)?);
    }

    let dep_values = array(field(root, "deps")?, "deps")?;
    if dep_values.len() > 64 {
        return Err(Error::LimitExceeded("deps"));
    }
    let mut deps = Vec::with_capacity(dep_values.len());
    for value in dep_values {
        let m = map(value, "deps[]")?;
        deps.push(Dependency {
            name: bounded_text(field(m, "name")?, "deps[].name", 128)?,
            min: optional_field(m, "min")
                .map(|v| bounded_text(v, "deps[].min", 64))
                .transpose()?,
            max: optional_field(m, "max")
                .map(|v| bounded_text(v, "deps[].max", 64))
                .transpose()?,
        });
    }

    let mode = match uint(field(root, "mode")?, "mode")? {
        0 => DriverMode::Kernel,
        1 => DriverMode::Userspace,
        2 => DriverMode::Isolated,
        other => return Err(Error::UnknownMode(other)),
    };

    Ok(Manifest {
        id,
        name,
        version,
        abi_min,
        abi_max,
        arch,
        devices,
        caps,
        deps,
        mode,
        entry,
        license,
    })
}
