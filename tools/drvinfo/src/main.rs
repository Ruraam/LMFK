//! Inspect a .drv package. Inspection never claims authenticity.

use std::{env, fs, process::ExitCode};

use lmfk_drv_crypto::{hex, signature};
use lmfk_drv_format::{
    SECTION_TYPE_BSS, SECTION_TYPE_DATA, SECTION_TYPE_RELOC, SECTION_TYPE_RESOURCE,
    SECTION_TYPE_RODATA, SECTION_TYPE_TEXT,
};
use lmfk_drv_parser::{DrvFile, parse};

fn arch_name(code: u32) -> &'static str {
    match code {
        1 => "x86_64",
        2 => "aarch64",
        3 => "armv7",
        4 => "riscv64",
        _ => "unknown",
    }
}

fn section_name(ty: u32) -> &'static str {
    match ty {
        SECTION_TYPE_TEXT => "TEXT",
        SECTION_TYPE_RODATA => "RODATA",
        SECTION_TYPE_DATA => "DATA",
        SECTION_TYPE_BSS => "BSS",
        SECTION_TYPE_RELOC => "RELOC",
        SECTION_TYPE_RESOURCE => "RESOURCE",
        _ => "UNKNOWN",
    }
}

fn mode_name(mode: &lmfk_drv_format::DriverMode) -> &'static str {
    match mode {
        lmfk_drv_format::DriverMode::Kernel => "kernel",
        lmfk_drv_format::DriverMode::Userspace => "userspace",
        lmfk_drv_format::DriverMode::Isolated => "isolated",
    }
}

fn print_package(path: &str, package: &DrvFile<'_>) {
    let header = package.header();
    let manifest = package.manifest();

    println!("File: {path}");
    println!("Size: {} bytes", package.raw().len());
    println!();
    println!("Structure");
    println!("  format version   : {}", header.format_version);
    println!("  flags            : {:#010x}", header.flags);
    println!(
        "  ABI range        : {:#010x} .. {:#010x}",
        header.abi_min, header.abi_max
    );
    println!(
        "  architectures    : {}",
        manifest
            .arch
            .iter()
            .map(|&code| arch_name(code))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  sections         : {}", header.section_count);
    for section in package.sections() {
        println!(
            "    {:<12} type={:<8} offset={:<6} size={:<6} align={} bytes={}",
            String::from_utf8_lossy(section.header.name),
            section_name(section.header.ty),
            section.header.offset,
            section.header.size,
            section.header.align,
            section.data.len()
        );
        println!("      sha256={}", hex(&section.header.sha256));
    }

    println!();
    println!("Manifest");
    println!("  id               : {}", hex(&manifest.id));
    println!("  name             : {}", manifest.name);
    println!("  version          : {}", manifest.version);
    println!("  entry            : {}", manifest.entry);
    println!("  mode             : {}", mode_name(&manifest.mode));
    println!(
        "  license          : {}",
        manifest.license.unwrap_or("unspecified")
    );
    println!(
        "  security policy  : {}",
        manifest
            .security_policy
            .map(|v| v.to_string())
            .unwrap_or_else(|| "absent".to_owned())
    );
    println!("  capabilities     : {:?}", manifest.caps);
    for device in &manifest.devices {
        println!(
            "  device           : bus={} vendor={:#06x} device={:#06x}",
            device.bus, device.vendor, device.device
        );
    }
    for dependency in &manifest.deps {
        println!(
            "  dependency       : {} (min={:?}, max={:?})",
            dependency.name, dependency.min, dependency.max
        );
    }

    println!();
    println!("Signature (declared only - NOT verified)");
    if package.signature().is_empty() {
        println!("  none");
    } else {
        match signature::decode(package.signature()) {
            Ok(blob) => {
                println!("  algorithm        : {}", blob.alg);
                println!("  key id           : {}", hex(&blob.key_id));
                println!("  signature bytes  : {}", blob.signature.len());
            }
            Err(error) => println!("  malformed blob   : {error}"),
        }
    }
    println!(
        "  signed region    : {} bytes",
        package.signed_region().len()
    );
}

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: drvinfo <package.drv>");
        return ExitCode::from(2);
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            return ExitCode::from(2);
        }
    };
    let package = match parse(&bytes) {
        Ok(package) => package,
        Err(error) => {
            eprintln!("structure check failed: {error}");
            return ExitCode::from(2);
        }
    };
    print_package(&path, &package);
    ExitCode::SUCCESS
}
