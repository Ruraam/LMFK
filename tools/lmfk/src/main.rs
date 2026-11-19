//! LMFK command-line interface. Phase 1 implements `lmfk scan` only.

use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use lmfk_core::{Host, Inventory, SecureBoot};
use lmfk_hw::{ScanOptions, scan};

fn read_small(path: &str) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn os_release_field(field: &str) -> String {
    let content = fs::read_to_string("/etc/os-release").unwrap_or_default();
    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key == field {
                return value.trim().trim_matches('"').to_owned();
            }
        }
    }
    "unknown".to_owned()
}

fn secure_boot_state() -> SecureBoot {
    let path = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    match fs::read(path) {
        Ok(bytes) => match bytes.last() {
            Some(1) => SecureBoot::Enabled,
            Some(0) => SecureBoot::Disabled,
            _ => SecureBoot::Unknown,
        },
        Err(_) => SecureBoot::Unknown,
    }
}

fn host_info() -> Host {
    Host {
        kernel_release: read_small("/proc/sys/kernel/osrelease"),
        kernel_version: read_small("/proc/version"),
        arch: std::env::consts::ARCH.to_owned(),
        distro_id: os_release_field("ID"),
        distro_version: os_release_field("VERSION_ID"),
        secure_boot: secure_boot_state(),
    }
}

/// Minimal UTC RFC 3339 formatter; avoids a date dependency for a single field.
fn rfc3339_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let days = seconds.div_euclid(86_400);
    let remainder = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3600,
        (remainder % 3600) / 60,
        remainder % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (year + if month <= 2 { 1 } else { 0 }, month, day)
}

fn line(text: &str) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    // Ignoring write errors lets `lmfk scan | head` exit cleanly.
    let _ = writeln!(handle, "{text}");
}

fn print_text(inventory: &Inventory) {
    let boot = match inventory.host.secure_boot {
        SecureBoot::Enabled => "enabled",
        SecureBoot::Disabled => "disabled",
        SecureBoot::Unknown => "unknown",
    };
    line(&format!(
        "LMFK hardware inventory (schema {})",
        inventory.schema_version
    ));
    line(&format!("Generated: {}", inventory.generated_at));
    line(&format!(
        "Host: kernel {} | {} | {} {} | Secure Boot: {}",
        inventory.host.kernel_release,
        inventory.host.arch,
        inventory.host.distro_id,
        inventory.host.distro_version,
        boot
    ));
    line(&format!("Sources: {}", inventory.scan.sources.len()));
    line(&format!("Errors: {}", inventory.scan.errors.len()));
    for error in &inventory.scan.errors {
        line(&format!("  ! {}: {}", error.source, error.message));
    }
    line(&format!(
        "Devices: {} (with driver {}, without {})",
        inventory.summary.devices, inventory.summary.with_driver, inventory.summary.without_driver
    ));
    line("");
    for device in &inventory.devices {
        let driver = device.driver.bound.as_deref().unwrap_or("none");
        line(&format!(
            "[{}] {} (bus {:?})",
            device.id, device.class.name, device.bus
        ));
        line(&format!(
            "  vendor {}  device {}  class {}",
            device.vendor.id, device.device.id, device.class.id
        ));
        line(&format!("  modalias: {}", device.modalias));
        line(&format!(
            "  driver: {driver} ({:?})  parent: {}",
            device.driver.state,
            device.parent.as_deref().unwrap_or("-")
        ));
        if !device.interfaces.is_empty() {
            line(&format!("  interfaces: {}", device.interfaces.len()));
            for interface in &device.interfaces {
                let bound = interface.driver.bound.as_deref().unwrap_or("none");
                line(&format!(
                    "    {} class {} driver {bound} ({:?})",
                    interface.id, interface.class.id, interface.driver.state
                ));
            }
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: lmfk scan [--format text|json]");
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else { usage() };
    if command != "scan" {
        eprintln!("unknown command: {command}");
        usage();
    }
    let mut format = "text";
    while let Some(arg) = args.next() {
        if arg == "--format" {
            format = match args.next().as_deref() {
                Some("text") => "text",
                Some("json") => "json",
                Some(other) => {
                    eprintln!("unknown format: {other}");
                    usage();
                }
                None => usage(),
            };
        } else {
            eprintln!("unknown option: {arg}");
            usage();
        }
    }

    let root: PathBuf = Path::new("/sys").to_path_buf();
    let options = ScanOptions::new(&root, host_info(), rfc3339_now());
    let inventory = scan(&options);

    let output = if format == "json" {
        match inventory.to_json_pretty() {
            Ok(json) => json,
            Err(error) => {
                eprintln!("cannot serialize inventory: {error}");
                return ExitCode::from(1);
            }
        }
    } else {
        print_text(&inventory);
        return ExitCode::SUCCESS;
    };
    line(&output);
    ExitCode::SUCCESS
}
