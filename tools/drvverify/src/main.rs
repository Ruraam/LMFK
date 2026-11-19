//! Verify a package in three distinct stages. A valid hash never implies
//! authenticity; both stages must pass before the verdict is ACCEPTED.

use std::{env, fs, process::ExitCode};

use lmfk_drv_crypto::{Policy, TrustStore, hex, verify_all};
use lmfk_drv_parser::parse;

fn unhex(value: &str) -> Option<[u8; 32]> {
    let value = value.trim().trim_start_matches("0x");
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn load_trust(
    keys_dir: Option<&String>,
    revoked_file: Option<&String>,
) -> Result<TrustStore, String> {
    let mut store = TrustStore::new();
    if let Some(dir) = keys_dir {
        let entries =
            fs::read_dir(dir).map_err(|e| format!("cannot read key directory {dir}: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("invalid directory entry: {e}"))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let public =
                fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let public: [u8; 32] = public
                .try_into()
                .map_err(|_| format!("key file {} must be exactly 32 bytes", path.display()))?;
            let label = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".to_owned());
            store.add(public, label);
        }
    }
    if let Some(file) = revoked_file {
        let content = fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))?;
        for line in content.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let id = unhex(line).ok_or_else(|| format!("invalid key id in {file}: {line}"))?;
            store.revoke(&id);
        }
    }
    Ok(store)
}

fn usage() -> ! {
    eprintln!("usage: drvverify [--keys DIR] [--revoked FILE] [--min-policy N] <package.drv>");
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let mut keys_dir = None;
    let mut revoked = None;
    let mut min_policy = 1u64;
    let mut package_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--keys" => keys_dir = Some(args.next().unwrap_or_else(|| usage())),
            "--revoked" => revoked = Some(args.next().unwrap_or_else(|| usage())),
            "--min-policy" => {
                let value = args.next().unwrap_or_else(|| usage());
                min_policy = value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --min-policy value: {value}");
                    std::process::exit(2);
                });
            }
            "--help" => usage(),
            other if other.starts_with("--") => {
                eprintln!("unknown option: {other}");
                usage();
            }
            other => package_path = Some(other.to_owned()),
        }
    }
    let Some(path) = package_path else { usage() };

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
            println!("Structure: INVALID ({error})");
            println!("Integrity: NOT CHECKED");
            println!("Signature: NOT CHECKED");
            println!("Verdict  : REJECTED");
            return ExitCode::from(2);
        }
    };

    println!("Structure: VALID");
    let trust = match load_trust(keys_dir.as_ref(), revoked.as_ref()) {
        Ok(trust) => trust,
        Err(error) => {
            eprintln!("trust store error: {error}");
            println!("Integrity: NOT CHECKED");
            println!("Signature: NOT CHECKED");
            println!("Verdict  : REJECTED");
            return ExitCode::from(1);
        }
    };
    let policy = Policy {
        min_format_version: 1,
        min_security_policy: min_policy,
    };
    let report = verify_all(&package, &trust, &policy);

    match &report.integrity {
        Ok(result) => println!(
            "Integrity: VERIFIED ({} section(s))",
            result.sections_checked
        ),
        Err(error) => println!("Integrity: FAILED ({error})"),
    }
    match &report.authenticity {
        Ok(result) => println!("Signature: AUTHENTICATED (key_id={})", hex(&result.key_id)),
        Err(error) => println!("Signature: NOT AUTHENTICATED ({error})"),
    }

    if report.accepted() {
        println!("Verdict  : ACCEPTED");
        ExitCode::SUCCESS
    } else {
        println!("Verdict  : REJECTED");
        ExitCode::from(1)
    }
}
