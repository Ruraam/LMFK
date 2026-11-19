//! Build a .drv container from a CBOR manifest and section files, then sign it.

use std::{env, fs, io::Read, process::ExitCode};

use ed25519_dalek::{Signer, SigningKey};
use lmfk_drv_crypto::{
    signature::{self, ALG_ED25519},
    trust::key_id,
};
use lmfk_drv_format::{
    HEADER_SIZE, Header, PKG_F_SIGNED, SECTION_ENTRY_SIZE, SECTION_F_ALLOC, SECTION_F_EXEC,
    SECTION_F_WRITE, SECTION_TYPE_BSS, SECTION_TYPE_DATA, SECTION_TYPE_RELOC,
    SECTION_TYPE_RESOURCE, SECTION_TYPE_RODATA, SECTION_TYPE_TEXT, SectionHeader, arch_bit,
    cbor::{self, Value},
    manifest,
};
use sha2::{Digest, Sha256};

struct InputSection {
    name: String,
    ty: u32,
    flags: u32,
    offset: u64,
    size: u64,
    sha256: [u8; 32],
    payload: Option<Vec<u8>>,
}

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

fn section_kind(name: &str) -> Option<(u32, u32)> {
    match name {
        ".text" => Some((SECTION_TYPE_TEXT, SECTION_F_ALLOC | SECTION_F_EXEC)),
        ".rodata" => Some((SECTION_TYPE_RODATA, SECTION_F_ALLOC)),
        ".data" => Some((SECTION_TYPE_DATA, SECTION_F_ALLOC | SECTION_F_WRITE)),
        ".bss" => Some((SECTION_TYPE_BSS, SECTION_F_ALLOC)),
        ".reloc" => Some((SECTION_TYPE_RELOC, 0)),
        ".resources" => Some((SECTION_TYPE_RESOURCE, 0)),
        _ => None,
    }
}

fn generate_key(path: &str) -> Result<[u8; 32], String> {
    let mut seed = [0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut seed))
        .map_err(|e| format!("cannot generate key: {e}"))?;
    fs::write(path, seed).map_err(|e| format!("cannot write key file {path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot secure key file {path}: {e}"))?;
    }
    Ok(seed)
}

fn load_key(path: &str) -> Result<[u8; 32], String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read key {path}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("key file {path} must be exactly 32 bytes"))
}

struct ManifestInfo {
    abi_min: u32,
    abi_max: u32,
    arch: Vec<u32>,
}

fn prepare_manifest(path: &str, policy: u64) -> Result<(Vec<u8>, ManifestInfo), String> {
    let raw = fs::read(path).map_err(|e| format!("cannot read manifest {path}: {e}"))?;
    let decoded = manifest::decode(&raw).map_err(|e| format!("invalid manifest: {e:?}"))?;
    let info = ManifestInfo {
        abi_min: decoded.abi_min,
        abi_max: decoded.abi_max,
        arch: decoded.arch.clone(),
    };

    let root = cbor::decode(&raw).map_err(|e| format!("manifest is not CBOR: {e:?}"))?;
    let Value::Map(mut entries) = root else {
        return Err("manifest root must be a CBOR map".to_owned());
    };
    entries.retain(|(key, _)| !matches!(key, Value::Text("security_policy")));
    entries.push((Value::Text("security_policy"), Value::Uint(policy)));
    let prepared = cbor::encode_vec(&Value::Map(entries));

    let check = manifest::decode(&prepared).map_err(|e| format!("invalid manifest: {e:?}"))?;
    debug_assert_eq!(check.security_policy, Some(policy));
    Ok((prepared, info))
}

fn usage() -> ! {
    eprintln!(
        "usage: drvpack --manifest FILE.cbor --out FILE.drv \
         [--section .text=FILE]... [--key SEED.bin | --gen-key SEED.bin] \
         [--security-policy N]"
    );
    std::process::exit(2);
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut manifest_path = None;
    let mut output_path = None;
    let mut section_args = Vec::new();
    let mut key_path = None;
    let mut gen_key_path = None;
    let mut security_policy = 1u64;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifest" => manifest_path = Some(args.next().unwrap_or_else(|| usage())),
            "--out" => output_path = Some(args.next().unwrap_or_else(|| usage())),
            "--section" => section_args.push(args.next().unwrap_or_else(|| usage())),
            "--key" => key_path = Some(args.next().unwrap_or_else(|| usage())),
            "--gen-key" => gen_key_path = Some(args.next().unwrap_or_else(|| usage())),
            "--security-policy" => {
                let value = args.next().unwrap_or_else(|| usage());
                security_policy = value
                    .parse()
                    .map_err(|_| format!("invalid security policy: {value}"))?;
            }
            "--help" => usage(),
            other => return Err(format!("unknown option: {other}")),
        }
    }
    let manifest_path = manifest_path.ok_or_else(|| "missing --manifest".to_owned())?;
    let output_path = output_path.ok_or_else(|| "missing --out".to_owned())?;
    if section_args.is_empty() {
        return Err("at least one --section is required".to_owned());
    }
    if key_path.is_some() && gen_key_path.is_some() {
        return Err("--key and --gen-key are mutually exclusive".to_owned());
    }

    let seed = if let Some(path) = gen_key_path {
        Some(generate_key(&path)?)
    } else if let Some(path) = key_path {
        Some(load_key(&path)?)
    } else {
        None
    };

    let (manifest_cbor, parsed_manifest) = prepare_manifest(&manifest_path, security_policy)?;
    let mut arch_mask = 0u32;
    for &code in &parsed_manifest.arch {
        arch_mask |= arch_bit(code).ok_or_else(|| format!("unknown architecture: {code}"))?;
    }

    let mut sections = Vec::new();
    for argument in &section_args {
        let (name, path) = argument
            .split_once('=')
            .ok_or_else(|| format!("expected --section name=path, got {argument}"))?;
        let (ty, flags) =
            section_kind(name).ok_or_else(|| format!("unknown section name: {name}"))?;
        let bytes = fs::read(path).map_err(|e| format!("cannot read section {path}: {e}"))?;
        let payload = if ty == SECTION_TYPE_BSS {
            None
        } else {
            Some(bytes)
        };
        let size = match &payload {
            Some(bytes) => bytes.len() as u64,
            None => {
                // For BSS the referenced file contains the size as decimal text.
                let text = fs::read_to_string(path)
                    .map_err(|e| format!("cannot read BSS size file {path}: {e}"))?;
                text.trim()
                    .parse::<u64>()
                    .map_err(|_| format!("BSS size file {path} must contain one integer"))?
            }
        };
        sections.push(InputSection {
            name: name.to_owned(),
            ty,
            flags,
            offset: 0,
            size,
            sha256: payload
                .as_ref()
                .map(|bytes| Sha256::digest(bytes).into())
                .unwrap_or([0u8; 32]),
            payload,
        });
    }

    let table_offset = HEADER_SIZE;
    let mut cursor = table_offset + sections.len() * SECTION_ENTRY_SIZE;
    for section in &mut sections {
        if section.payload.is_some() {
            cursor = align8(cursor);
            section.offset = cursor as u64;
            cursor += section.size as usize;
        }
    }
    let manifest_offset = align8(cursor);
    let manifest_end = manifest_offset + manifest_cbor.len();
    let signature_offset = align8(manifest_end);

    let signing_key = seed.map(|secret| SigningKey::from_bytes(&secret));
    let declared_key_id = signing_key
        .as_ref()
        .map(|key| key_id(&key.verifying_key().to_bytes()));
    let placeholder = signature::encode(&signature::SignatureBlob {
        alg: ALG_ED25519,
        key_id: declared_key_id.unwrap_or([0u8; 32]),
        signature: [0u8; 64],
    });
    let signature_length = if signing_key.is_some() {
        placeholder.len() as u64
    } else {
        0
    };
    let total_size = if signing_key.is_some() {
        signature_offset as u64 + signature_length
    } else {
        manifest_end as u64
    };

    let mut data = vec![0u8; total_size as usize];
    for (index, section) in sections.iter().enumerate() {
        let entry = SectionHeader {
            name: section.name.as_bytes(),
            ty: section.ty,
            flags: section.flags,
            offset: section.offset,
            size: section.size,
            align: 8,
            sha256: section.sha256,
        };
        let start = table_offset + index * SECTION_ENTRY_SIZE;
        entry.to_bytes(&mut data[start..start + SECTION_ENTRY_SIZE]);
        if let Some(payload) = &section.payload {
            let offset = section.offset as usize;
            data[offset..offset + payload.len()].copy_from_slice(payload);
        }
    }
    data[manifest_offset..manifest_end].copy_from_slice(&manifest_cbor);

    let header = Header {
        format_version: 1,
        flags: if signing_key.is_some() {
            PKG_F_SIGNED
        } else {
            0
        },
        abi_min: parsed_manifest.abi_min,
        abi_max: parsed_manifest.abi_max,
        section_count: sections.len() as u32,
        arch_mask,
        total_size,
        section_table_offset: table_offset as u64,
        manifest_offset: manifest_offset as u64,
        manifest_length: manifest_cbor.len() as u64,
        signature_offset: if signing_key.is_some() {
            signature_offset as u64
        } else {
            0
        },
        signature_length,
    };
    header.to_bytes(&mut data[..HEADER_SIZE]);

    if let Some(key) = &signing_key {
        let sig = key.sign(&data[..signature_offset]);
        let blob = signature::encode(&signature::SignatureBlob {
            alg: ALG_ED25519,
            key_id: key_id(&key.verifying_key().to_bytes()),
            signature: sig.to_bytes(),
        });
        debug_assert_eq!(blob.len(), signature_length as usize);
        data[signature_offset..].copy_from_slice(&blob);
    }

    fs::write(&output_path, &data).map_err(|e| format!("cannot write {output_path}: {e}"))?;
    println!("Wrote {output_path} ({} bytes)", data.len());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("drvpack: {error}");
            ExitCode::from(1)
        }
    }
}
