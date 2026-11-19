# LMFK — Linux Modular-Free Kernel

LMFK is a hybrid kernel project built around a **stable driver ABI**. The goal is to define a public, versioned interface to device drivers that is independent of any particular kernel implementation, so that a driver compiled once keeps working across kernel versions and can be installed or updated without rebuilding or rebooting the kernel.

The central design idea: *we do not freeze the kernel internals, we freeze the public interface to drivers.* Drivers run by default in userspace (isolated when untrusted), are shipped as signed `.drv` packages, and cross the kernel boundary only through opaque handles and a function table — never through raw pointers or imported symbols.

> LMFK is a distinct project from the `B-Web` Rust browser engine.

## Documentation

English documentation (under [`docs/en/`](docs/en/)):

- [Technical Specification v0.1](docs/en/00-technical-spec.md) — scope, architecture, ABI design rules, roadmap and risks.
- [`.drv` Package Format v1](docs/en/01-drv-format.md) — binary container, typed CBOR manifest, section flags and the signature zone.

French documentation (under [`docs/fr/`](docs/fr/)):

- [Cahier des charges technique v0.1](docs/fr/00-cahier-des-charges.md)
- [Format de paquet `.drv` v1](docs/fr/01-format-drv.md)

For an index of this repository, see [README.md](README.md).

## Workspace crates

The Cargo workspace contains four library crates and three command-line tools.

| Crate | Path | Role |
|---|---|---|
| `lmfk-abi` | `crates/lmfk-abi` | ABI v1 definitions — the driver/kernel contract only, with no kernel implementation. Opaque handles, status codes, IPC types and `major << 16 \| minor` versioning. |
| `lmfk-drv-format` | `crates/lmfk-drv-format` | `.drv` binary container definitions (header, section table) and the strict, typed CBOR manifest encoder/decoder with a deterministic profile. |
| `lmfk-drv-parser` | `crates/lmfk-drv-parser` | Bounds-checked, overflow-safe parser and validator for `.drv` packages; malformed-file and negative tests. Exposes the signature zone as opaque bytes. |
| `lmfk-drv-crypto` | `crates/lmfk-drv-crypto` | Integrity (SHA-256) and authenticity (Ed25519) verification, trust store, key lifecycle, revocation and downgrade policy. |
| `drvinfo` | `tools/drvinfo` | Inspect the header, sections and manifest of a `.drv` package. |
| `drvverify` | `tools/drvverify` | Verify a package's structure, integrity and authenticity; never short-circuits the stages. |
| `drvpack` | `tools/drvpack` | Build a `.drv` container from a CBOR manifest and section files, then sign it. |

The C ABI header lives in [`include/lmfk/abi.h`](include/lmfk/abi.h); its layout is checked by [`tests/abi_layout.c`](tests/abi_layout.c) and by Rust tests in `crates/lmfk-abi/tests/`.

## Build and test

```sh
# Build every crate and tool in the workspace
cargo build --workspace

# Run the full test suite
cargo test --workspace

# Work on one crate in particular
cargo test -p lmfk-abi
cargo test -p lmfk-drv-format
cargo test -p lmfk-drv-parser
cargo test -p lmfk-drv-crypto

# Check the C ABI header layout (gcc or clang)
cc -std=c11 -fsyntax-only -Iinclude tests/abi_layout.c
```

The workspace targets Rust 1.85 (edition 2024). The ABI is a **contract**, not a representation of an internal implementation: no kernel structure, pointer or architecture-dependent type crosses the boundary. See [`include/lmfk/abi.h`](include/lmfk/abi.h) for the versioning rules.

## Current status

| Component | Status |
|---|---|
| Technical specification / cahier des charges | Delivered (v0.1) |
| `.drv` format specification + structural parser | Delivered |
| ABI v1 (C header + Rust crate) | Delivered |
| Ed25519 / SHA-256 cryptographic verification (`lmfk-drv-crypto`) | Implemented — pending review |
| Tools (`drvinfo`, `drvverify`, `drvpack`) | Implemented — pending review |
| Driver Manager (detection, matching, lifecycle) | Not started |

## The three-stage verification rule

Verification is deliberately split into **three distinct stages**, and the stages are never conflated. A valid SHA-256 digest never implies authenticity.

1. **Structure** — structural parsing by `lmfk-drv-parser`. This stage is **free of any cryptographic verification**: it checks bounds, offsets, non-overlap, section flag masks and manifest/header consistency, and exposes the signature as opaque bytes. It never verifies hashes or signatures. Reported as `VerificationLevel::Structure`.
2. **Integrity** — `verify_integrity()` checks every non-BSS section against its SHA-256 digest in the section table. This detects corruption and payload tampering but says nothing about who produced the digests. Reported as `VerificationLevel::Integrity`. If any hash is wrong, the highest level stays `Structure`.
3. **Authenticity** — `verify_authenticity()` verifies the Ed25519 signature over the signed region, checks the key against the trust store (including revocation) and enforces the format-version and security-policy downgrade rules. This stage does **not** check section hashes. Reported as `VerificationLevel::Authenticated`.

`verify_all()` runs the integrity and authenticity stages independently and **never short-circuits**, so callers see exactly which stage failed. A package is **ACCEPTED only when both integrity and authenticity succeed** — a valid signature over corrupt section hashes is reported as `Structure`, never as `Authenticated`. In production an unsigned `.drv` is refused; `drvverify` must pass before any installation or execution.

For the exact container invariants (signature-at-end rule, section flag masks, canonical CBOR key order), see the [`.drv` format specification](docs/en/01-drv-format.md).
