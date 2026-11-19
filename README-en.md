# LMFK — Linux Driver Manager

LMFK is a **Linux driver manager**. It focuses on the drivers that already exist for Linux: detect the hardware in a machine, identify which Linux driver handles it and in what state it is, find the packages that are needed, and — later — make installation and maintenance simpler.

It works with **existing Linux drivers**: the kernel modules, firmware and distribution packages that are already available. LMFK is not a new kernel and does not invent a new class of drivers.

> LMFK is a distinct project from the `B-Web` Rust browser engine.

## What LMFK does

Concretely, the driver manager is meant to answer everyday hardware questions:

- **You plug in a Wi-Fi card** → LMFK identifies the hardware and the Linux driver that supports it.
- **You have a GPU** → LMFK proposes a compatible driver for that chipset.
- **You connect a USB device** → LMFK looks up the kernel module and the firmware it needs.
- **A driver is missing or outdated** → LMFK gives a clear explanation of the problem and a concrete solution.

## What is planned next

- **Assisted installation** through the distribution's native package manager (no parallel package system).
- **Fewer unnecessary compilations**: prefer built-in drivers and official precompiled modules matching the exact kernel; local compilation and DKMS are last resorts, never the automatic default.
- **Driver and firmware updates**, with a clear view of what is installed and what can be improved.
- **Multi-distribution support**: the first reference backend targets **Debian 13**, but the architecture is designed to be distribution-independent and to extend to other distributions.

## What LMFK does not replace

- **No new kernel.** LMFK runs on the Linux kernel you already have.
- **No replacement for `.ko` modules.** Existing kernel modules keep working as they do today.
- **No new driver ABI.** LMFK does not define a competing binary interface for drivers.
- **No universal driver subsystem.** It does not try to replace the kernel's driver infrastructure.

## Documentation

English documentation (under [`docs/en/`](docs/en/)) — current roadmap:

- [Driver Manager Specification](docs/en/04-driver-manager-spec.md)
- [Hardware Scanner Specification](docs/en/05-hw-scanner-spec.md)
- [Inventory Schema](docs/en/06-inventory-schema.md)

Historical / experimental documentation (under `docs/en/`, preserved for reference — **not** the current roadmap):

- [Technical Specification v0.1](docs/en/00-technical-spec.md) — historical.
- [`.drv` Package Format v1](docs/en/01-drv-format.md) — historical.
- [ABI v1 Contract](docs/en/02-abi-contract.md) — historical.
- [Technical Review and Decisions](docs/en/03-review-report.md) — historical.

The active roadmap is published in **English only** (see `docs/en/` above). The files `docs/fr/00..03` are historical.

Documentation historique / expérimentale (dans `docs/fr/`, conservée pour référence — **hors** feuille de route actuelle) :

- [Cahier des charges technique v0.1](docs/fr/00-cahier-des-charges.md) — historique.
- [Format de paquet `.drv` v1](docs/fr/01-format-drv.md) — historique.
- [Contrat ABI v1](docs/fr/02-contrat-abi.md) — historique.
- [Revue technique et décisions](docs/fr/03-rapport-revue.md) — historique.

For an index of this repository, see [README.md](README.md).

## Workspace crates

The Cargo workspace still contains the library crates and command-line tools from the former project. They are **preserved, historical/experimental** code, kept intact but off the current critical path.

| Crate | Path | Status |
|---|---|---|
| `lmfk-abi` | `crates/lmfk-abi` | Historical/experimental, preserved — former ABI v1 definitions. |
| `lmfk-drv-format` | `crates/lmfk-drv-format` | Historical/experimental, preserved — former `.drv` container and CBOR manifest. |
| `lmfk-drv-parser` | `crates/lmfk-drv-parser` | Historical/experimental, preserved — former `.drv` parser/validator. |
| `lmfk-drv-crypto` | `crates/lmfk-drv-crypto` | Historical/experimental, preserved — former SHA-256/Ed25519 verification. |
| `drvinfo` | `tools/drvinfo` | Historical/experimental, preserved — `.drv` inspector. |
| `drvverify` | `tools/drvverify` | Historical/experimental, preserved — `.drv` verifier. |
| `drvpack` | `tools/drvpack` | Historical/experimental, preserved — `.drv` builder/signer. |

These crates and tools are **committed** to the repository; they are not pending review. They are retained for reference and possible reuse, not developed as part of the driver-manager roadmap.

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

The workspace targets Rust 1.85 (edition 2024).

## Current status

| Component | Status |
|---|---|
| New Linux driver manager (specifications, architecture) | Phase 0 documentation — not implemented |
| Former ABI / `.drv` / crypto crates and tools | Preserved — experimental/historical (committed) |
| Driver Manager (detection, matching, inventory, lifecycle) | Not started |
