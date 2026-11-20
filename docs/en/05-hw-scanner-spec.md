# LMFK Hardware & Driver Scanner — Specification

*Status: phased specification. Sections 1–2 define the Phase 1 scanner boundary. Later sections describe future capabilities and must not be interpreted as Phase 1 acceptance criteria.*

> The scanner's only product is an immutable `Inventory` as defined by `06-inventory-schema.md`. It never changes the system.

---

## 1. Scope

### Phase 1 — hardware discovery (implemented milestone)

Phase 1 is strictly read-only and is limited to hardware discovery:

- enumerate **PCI**, **USB** (devices and interfaces), and **Device Tree** nodes exposed by sysfs;
- collect the identifiers and properties actually exposed by each bus, including PCI/USB IDs, Device Tree `compatible` strings, class codes, and modalias values where present;
- record the currently bound driver through existing sysfs driver links, without loading, unloading, binding, or probing modules;
- preserve partial results and report enumeration, access, and malformed-data errors;
- produce the versioned inventory as text or JSON on stdout.

A missing optional sysfs property is not itself an error. A present but malformed property must be reported. Every source actually consulted by the scanner must be represented in `scan.sources`.

### Explicitly deferred to later phases

The following are **not Phase 1 acceptance criteria** and must not be implemented as part of the hardware scanner milestone:

- module matching and module-state resolution — Phase 2;
- firmware declaration and presence analysis — Phase 3;
- distribution package backends and package suggestions — Phase 4 and later;
- expanded diagnostics — Phase 5;
- complete CLI workflows — Phase 6;
- binary-first resolution — Phase 7;
- installation or any other mutating operation — Phase 8.

The Phase 1 inventory keeps the schema's future-facing fields present but empty when their corresponding phase has not run. In particular, an empty `modules`, `firmwares`, or `package_suggestions` array is not evidence that a driver or firmware is missing. `PACKAGE_UNKNOWN` only records that no package lookup was performed.

---

## 2. Out of scope

The scanner must never:

- **write** to any file, directory, sysfs attribute, or configuration;
- **install**, update or remove packages;
- invoke **`modprobe` at all**, including read-looking variants such as `--show-depends`; module metadata must be read directly from kernel-provided files instead; or perform any other operation with side effects (module loading, unbinding, re-binding, resetting devices);
- access the **network**;
- build or run **DKMS** modules or any compilation step;
- do **kernel/ABI work**, define a new driver ABI, or revive the historical `.drv` format; or
- run **privileged commands**, use `sudo`, or require `root`.

If a desired fact can only be obtained by an out-of-scope operation, the scanner reports it as `unknown` with an explanatory diagnosis rather than performing the operation.

---

## 3. Data sources

All data comes from the following sources. Network access and writes are excluded by construction.

| Source | Purpose | Access |
|---|---|---|
| `/sys/bus/pci/devices` | Enumerate PCI devices; read IDs, class, modalias, driver link, parent. | `read_dir` / `read` |
| `/sys/bus/usb/devices` | Enumerate USB devices **and interfaces**; read IDs, class, modalias, driver link. | `read_dir` / `read` |
| `/sys/class` | Cross-check device classes and friendly names for network, graphics, audio, storage. | `read_dir` / `read` |
| `/sys/firmware/devicetree/base` | Phase 1 Device Tree node enumeration and `compatible` properties. | `read_dir` / `read` |
| `/proc/modules` or `lsmod` | Future Phase 2 module-state inspection; not read in Phase 1. | `read` / allowlisted read-only command |
| `/lib/modules/<release>/modules.alias(.bin)` | Future Phase 2 module matching; not read in Phase 1. | `read` |
| `/lib/modules/<release>/modules.builtin` | Identify modules built into the running kernel. | `read` |
| `/lib/modules/<release>/modules.dep` | Resolve module dependency lists. | `read` |
| `modinfo` | Read module metadata: `firmware:` entries, build/compatibility information such as `vermagic`, and signature information (read-only, fixed arguments). | allowlisted read-only command |
| `uname -r`, `uname -m` | Record the exact kernel release and machine architecture used for compatibility checks. | allowlisted read-only commands |
| `/proc/config.gz`, `/boot/config-<release>` | Future-phase kernel configuration inspection. | `read` |
| `/proc/sys/kernel/osrelease`, `/proc/version` | Phase 1 host kernel release and version metadata. | `read` |
| `/lib/firmware`, `/usr/lib/firmware` | Future-phase firmware presence checks. | `read_dir` / `read` (existence) |
| `/etc/os-release` | Identify distribution ID and version for host metadata. | `read` |
| `/sys/firmware/efi/efivars/SecureBoot-*` | Read the Secure Boot state when the firmware exposes it. If absent or unreadable, report `unknown`; never infer a state. | `read` |
| Package-manager query commands | Read-only package lookups per backend (see `04-driver-manager-spec.md` §5). | allowlisted read-only commands only |

`<release>` is the running kernel release (`uname -r`), obtained through an allowlisted read-only command or an equivalent kernel-provided file. Every source actually consulted is recorded in `scan.sources`.

---

## 4. Mandatory technical distinctions

These distinctions are the core of the scanner's correctness. A scanner that conflates any of them produces misleading inventories and must be corrected.

### 4.1 A USB DEVICE is not its INTERFACES

A USB physical device is **not** the same entity as its interfaces. Enumerate `/sys/bus/usb/devices`; each device may have **1..n interface children**, each with its **own modalias** and its **own bound driver**. Therefore:

- represent the **USB device** and each **USB interface** as separate records at separate levels;
- each interface carries its own `id`, `interface_number`, `class`, `modalias` and `driver` state;
- a device's interfaces are listed in `device.interfaces`, keyed to `device_id`;
- never assign an interface's driver to the parent device, or vice versa.

### 4.2 Module identification comes from modalias + kernel metadata

A module is identified by matching the device's **modalias** against kernel metadata — `modules.alias(.bin)`, `modules.builtin` and the sysfs `driver` link — **not by guessing names** from the vendor, device name or class. Name heuristics are not an acceptable substitute; if metadata cannot resolve a module, the state is `unknown`, never a guessed driver name.

### 4.3 The four module states (plus unknown)

The scanner must distinguish:

- **loaded** — present in `/proc/modules` / `lsmod`;
- **available** — present in the module metadata for the running release but not loaded;
- **builtin** — compiled into the kernel (`modules.builtin`);
- **missing** — required by metadata/modalias but not found in the current kernel's modules;
- **unknown** — not determinable from available data.

Collapsing these into "has driver / no driver" loses essential information and is forbidden.

### 4.4 Declared firmware vs firmware actually present

Firmware **declared** by a module (via `modinfo firmware:` or `firmware:` modalias aliases) is distinct from firmware **actually present** on disk. Each firmware record carries `alias`, `present` and `paths`. A module can be correctly installed while its firmware is missing; this must be reported as `FIRMWARE_MISSING`, not as a missing module.

### 4.5 Module↔device matching ≠ module↔package mapping

Matching a module to a device (modalias → module, via kernel metadata) is **not** the same as mapping a module to a package (module → package, via distribution queries). They are separate steps with separate confidence and separate failure modes. Never conflate them: a device can have a well-identified module and still have `PACKAGE_UNKNOWN`.

### 4.6 `dpkg -S` / `APT search` are heuristics

`dpkg -S` and `apt search` (and their equivalents for other distributions) are **heuristics**. They may fail to find the package that provides a module — for example for generated DKMS modules, meta-packages, or unusual layouts. When they cannot justify a suggestion, the scanner **reports `PACKAGE_UNKNOWN` honestly**; it must not fabricate a package name to fill the gap.

### 4.7 DKMS, external modules and Secure Boot are future concerns

`DKMS` and third-party/external modules are **extension points only**. Their types and hooks belong in `lmfk-policy` design, but the scanner does not implement or evaluate them in the current phases. Where they affect a result, the scanner records a clear limitation rather than pretending to have checked them.

For **Secure Boot**, the scanner reads a reliable system source if one is available (for example the EFI variable listed in §3) and reports `enabled` or `disabled` accordingly. If no reliable source is available or readable, it reports `unknown`. It must **never infer** a Secure Boot state from indirect signals, kernel configuration strings or the presence of signed modules.

### 4.8 Binary-first resolution is a future concern

The scanner records the **facts** needed for binary-first resolution — exact kernel release, architecture, relevant kernel features and module compatibility metadata — but it does **not** perform resolution. Selecting built-in or precompiled drivers, distinguishing DKMS/local builds, finding matching binary packages, detecting kernel-update breakage and signalling last-resort compilation belong to the future `lmfk-resolve` component described in `04-driver-manager-spec.md` §3.1 and §7 (phase 7). The scanner never compiles anything and must not present DKMS as a preferred solution.

---

## 5. Read-only guarantee

The scanner's I/O is constrained structurally:

- **Only** `fs::read`, `fs::read_dir` and equivalent read operations are permitted for filesystem access.
- External information may be obtained **only** through an **explicit allowlist of read-only commands with fixed arguments** (for example `modinfo <module>`, `uname -r`, and the package-query commands defined per backend).
- **No shell** interpretation is allowed: commands are executed directly with argument vectors, not through `sh -c` or string interpolation.
- Every allowlisted command has a **timeout** so a hung command cannot block a scan indefinitely.
- **No `sudo`**, no privilege escalation, no setuid helpers, no privileged APIs.
- **No writes anywhere** — not to sysfs, not to configuration, not to a journal or log on disk, not to a cache, not to temporary files.
- **Audit events stay in memory** for the duration of the run. They may be displayed on the terminal; they are never persisted.
- **Terminal output is allowed.** Exporting the inventory to a file is a **later feature that requires separate authorization** and is outside this MVP.

A read-only assertion (see §8) verifies that a scan does not modify the filesystem or device state and creates no file of any kind.

---

## 6. Error handling

Hardware inspection is inherently partial: files disappear, permissions differ, formats vary. The scanner must be **resilient** and always produce a best-effort inventory.

- **Missing files** (e.g. no `modules.alias`, no firmware directory) → record an error entry and continue with reduced information.
- **Permission denied** → record an error with the source and a plain message; mark affected data `unknown`.
- **Malformed modalias** → skip the bad value, record an error, continue with other devices.
- **Symlink loops** in `/sys` → detect and avoid following cycles; record an error rather than hanging.
- **Huge files** → impose size limits with a clear error when exceeded, to avoid memory exhaustion.
- **Partial results** → always return an `Inventory`, with per-source error entries in `scan.errors` and affected fields set to `unknown` or empty as appropriate. A scan fails loudly in its error list, never silently and never by panicking.

Diagnostics derived from missing information must be phrased as uncertainty (`unknown`, `cannot determine`), not as a definite problem.

---

## 7. Output

The scanner produces an `Inventory` that can be rendered in two forms:

- **Human-readable text** — grouped by device, with plain-language state and diagnosis, intended for end users.
- **JSON** — the machine-readable contract defined in `06-inventory-schema.md` (schema version `1.0`).

Both forms are derived from the **same immutable `Inventory`**, so they cannot disagree. The JSON is an **output-only** artifact in phase 0: no writer/ingestion implementation exists yet.

---

## 8. Test strategy

- **Synthetic sysfs fixtures.** Build fake `/sys` trees representing PCI devices, USB devices with one or two interfaces, device-tree nodes, and edge cases (malformed modalias, symlink loops). Tests read from the fixture root, never the host.
- **Fake command runner.** Inject a command runner that returns canned outputs for `modinfo`, `uname -r` and package queries, so tests are deterministic and never execute real processes.
- **Negative cases.** Missing files, permission errors, malformed modaliases, oversized files and unknown packages must all yield a valid inventory with appropriate errors/diagnoses and no panic.
- **Read-only assertions.** After a scan over a fixture, assert byte-for-byte that no file was created, modified or deleted and that no side-effecting command was invoked; assert that every executed command was on the allowlist with exactly the expected fixed arguments.
- **Golden inventory on Debian 13.** On the reference distribution, capture a golden JSON inventory for a known machine and compare subsequent runs against it (accounting for legitimate fields such as `generated_at`). This locks the observable behaviour of the scanner.
- **Forbidden command assertion.** Explicitly assert that `modprobe` is never invoked, including `--show-depends`; all module facts must come from the kernel metadata files listed in §3.
- **Schema validation tests.** Run the reproducible validator from `06-inventory-schema.md` §14 against the valid example and against every invalid example; each invalid example must be rejected with its documented reason.

### 8.1 Reference fixtures and expected values

Phase 1 is accepted against these fixed fixtures, not against a vague notion of "correct IDs". The fixture tree is synthetic and lives under `tests/fixtures/`.

| Fixture | Expected `id` | Expected modalias | Expected structure |
|---|---|---|---|
| PCI VGA | `pci:0000:00:02.0` | `pci:v00008086d00009BC4sv00008086sd00000000bc03sc00i00` | One device, no interfaces, `parent: null` |
| PCI network | `pci:0000:03:00.0` | `pci:v00008086d0000157Bsv00008086sd00000000bc02sc00i00` | One device, `class.code` `0x020000` |
| USB composite device | `usb:1-4` | `usb:v0BDAp8812d0000dc00dsc00dp00ic00isc00if00` | Two interfaces: `usb:1-4:1.0` and `usb:1-4:1.1`, each with its own modalias and driver state |
| USB single-interface | `usb:1-2` | `usb:v046Dp0825d0000dc00dsc00dp00ic03isc01if02` | One interface, `usb:1-2:1.0` |

Each fixture also declares the expected bound driver, module state and firmware presence so the test can compare the produced `Inventory` field by field.

---

Companion documents: `04-driver-manager-spec.md`, `06-inventory-schema.md`.
