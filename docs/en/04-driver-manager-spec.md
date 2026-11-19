# LMFK Linux Driver Manager — Technical Specification

*Status: proposed reference architecture. This document defines the strategic repositioning of LMFK and supersedes the direction of `00-technical-spec.md`, `01-drv-format.md` and `02-abi-contract.md` for the active roadmap.*

> **Positioning change.** LMFK is no longer a project to build a new kernel, a replacement for Linux kernel modules (`.ko`), or a competing universal driver ABI. LMFK is a **manager for existing Linux drivers**: it detects hardware, identifies the Linux drivers that support it, determines their current state, finds the packages that provide them, and — in later phases — simplifies their installation and maintenance.
>
> The earlier ABI / `.drv` / crypto work is **preserved but historical and experimental**. It is kept for reference and possible future use, but it is explicitly **off the critical path** and must not influence decisions in this specification.
>
> **Additional strategic ambition.** LMFK is not merely a driver installer. It must also **minimise heavy local kernel-module compilations**, such as those imposed by DKMS when a compatible precompiled alternative exists. The default path is to find and reuse an official, maintained binary driver for the exact running kernel; local compilation is a last resort, never the automatic default.

---

## 1. Purpose and user stories

### 1.1 Purpose

A Linux user with a newly installed or newly failing piece of hardware typically faces a scattered set of questions: *What device is this? Which driver should handle it? Is that driver loaded, built into the kernel, available but not loaded, or simply missing? Do I need firmware? Which package do I install?* The information needed to answer these questions exists on the system (sysfs, kernel module metadata, firmware directories) and in distribution repositories, but it is spread across many low-level commands and is hard to interpret without kernel expertise.

LMFK's purpose is to **gather that information, correlate it, and explain it in plain language**, without changing the system. The first reference distribution is **Debian 13**, but the architecture must remain **distribution-independent**: Debian is the first backend, not an assumption baked into the core.

### 1.2 User stories

- **Wi-Fi card.** A user plugs in a USB Wi-Fi adapter that is not detected. LMFK reads its USB vendor/product IDs and modalias, finds the matching `modules.alias` entry (for example `brcmfmac`), reports that the module is *available but not loaded*, lists the firmware files that module declares, and explains that two of them are missing from `/lib/firmware`.
- **GPU.** A user wonders why hardware acceleration is unavailable. LMFK identifies a PCI VGA device, shows that the `i915` module is *builtin* to the running kernel, that the driver is *bound*, and that no package action is required — distinguishing a correctly working driver from a misconfiguration.
- **USB device with firmware.** A user connects a USB device whose driver requests a firmware blob. LMFK reports that the device has two interfaces with different drivers, that the relevant module declares `rtl_nic/rtl8168e-2.fw`, and that the file is absent. It explains, in plain language, that the driver is present but cannot initialise the device without that firmware.
- **Missing or outdated driver.** A user runs LMFK after a kernel upgrade and sees that a device's module is *missing* for the current kernel release, or that a `DKMS` module was not rebuilt. LMFK reports the state honestly (`missing` / `unknown`) rather than guessing, and suggests candidate packages when — and only when — a distribution backend can justify them.

In every story the output is an explanation and a set of **suggestions**, never an automatic change.

---

## 2. What LMFK is NOT

The following are explicit non-goals. Each one is a boundary that protects the project from its earlier, much larger scope.

- **Not a new kernel.** LMFK does not build, ship, or replace a Linux kernel. It runs on the kernel the user already has.
- **Not a `.ko` replacement.** LMFK does not produce loadable kernel modules. The drivers it manages are the Linux kernel's own modules and built-in drivers.
- **Not a universal driver ABI.** LMFK does not define a new binary interface for drivers, does not compete with the kernel's internal driver interfaces, and does not revive the historical `.drv` ABI as a critical-path deliverable.
- **No automatic privileged installation in the MVP.** The initial phases are strictly read-only. LMFK never installs packages, loads modules, writes files, compiles modules, or runs privileged commands on its own. Assisted, explicitly confirmed installation is a **later phase** (phase 8), not part of the MVP.

---

## 3. Guiding rule

> **Every design decision, API, and line of code must be tested against one question:**
>
> *Does it help detect hardware, find the corresponding Linux drivers, determine their state, install them, update them, or manage them?*

If the answer is no, the decision does not belong in the active roadmap. This rule is the tie-breaker for all scope disputes. It is deliberately narrow: it keeps historical ABI, `.drv`, and cryptographic work parked, and it keeps new features aligned with the repositioned mission. A feature that is technically interesting but does not improve driver detection, discovery, installation, update, or management is out of scope.

### 3.1 Binary-first resolution strategy

LMFK must resolve a driver by **reusing the lightest compatible solution first**. The order is mandatory:

1. Drivers **already built into the running kernel**.
2. Modules **already present on disk and compatible** with the running kernel.
3. **Official precompiled binary packages** matching both the kernel and the distribution.
4. **Maintained, compatible binary alternatives** from explicitly trusted sources.
5. **Local compilation only as a last resort**, reported clearly as such and never triggered automatically.

**DKMS is never the priority simply because it can compile automatically.** If a maintained precompiled binary exists for the exact kernel, LMFK must propose that first. Local compilation is a possibility, not an obligation.

To support this strategy, the target architecture must be able to:

- detect the **exact kernel release**, architecture and relevant kernel features;
- check **module compatibility** with that kernel (metadata such as `vermagic`/build information);
- find **precompiled module packages** and identify the packages matching installed kernel versions;
- **distinguish precompiled modules from DKMS-built and locally built modules**;
- verify that **dependencies and firmware** are available before recommending a driver;
- detect when a **kernel update has made a module incompatible**;
- state clearly **when compilation would be necessary**, and **why no compatible binary solution was found**.

These capabilities are part of the target architecture; they are specified in detail by the future resolution phase (§7, phase 7) and are **not implemented in the read-only MVP**.

---

## 4. Target architecture

The architecture is a set of layered Rust crates. Dependencies flow downward: upper layers depend on lower layers; lower layers never depend on upper ones. Each crate has a single responsibility and can be tested independently.

### 4.1 Crates and responsibilities

| Crate | Responsibility |
|---|---|
| `lmfk-core` | Shared **immutable** types used across all layers: `Inventory`, `Device`, `Module`, `Firmware`, `Suggestion`, `Diagnosis`, identifier types, and error types. No I/O, no policy. This is the compatibility surface also serialized as the JSON schema (see `06-inventory-schema.md`). |
| `lmfk-hw` | Hardware discovery. Enumerates PCI, USB and device-tree devices through `/sys`, reads identifiers (vendor, device, subsystem, class, modalias) and the bound-driver link. Produces raw device records; it does **not** decide driver state or package names. |
| `lmfk-modules` | Kernel-module metadata. Parses `modules.alias(.bin)`, `modules.builtin`, `modules.dep` and reads `/proc/modules` / `lsmod`; resolves module-to-device matches and computes module states (`loaded`, `available`, `builtin`, `missing`, `unknown`) and dependency lists. |
| `lmfk-firmware` | Firmware inspection. Reads the firmware aliases declared by a module (`modinfo firmware:` or `firmware:` modalias aliases) and checks for their real presence under `/lib/firmware` and `/usr/lib/firmware`. Distinguishes *declared* from *present*. |
| `lmfk-distro` | Distribution abstraction. Defines the `PackageBackend` trait and implements read-only query backends for **Debian/APT**, **Fedora/DNF**, **Arch/pacman** and **openSUSE/Zypper**. Produces package **suggestions** with a reason and confidence; never installs. |
| `lmfk-policy` | Policy evaluation: exact kernel release/architecture/features, module ABI compatibility, header availability, Secure Boot implications, DKMS status and external/third-party modules. **Design only — not implemented in the current phases.** It defines extension points and types so later phases can add these checks without changing the data model. |
| `lmfk-resolve` (future) | Binary-first resolution. Implements the ordered strategy of §3.1: prefer built-in and precompiled modules, identify matching official packages, mark DKMS and local builds, report why no compatible binary was found, and signal local compilation only as a last resort. **Future phase 7; no implementation in the MVP.** |
| `lmfk-manager` | Orchestration. Drives the scanners, merges their outputs into a single `Inventory`, runs diagnosis rules, and keeps audit events **in memory only** for the duration of the run. It is the future home of transactional installation. It coordinates; it does not perform raw I/O itself. |
| `lmfk` CLI / TUI | User-facing interface. Renders the `Inventory` as human-readable text or JSON and, in later phases, presents suggestions and confirmation prompts. The CLI is authoritative; the TUI is an optional presentation layer. |

### 4.2 Data-flow diagram

```
                          ┌──────────────────────────────────────────────┐
                          │                 lmfk CLI / TUI                │
                          │          (render text or JSON; later:        │
                          │           confirmation prompts)              │
                          └───────────────────┬──────────────────────────┘
                                              │ reads Inventory
                                              ▼
   ┌──────────────────────────────────────────────────────────────────────────┐
   │                            lmfk-manager                                  │
   │ orchestrates scanners · merges results · diagnosis · in-memory audit │
   └───┬──────────┬──────────┬──────────┬──────────┬──────────────────────────┘
       │          │          │          │          │
       ▼          ▼          ▼          ▼          ▼          (future, design only)
  lmfk-hw    lmfk-modules  lmfk-firmware  lmfk-distro  lmfk-policy
  /sys       modules.*     /lib/firmware   pkg query    Secure Boot
  PCI/USB    /proc/modules modinfo         apt/dnf/     DKMS/headers
  DT         modinfo       /usr/lib/fw     pacman/      (extension points)
                                           zypper        lmfk-resolve (future):
                                                         binary-first selection,
                                                         DKMS/local-build signalling
       │          │          │          │
       └──────────┴──────────┴──────────┘
                          │ immutable facts
                          ▼
                  ┌──────────────────┐
                  │   lmfk-core      │  ──►  Inventory (JSON via schema v1.0)
                  │ immutable types  │
                  └──────────────────┘
```

### 4.3 The two hard separation rules

1. **The scanner only produces an immutable `Inventory`.** Discovery and inspection layers report facts. They do not install, do not load modules, do not mutate state, and do not make decisions on the user's behalf. The `Inventory` is a snapshot; once produced it is not modified.
2. **Backends only produce suggestions.** A `PackageBackend` returns candidate packages with a reason and a confidence level. It never executes an installation. The manager correlates suggestions with devices, and the user — not LMFK — decides what to do. Even in phase 8, installation requires explicit user confirmation.

These two rules keep the read-only guarantee structural rather than merely conventional.

---

## 5. Distribution backend rules

- **Trait-based abstraction.** All distribution support goes through the `PackageBackend` trait in `lmfk-distro`. The core, scanners and manager must contain **no distribution-specific logic**. Adding a new distribution means adding a new backend implementation, not editing the core.
- **No APT assumption.** Debian/APT is the first reference backend, not the default model for the others. No code may assume `apt`, `dpkg`, `.deb`, or Debian file layouts. Paths such as `/lib/firmware` are treated as configurable/observed facts, not hard-coded distro truth.
- **Heuristics are not guarantees.** `dpkg -S` and `apt search` are heuristics. They may fail to find the package that provides a module (for example, when the module is built into a meta-package, generated by DKMS, or provided under an unexpected name). A backend must never present a heuristic result as certain.
- **Honest emptiness.** A backend is allowed — and expected — to return **no suggestions** when it cannot justify one. In that case the manager emits a `PACKAGE_UNKNOWN` diagnosis with a plain-language explanation. An empty suggestion list is a valid, honest result, not an error to be hidden or filled with guesses.
- **Confidence is mandatory.** Every suggestion carries a backend, a package name, a reason, and a confidence (`high` / `medium` / `low`) so the UI can communicate uncertainty.

---

## 6. Security and installation rules

- **Read-only MVP — definitive rule.** Through phase 7 (and throughout the MVP, phases 0–6), LMFK performs **no writes of any kind**: no system writes, no journal on disk, no cache, no temporary files, no configuration changes and no privileged access. All operations are reads of files and explicitly allowlisted read-only commands. Printing diagnostics to the terminal is allowed. Exporting the inventory to a file is a **later feature that requires separate authorization** and is not part of the MVP.
- **No privileged operations.** LMFK must not require `root`, must never invoke `sudo`, and must not call privileged APIs. It runs as a normal user and reports what it cannot observe rather than escalating.
- **Official repositories only.** Suggestions must come from the system's configured official distribution repositories. LMFK must not suggest third-party PPAs, random downloads, or untrusted sources.
- **Native package manager only.** Any future installation uses the distribution's native package manager through the `PackageBackend` abstraction. LMFK never implements its own package format or installer.
- **Explicit user confirmation.** No installation, update, or removal happens without a clear, explicit, per-action confirmation from the user. There is no "just do it" default and no implicit consent carried over between actions.
- **Dependency and compatibility checks.** Before proposing any action, LMFK checks module dependencies, kernel/header compatibility and other policy constraints where available. Known policy gaps (Secure Boot, DKMS) must be reported as such rather than silently ignored.
- **Secure Boot state.** The state must be read from a reliable system source when one is available; otherwise LMFK returns `unknown`. LMFK must **never infer** a Secure Boot state from indirect signals or assume one.
- **Audit events (in memory only).** Every significant action and every suggestion accepted or rejected is recorded as an **in-memory audit event** for the duration of the run and may be printed to the terminal. No audit log is written to disk, no cache is created and no temporary file is used during the MVP. A persistent export requires separate authorization.
- **Rollback strategy — later phases.** Every future mutating operation must be designed to be reversible: record the previous state, prefer package-manager transactions, and define a rollback path before the operation is enabled. No mutating feature ships without a tested rollback plan.
- **Forbidden: arbitrary `.ko` downloads.** LMFK must **never** download, fetch, or install arbitrary `.ko` files from the network or from untrusted locations. Kernel modules may only be obtained through the distribution's native package manager from official repositories. Downloads of loose module binaries are explicitly and permanently forbidden.

---

## 7. Development phases

Phases are sequential in intent but **independently testable** in execution: each phase has its own fixtures, tests and exit criterion, and must be shippable without depending on the implementation of later phases. A phase may be slowed or paused without blocking validation of what came before.

| Phase | Name | Scope | Concrete exit criterion |
|---|---|---|---|
| 0 | Documentation | This spec, `05-hw-scanner-spec.md`, `06-inventory-schema.md`; freeze schema v1.0. | All three documents reviewed and accepted; 06 provides a **reproducible validation procedure**, **one valid example** and **a set of invalid examples** with the expected rejection reason. No crate or scanner code is required. |
| 1 | Discovery | `lmfk-core` types + `lmfk-hw` PCI/USB/DT enumeration from `/sys`; text and JSON output of an `Inventory`. | Against the reference PCI and USB fixtures defined in `05-hw-scanner-spec.md` §8 (expected IDs, modalias and parent/interface structure), `lmfk scan` reproduces every expected value exactly; on the Debian 13 host its JSON validates against schema v1.0 — with zero writes. |
| 2 | Modules | `lmfk-modules`: `modules.alias(.bin)`, `modules.builtin`, `modules.dep`, `/proc/modules`, state and dependency resolution. | For a fixture set with known `loaded`, `available`, `builtin`, `missing` and `unknown` cases, each module is assigned the correct state and `match_source`, and dependency chains resolve; a synthetic missing-module case is detected. |
| 3 | Firmware | `lmfk-firmware`: declared aliases vs files on disk; `FIRMWARE_MISSING` diagnosis. | A module declaring two firmware files where one exists and one does not produces exactly one `FIRMWARE_MISSING` diagnosis with `present=true` for the existing file and `present=false` for the missing one. |
| 4 | Backends | `lmfk-distro` trait + Debian/APT, Fedora/DNF, Arch/pacman, openSUSE/Zypper read-only backends. | Each backend returns suggestions with reason and confidence from synthetic package-query fixtures; a no-result case yields `PACKAGE_UNKNOWN`; no backend writes or invokes anything outside its read-only allowlist. |
| 5 | Diagnostics | `lmfk-manager` orchestration, diagnosis rules, in-memory audit events; plain-language explanations from the diagnostic catalogue in `06-inventory-schema.md` §12.2. | A combined fixture (missing module + missing firmware + unbound driver + unknown package) yields exactly the expected codes and severities; every emitted diagnosis passes the acceptance checklist in §7.1; audit events exist in memory and appear on the terminal, and no file is written. |
| 6 | UX | CLI polish, stable output contract, optional TUI, documentation of commands. | A non-expert tester answers all four questions of the acceptance checklist in §7.1 for a Wi-Fi, GPU and USB device from text output alone; CLI JSON output remains schema-valid; TUI (if present) uses the same `Inventory`. Still read-only, with terminal output only. |
| 7 | Binary resolution | `lmfk-resolve` + `lmfk-policy`: apply the §3.1 strategy; detect exact kernel/ABI compatibility, precompiled vs DKMS vs local builds, dependency/firmware availability and kernel-update breakage. Still **read-only**: it selects and explains, it never compiles or installs. | Given fixtures for (a) a built-in driver, (b) a compatible precompiled package, (c) a DKMS-only path and (d) an incompatible kernel update, the resolver returns the expected ordered choice, names the matched package where one exists, and explains in plain language why a binary solution was or was not found; no compilation or write occurs. |
| 8 | Assisted installation | Explicitly confirmed, transactional install/update through backends, with rollback and in-memory audit events. Any last-resort local build requires separate explicit confirmation. | In an isolated test environment, a confirmed install runs through the native package manager, is fully audited in memory, is rejected without confirmation, and is successfully rolled back on simulated failure. No arbitrary `.ko` download path exists in the code. |

### 7.1 Acceptance checklist for beginner-facing output

A diagnosis or status message is accepted only when a tester without kernel expertise can answer **yes** to all four questions:

1. **Clarity** — Is the problem stated in plain language, without kernel jargon or raw identifiers as the only explanation?
2. **Explanation** — Does it say what LMFK observed and why this is a problem?
3. **Consequences** — Does it say what currently does not work (or may not work) because of it?
4. **Advised action** — Does it state one concrete next step, clearly marked as a suggestion that the user must perform or confirm? LMFK must never perform that action automatically.

This checklist is the objective replacement for the subjective phrase "readable by a non-expert". It applies to every entry of the diagnostic catalogue defined in `06-inventory-schema.md` §12.2.

Phases 7 and 8 are explicitly outside the MVP. Phases 0–7 are read-only (phase 7 selects and explains but never compiles or installs); phase 8 is the first mutating phase. Phases 0–6 must remain fully functional on their own.

---

## 8. Decisions taken and open questions

### 8.1 Decisions taken

- LMFK is a **manager of existing Linux drivers**, not a kernel, module format, or ABI project.
- The repository **keeps the name LMFK**; all historical crates and tools **stay in place**, none are moved or deleted.
- The ABI / `.drv` / crypto work is **historical, preserved, experimental, and off the critical path**.
- The first reference distribution is **Debian 13**, but the design is **distribution-independent** via the `PackageBackend` trait and an open string for `suggestion.backend`.
- The MVP is **strictly read-only**: no writes, no disk journal, no cache, no temporary files, no configuration changes, no privileged access, and no file export without separate authorization. Audit events stay in memory; terminal output is allowed.
- **Binary first:** reuse built-in and precompiled compatible drivers before any local build; DKMS is not the default and local compilation is a last resort requiring explicit confirmation.
- No `modprobe` invocation at all during the MVP, including `--show-depends`; module metadata is read directly.
- Secure Boot state is read from a reliable system source when available, otherwise `unknown`; it is never inferred.
- Diagnostics must be understandable by beginners; the stable catalogue and acceptance checklist are defined in `06-inventory-schema.md` §12.2 and `04` §7.1.
- Development is **CLI-first**; a TUI, if added, is an optional presentation layer over the same `Inventory`.
- The active roadmap is **English-only**; the French `00`–`03` documents are historical.
- The `Inventory` and its distro-independent JSON schema (v1.0) are the central, immutable contract between layers.
- Scanner produces facts; backends produce suggestions; the user decides.

### 8.2 Open questions to arbitrate

1. **Localization of messages.** The catalogue defines stable codes and beginner-friendly English text; translated phrasing is not specified and would require a separate decision.
2. **TUI timing.** A TUI is optional and deferred; the decision whether to build it in phase 6 or later remains open. CLI-first is already decided.

---

Companion documents: `05-hw-scanner-spec.md`, `06-inventory-schema.md`.
