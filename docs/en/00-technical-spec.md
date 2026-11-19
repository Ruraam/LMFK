> **HISTORICAL / EXPERIMENTAL DOCUMENT** — describes the former hybrid-kernel/stable-ABI project. LMFK is now a Linux driver manager for EXISTING Linux drivers; see [docs/en/04-driver-manager-spec.md](04-driver-manager-spec.md). Preserved for reference, not the current roadmap.

---

# LMFK — Technical Specification v0.1

*Working document. Decisions already arbitrated according to the initial recommendation: **hybrid kernel**, retained Linux base, independent Driver Framework, progressive Linux compatibility.*

> This document is intentionally kept separate from the `B-Web` repository (Rust browser engine). LMFK is a distinct project.

---

## 0. Scope and non-goals

| | |
|---|---|
| **Scope** | Define a stable driver boundary (ABI), independent of kernel version, above a reduced Linux kernel. |
| **v1 non-goal** | Rewrite Linux. Universally replace kernel drivers with userspace drivers. Support GPU/DRM from the outset. |
| **Guiding principle** | We do not freeze the kernel internals, we freeze the **public interface** to drivers. This is the only way to keep freedom of internal evolution. |

⚠️ Fundamental clarification: the described architecture is very close to **Fuchsia** (FIDL/banjo, `driver_host`, userspace drivers) and to **seL4 / MINIX 3** for isolation. LMFK's specific contribution would be to graft this architecture onto a Linux foundation. This is useful, but it must be stated clearly: the innovation lies in the **integration**, not in the pure concept.

## 1. Measurable objectives

1. **Version independence**: a `.drv` compiled for `ABI 1.x` loads on any `1.y` kernel without recompilation, verified by a CI matrix `ABI × kernel versions`.
2. **Update without rebuild**: install or update a userspace driver without rebuilding or rebooting the kernel.
3. **Real isolation**: a crash or memory fault in a userspace driver must not bring down the system (fault injection tests).
4. **Chain of trust**: 100% of `.drv` loaded in production are signed and verified; refusal in Secure Boot mode.
5. **Progressive coverage**: at phase 5, at least 20 common Linux drivers (PCI/USB/network/audio) functional via the compatibility layer.

## 2. Target architecture

```
RING 0  ── Kernel Core ──────────────────────────────────────────
│  Scheduler · Memory · Processes · IPC · VFS · Networking · Security
│  Driver Core (kernel, minimal): buses, IRQ, IOMMU, ABI shims, registry
└──────────────────────────┬──────────────────────────────────────
          IPC / handles / capabilities (stable boundary)
RING 3  ── Driver Framework ─────────────────────────────────────
│  driver-manager: detection, matching, dependencies, policy, update
│  driver-host/userspace: 1 process per driver, IOMMU + eventfd-like
│  driver-host/isolated: WASM/eBPF or CSpace capability, fine-grained permissions
├─────────────────────────────────────────────────────────────────
│  Applications: Linux system ABI retained (no change)
└─────────────────────────────────────────────────────────────────
RING 3  ── Hardware: CPU · GPU · USB · PCIe · Audio · Wi-Fi · Storage
```

**Driver placement rule:** by default *userspace*; *isolated* if the driver is third-party or untrusted; *kernel* only if the hardware is on the critical path before userspace hosts exist (interrupt controller, IOMMU, clock, early console, boot storage).

## 3. The stable ABI — the heart of the project

### 3.1 Design rules (non-negotiable)

- **Opaque handles**: no kernel internal structure crosses the boundary. An opaque `uint64_t`, never a pointer. This is what allows changing the internal implementation without breaking drivers.
- **Function tables (vtable)** passed at entry, never imported symbols. The driver links only against the ABI, not against the kernel.
- **Fixed-width types** (`uint32_t`, `uint64_t`), explicit size at the head of each structure (`uint32_t size`), fields added only **at the end**.
- **Versioning `major << 16 | minor`**. Adding a function = minor bump. Semantic change = major bump. The framework embeds several major ABI shims in parallel (just as Linux keeps 32-bit compatibility).
- **Stable error codes** (`errno`-style enum), never an ambiguous `-1`.
- **Prohibitions**: raw pointer to kernel memory, synchronous call in an arbitrary IRQ context, dependence on compiler memory layout, call to libc.
- **Callbacks**: executed on the driver's thread or executor with a `drv_handle_t ctx`, never in an arbitrary kernel context.

### 3.2 ABI surface (excerpt)

The initial example `int (*allocate_memory)(size_t size)` is the classic trap: an **output handle** is needed, not an `int`. Corrected version:

```c
typedef uint64_t drv_handle_t;  /* opaque: never a kernel pointer */

typedef struct {
    uint32_t size;              /* sizeof(lmfk_driver_api_t) */
    uint32_t abi_version;       /* 0x00010000 = 1.0 */
    int (*log)(drv_handle_t ctx, uint32_t level, const char *msg, uint32_t len);
    int (*mem_alloc)(drv_handle_t ctx, uint64_t size, uint64_t align, drv_handle_t *out);
    int (*mem_free)(drv_handle_t h);
    int (*mmio_map)(drv_handle_t dev, uint32_t bar, drv_handle_t *out_vaddr, uint64_t *out_len);
    int (*irq_register)(drv_handle_t dev, uint32_t index, uint32_t flags, drv_handle_t *out_event);
    int (*irq_ack)(drv_handle_t dev, uint32_t irq_index);
    int (*dma_alloc)(drv_handle_t dev, uint64_t size, uint64_t *out_iova, drv_handle_t *out_cpu);
    int (*ipc_open)(drv_handle_t ctx, const char *name, drv_handle_t *out_chan);
    int (*device_register)(drv_handle_t ctx, const drv_device_desc_t *desc, drv_handle_t *out);
} lmfk_driver_api_t;             /* provided by the framework */

typedef struct {
    uint32_t size;
    int  (*init)(const lmfk_driver_api_t *api, drv_handle_t ctx,
                 const uint8_t *config, uint32_t config_len);
    int  (*probe)(drv_handle_t ctx, const drv_device_desc_t *dev, drv_handle_t *out);
    int  (*start)(drv_handle_t device);
    int  (*irq)(drv_handle_t device, uint32_t irq_index);
    int  (*suspend)(drv_handle_t device);
    int  (*resume)(drv_handle_t device);
    int  (*stop)(drv_handle_t device);
    int  (*remove)(drv_handle_t device);
    void (*shutdown)(drv_handle_t ctx);
} lmfk_driver_entry_t;           /* provided by the driver */
```

### 3.3 Compatibility rules

- Minor ABI: any `1.0` driver runs on a `1.7` framework; new functions are detected via `size`.
- Major ABI: a `1.x` driver is loaded via the `v1` shim; multiple shims coexist.
- Deprecation: two versions of warning before removal at the next major.
- A `.drv` file declares a **range** `abi_min..abi_max`, not a single version.

## 4. The `.drv` format

### 4.1 Header (all little-endian)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Magic `LMFKDRV\0` |
| 8 | 2 | `format_version` = 1 |
| 10 | 2 | `header_size` |
| 12 | 4 | `flags` (signed, compressed, PIE, …) |
| 16 | 4 | `abi_min` (u16) / `abi_max` (u16) |
| 20 | 4 | arch (1 = x86_64, 2 = aarch64, 3 = armv7, 4 = riscv64) |
| 24 | 4 | `section_count` |
| 28 | … | section table (name, type, offset, size, align, SHA-256) |

**Sections**: `.text`, `.rodata`, `.data`, `.bss` (size only), `.reloc` (PIE relocations), `.manifest` (CBOR), `.resources`, `.signature`.

**Loading constraint**: position-independent code, no external symbol except the vtable received at entry. The framework applies relocations, then transfers control to `lmfk_driver_entry`.

### 4.2 Manifest (example)

```toml
[driver]
name = "intel-gpu"
version = "1.4.2"
abi = { min = "1.0", max = "1.x" }
arch = ["x86_64"]
mode = "userspace"          # kernel | userspace | isolated
license = "MIT OR Apache-2.0"
entry = "lmfk_driver_entry"

[match]
pci = [{ vendor = "0x8086", device = "0x9bc4", class = "0x030000" }]
acpi = ["PNP0A06"]

[capabilities]
request = ["dma:64", "irq:msi", "mmio:bar0", "ipc:display", "io:pcie_cfg"]

[dependencies]
drivers = ["pci-manager >= 1.2"]
```

### 4.3 Signature

Ed25519 over the (Merkle) digest of the manifest and sections, chained to a platform key anchored in Secure Boot. Revocation list distributed with the kernel. In production, any unsigned `.drv` is refused.

**Tools**: `drvpack`, `drvinfo`, `drvverify`, `drvsign`, `drvstrip`.

## 5. Driver Manager

**Responsibilities**: discovery (`/System/Drivers`), reading manifests, PCI/USB/ACPI/Device Tree matching, dependency resolution (topological sort), priority arbitration, application of capability policy, hotplug, lifecycle, rollback, audit log.

**Lifecycle**: `DISCOVERED → VERIFIED → MATCHED → LOADED → PROBED → STARTED → (SUSPENDED) → STOPPED → REMOVED → UNLOADED`. Every transition is audited and reversible where possible.

**IPC interface**: `Register`, `Query`, `Load`, `Unload`, `Enable`, `Disable`, `Update`, `ListDevices`. Access via a service socket and a capability token — no direct access to the registry.

**CLI**: `lmfk-drv list|info|verify|install|enable|disable|update|rollback`.

## 6. Security

| Threat | Mitigation |
|---|---|
| Buggy or malicious driver | Separate process, IOMMU, minimal capabilities, WASM/eBPF sandbox for third-party drivers |
| Hostile DMA | Per-domain IOMMU, `dma_alloc` via IOVA, no raw physical access |
| Supply chain | Ed25519 signature, Secure Boot, revocation, reproducible builds |
| Confused deputy | The manager passes only handles, never implicit rights |
| Escalation via interrupt | IRQs routed as events, explicit acknowledgement, bounded queues |

**Capability model**: `mmio:barN`, `irq:index`, `dma:width`, `io:bus`, `ipc:name`, `clock`, `power`. A driver receives only what its manifest requests **and** what policy allows.

## 7. Linux compatibility — the riskiest decision

| Approach | Advantage | Cost | Verdict |
|---|---|---|---|
| Static integration of drivers into the kernel | Simple, immediate | Recouples to version, no more independent updates | **Stopgap phases 1–2** |
| Compatibility layer (Linux API shim → LMFK ABI) | Reuses the ecosystem | Very heavy: `device`, `pci`, workqueues, alloc, locks, DRM… must follow upstream | **Phase 5, targeted** |
| Full Linux runtime in userspace | Strong isolation | Heavy, close to UML, performance | To be studied, not in v1 |
| Native `.drv` drivers | Clean, independent | Everything to write | **Long-term goal** |

**Limits to acknowledge**: userspace drivers do not universally replace the kernel (IRQ, DMA, latency, GPU). Start with simple PCI/USB/network/audio; exclude DRM/GPU and boot storage from phase 5.

**⚖️ Legal**: reusing Linux driver code (GPLv2) imposes licensing obligations on derived `.drv` and potentially on the framework. To be decided with legal counsel before announcing an "independent" project. This is a real risk, not a detail.

## 8. Build and tooling

- **Rust** for new components (manager, hosts, tools, ABI bindings), **C** for the retained kernel and shims.
- Typical workspace: `lmfk-abi`, `lmfk-drv-format`, `lmfk-manager`, `lmfk-host`, `lmfk-compat`, `lmfk-sdk`, `lmfk-tools`.
- Targets: `x86_64`, `aarch64`, `armv7` (riscv64 as a stretch).
- Reproducible builds, toolchain pins, SBOM per `.drv`.
- Tests: `ABI × kernel` CI, multi-arch QEMU, fault injection, `.drv` parser fuzzing, negative signature verification.

## 9. Updates

Signed `.drv` packages, present in a signed repository. Atomic update of the manifest and sections, with automatic rollback if the driver fails `probe` or `start`. Kernel in A/B with `kexec` for major ABI changes. Userspace drivers update hot; kernel drivers require a reboot.

## 10. Roadmap

| Phase | Deliverable | Exit criterion |
|---|---|---|
| 1 — Kernel Core | Reduced Linux, defined boundary | Bootable kernel, ABI frozen in spec |
| 2 — Driver Framework | ABI v1, shims, registry | Test `.drv` loaded on two kernel versions |
| 3 — Driver Manager | Detection, matching, lifecycle | Functional USB hotplug |
| 4 — Driver Runtime | Userspace hosts and isolation | Injected crash = driver restarted, kernel intact |
| 5 — Linux Compatibility | Targeted PCI/USB/network shim | 20 common drivers functional |
| 6 — Native Drivers | Native `.drv` ecosystem | First drivers written directly against the ABI |

## 11. Major risks

1. **The frozen ABI trap**: freezing an interface can freeze the implementation if the shim becomes a thick layer. Mitigation: keep the shim thin and accept that only certain operations are in ABI v1.
2. **Endless compatibility layer**: following Linux internal APIs is a permanent job. Mitigation: limit it to an explicit, documented subset.
3. **Fork maintenance cost**: divergence from upstream. Mitigation: stay as close as possible to an LTS, contribute upstream.
4. **IPC/DMA performance**: overhead for networking and GPU. Mitigation: shared fast paths, ring buffers, measurements from phase 4.
5. **Double talk**: "independent" but dependent on Linux code. Mitigation: clarify licensing and positioning from the outset.

## 12. Decisions still to be made

1. **Kernel type**: hybrid (recommended) / microkernel / deep fork. → *recommendation: hybrid.*
2. **Hardware compatibility**: Linux + native / native only / all Linux. → *recommendation: Linux first, native progressively.*
3. **Initial hardware scope**: which three to five devices for the prototype? (e.g., an Intel network card, an xHCI USB controller, an audio codec).
4. **Project license** and strategy regarding GPLv2.
5. **Sandbox architecture**: WASM/eBPF or seL4-style capability CSpace.

---

*Suggested next step: freeze ABI v1 and the `.drv` format before any kernel modification. This is the only genuinely new part and it determines everything else.*
