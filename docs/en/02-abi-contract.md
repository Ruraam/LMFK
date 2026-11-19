# LMFK — ABI v1 Contract

*Normative document. This page defines the stable boundary between the framework and its drivers. It deliberately distinguishes two boundaries that must not be confused: an in-process native ABI and a pointer-free IPC wire protocol. The reference implementation lives in `crates/lmfk-abi` and `include/lmfk/abi.h`.*

The guiding principle is unchanged from the technical specification: we do not freeze the kernel internals, we freeze the **public interface** exposed to drivers.

## 1. The two boundaries

| | Native ABI | IPC wire protocol |
|---|---|---|
| Audience | In-process drivers sharing an address space with the framework | Isolated userspace drivers (separate address space / process) |
| Representation | Function-pointer vtables: `lmfk_driver_api_t` (framework → driver) and `lmfk_driver_entry_t` (driver → framework) | Byte frames with a fixed **32-byte, pointer-free, little-endian** header (`IpcMessageHeader`) |
| Reference | `crates/lmfk-abi/src/api.rs`, `include/lmfk/abi.h` | `crates/lmfk-abi/src/ipc.rs` |
| Portability | Size depends on the target pointer width (profile) | Identical on every architecture; a 32-bit host and a 64-bit host exchange the same bytes |
| Addresses | Local pointers appear only inside the vtables and are never serialized | No pointers, no function pointers; handles remain opaque `u64` tokens and buffers follow the header as length-prefixed byte arrays |

The two boundaries are separate contracts. A driver using the native ABI is never required to be wire-compatible, and an IPC driver never exposes a native vtable. Confusing them is the main source of past layout mistakes.

The IPC header carries `magic`, `version`, `opcode`, `request_id`, `handle_count`, `payload_len`, `flags` and `reserved`. `from_bytes` validates magic and version, `to_bytes` always emits exactly 32 little-endian bytes, and `frame_len` computes the total frame length with checked arithmetic (`handle_count * 8 + payload_len + 32`).

## 2. Profiles and data layout

Function pointers are **not fixed-width**: they are 4 bytes on a 32-bit target and 8 bytes on a 64-bit target. Consequently, any structure that contains them is **not universal** unless a profile mechanism is supplied. The native vtables are profile-dependent; data-only structures are not.

| Profile | Targets | Pointer | Native `DriverApi` | Native `DriverEntry` | Alignment |
|---|---|---|---|---|---|
| LP64 | x86_64, aarch64 | 8 bytes | 96 bytes | 80 bytes | 8 |
| ILP32 | armv7 | 4 bytes | 52 bytes | 44 bytes | 4 |

The size formulas are `8 + 11 * pointer` for `DriverApi` (two `uint32` headers plus eleven function pointers) and `8 + 9 * pointer` for `DriverEntry` (two headers plus nine function pointers). Both start with a 4-byte `size` field and a 4-byte `abi_version`; field offsets after the header are pointer-relative and must never be reordered.

Data-only structures use fixed-width integers exclusively and are **identical on all profiles**:

| Structure | Size | Alignment |
|---|---|---|
| `DeviceDesc` (`lmfk_device_desc_t`) | 96 bytes | 8 |
| `Handle` (`lmfk_handle_t`) | 8 bytes | — |
| `Status` (`lmfk_status_t`) | 4 bytes | — |
| `Bus` (`enum lmfk_bus`) | 2 bytes | — |

`DeviceDesc` exposes stable offsets (`size` 0, `bus` 4, `vendor_id` 8, `name` 32) and a 64-byte UTF-8 `name` that is **not guaranteed to be NUL-terminated**. A driver selects the native shim with `abi_profile()` / `AbiProfile` (`Lp64` or `Ilp32`); the ILP32 shim is what covers armv7. Data structures must never be silently changed between profiles.

## 3. Contract rules

### 3.1 Buffers

Pointer parameters are **borrowed for the duration of the call only**. The callee must not retain them. Every buffer is accompanied by an explicit length; **no NUL-termination is assumed** by either side. The caller keeps ownership and may free or reuse the buffer as soon as the call returns.

### 3.2 Handles

A `Handle` is an **opaque token owned by the framework**, never an address and never a kernel pointer. The driver borrows it; it must not fabricate, guess, dereference, or copy it into persistent storage across a framework restart. Using an invalid handle returns `Status::ERR_INVAL` (`LMFK_ERR_INVAL`) and must never trap.

### 3.3 Validation

The framework validates every handle and range before use with **overflow-safe (checked) arithmetic** and returns a stable `Status` value — never an ambiguous `-1`. Drivers must check every returned status and must not assume a handle stays usable after an error.

### 3.4 Concurrency and reentrancy

- Callbacks may be entered on **different threads**; drivers must synchronize their own state.
- The framework **never** calls a driver callback reentrantly from inside another callback of the **same instance**.
- A callback must **not block** on another callback of that same instance.

### 3.5 Execution context

Callbacks run on the **driver's own executor**, never in an arbitrary kernel interrupt context. Interrupt delivery is represented by the `irq` callback (`api::IrqFn`) and acknowledgement is explicit (`irq_ack`). **No unwinding** is allowed across the ABI (`panic = abort`).

### 3.6 Destruction and invalidation

`shutdown` (`api::ShutdownFn`) is the **last callback** issued for a context; after it returns, all handles issued to that context are invalid. Individual handles may be invalidated earlier by a failed operation, by `stop`/`remove`, or by key/policy revocation. Drivers must treat every handle as borrow-only and re-validate statuses on each call.

## 4. Versioning

- A version is encoded as `major << 16 | minor` (`ABI_V1 = 0x0001_0000`). Minor changes are backward-compatible additions; semantic breaks require a new major.
- Every structure begins with a `uint32_t size` field holding the writer's `sizeof`. A reader accepts `size >=` the smallest layout it knows and ignores the tail; `meets_min_size` / `meets_v1` perform this check.
- Fields are **append-only**: never reorder, never insert. The same rule applies to function tables — a missing function is a NULL pointer.
- The framework may host **several major ABI shims simultaneously** (as Linux keeps 32-bit compatibility).
- A driver declares an accepted **range `abi_min..abi_max`** in its manifest; a `minor` of `0xffff` is a wildcard for "any minor of this major" (`ABI_ANY_MINOR`). `VersionRange::accepts` implements the comparison.

## 5. Layout verification

- **Rust** compile-time assertions (`crates/lmfk-abi/src/lib.rs`) and integration tests (`crates/lmfk-abi/tests/layout.rs`) use **pointer-width-relative formulas**: `size_of::<DriverApi>() == 8 + 11 * size_of::<usize>()`, `size_of::<DriverEntry>() == 8 + 9 * size_of::<usize>()`, with `abi_profile()` selecting the exact LP64/ILP32 expectations. Data-only sizes are asserted as absolute constants.
- **C** `_Static_assert` checks (`tests/abi_layout.c`) branch on `__SIZEOF_POINTER__ == 4` for the ILP32 case and use the LP64 values otherwise; data-only structures are checked unconditionally.
- The **IPC header layout is fixed at 32 bytes on every profile**, asserted both in Rust (`IPC_HEADER_SIZE == 32`) and through encode/decode round-trip tests in `crates/lmfk-abi/src/ipc.rs`.

See `03-review-report.md` for the decisions and validation results associated with this contract.
