#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! LMFK ABI v1: binary contract between the kernel and its drivers.
//!
//! Two different boundaries are deliberately distinguished:
//!
//! * **Native ABI** ([`DriverApi`], [`DriverEntry`]) - in-process drivers that
//!   share an address space with their framework. It contains function
//!   pointers, therefore its layout depends on the target pointer width.
//! * **IPC wire protocol** ([`ipc`]) - isolated userspace drivers. It is
//!   pointer-free, little-endian and identical on every architecture.
//!
//! Data-only structures ([`DeviceDesc`], [`Handle`], [`Status`]) are identical
//! on all profiles: they contain no pointer and use fixed-width integers only.
//!
//! # Profiles
//!
//! | Profile | Targets | Pointer | Native `DriverApi` | Native `DriverEntry` |
//! | --- | --- | --- | --- | --- |
//! | LP64 | x86_64, aarch64 | 8 bytes | 96 bytes | 80 bytes |
//! | ILP32 | armv7 | 4 bytes | 52 bytes | 44 bytes |
//!
//! Use [`abi_profile`] to query the current profile.
//!
//! # Contract rules
//!
//! * **Buffers.** Pointer parameters are borrowed for the duration of the
//!   call only. A callee must not retain them. Lengths are explicit; no
//!   NUL-termination is assumed. The caller keeps ownership and may free or
//!   reuse the buffer as soon as the call returns.
//! * **Handles.** A [`Handle`] is an opaque token owned by the framework. It
//!   is not a pointer and has no meaning outside the framework that issued
//!   it. The driver borrows it; it must not fabricate, guess, copy into
//!   persistent storage across a framework restart, or dereference it.
//! * **Parameter validation.** The framework validates every handle and
//!   range before use and returns a stable [`Status`] error. Drivers must
//!   check every returned status and must not assume a handle stays usable
//!   after an error. Bounds are checked with overflow-safe arithmetic.
//! * **Concurrency and reentrancy.** Callbacks may be entered on different
//!   threads; drivers must synchronize their own state. The framework never
//!   calls a driver callback reentrantly from inside another callback of the
//!   same driver instance. A callback must not block on another callback of
//!   the same instance.
//! * **Execution context.** Callbacks run on the driver's own executor, never
//!   in an arbitrary kernel interrupt context. Interrupt delivery is
//!   represented as the [`api::IrqFn`] callback; acknowledgement is explicit.
//!   No unwinding is allowed across the ABI (`panic = abort`).
//! * **Destruction and invalidation.** [`api::ShutdownFn`] is the last
//!   callback issued for a context; after it returns, all handles issued to
//!   that context are invalid. Individual handles may be invalidated earlier
//!   by a failed operation, by `remove`/`stop`, or by key/policy revocation.
//!   Using an invalid handle returns `Status::ERR_INVAL` and must never trap.

pub mod api;
pub mod handle;
pub mod ipc;
pub mod status;
pub mod types;
pub mod version;

pub use api::{DriverApi, DriverEntry, DriverEntryPoint};
pub use handle::Handle;
pub use ipc::{IPC_HEADER_SIZE, IPC_MAGIC, IPC_VERSION, IpcMessageHeader};
pub use status::Status;
pub use types::{Bus, DEVICE_NAME_LEN, DeviceDesc};
pub use version::{
    ABI_ANY_MINOR, ABI_V1, ABI_VERSION, AbiProfile, VersionRange, abi_major, abi_minor,
    abi_profile, is_compatible, make_version,
};

/// Compile-time layout assertions. Data structures are fixed on every
/// profile; vtable sizes follow the pointer width. The same values are
/// checked in `tests/abi_layout.c` for both LP64 and ILP32.
mod layout_assertions {
    use super::*;
    use api::LogFn;
    use core::mem::{align_of, offset_of, size_of};

    const _: () = assert!(size_of::<Handle>() == 8);
    const _: () = assert!(size_of::<Status>() == 4);
    const _: () = assert!(size_of::<Bus>() == 2);

    const _: () = assert!(size_of::<DeviceDesc>() == 96);
    const _: () = assert!(align_of::<DeviceDesc>() == 8);
    const _: () = assert!(offset_of!(DeviceDesc, bus) == 4);
    const _: () = assert!(offset_of!(DeviceDesc, name) == 32);

    // Function pointers are pointer-sized, not 8 bytes on every target.
    const _: () = assert!(size_of::<LogFn>() == size_of::<usize>());
    const _: () = assert!(offset_of!(DriverApi, abi_version) == 4);
    const _: () = assert!(offset_of!(DriverApi, log) == 8);
    const _: () = assert!(size_of::<DriverApi>() == 8 + 11 * size_of::<usize>());
    const _: () = assert!(offset_of!(DriverEntry, init) == 8);
    const _: () = assert!(size_of::<DriverEntry>() == 8 + 9 * size_of::<usize>());

    const _: () = assert!(IPC_HEADER_SIZE == 32);
    const _: () = assert!(align_of::<IpcMessageHeader>() == 8);
}

/// Runtime profile check for driver hosts that need to select a shim.
pub fn native_abi_size() -> (usize, usize) {
    (size_of::<DriverApi>(), size_of::<DriverEntry>())
}

use core::mem::size_of;
