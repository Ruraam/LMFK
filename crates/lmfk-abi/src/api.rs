use core::mem::{offset_of, size_of};

use crate::{DeviceDesc, Handle, Status, version::VersionRange};

/* Callback aliases: Option<fn> = nullable pointer of pointer size. */

pub type LogFn =
    Option<unsafe extern "C" fn(ctx: Handle, level: u32, msg: *const u8, len: u32) -> Status>;
pub type MemAllocFn =
    Option<unsafe extern "C" fn(ctx: Handle, size: u64, align: u64, out: *mut Handle) -> Status>;
pub type MemFreeFn = Option<unsafe extern "C" fn(mem: Handle) -> Status>;
pub type MmioMapFn = Option<
    unsafe extern "C" fn(
        dev: Handle,
        bar: u32,
        out_vaddr: *mut Handle,
        out_len: *mut u64,
    ) -> Status,
>;
pub type IrqRegisterFn = Option<
    unsafe extern "C" fn(dev: Handle, index: u32, flags: u32, out_event: *mut Handle) -> Status,
>;
pub type IrqAckFn = Option<unsafe extern "C" fn(dev: Handle, irq_index: u32) -> Status>;
pub type DmaAllocFn = Option<
    unsafe extern "C" fn(
        dev: Handle,
        size: u64,
        out_iova: *mut u64,
        out_cpu: *mut Handle,
    ) -> Status,
>;
pub type IpcOpenFn = Option<
    unsafe extern "C" fn(
        ctx: Handle,
        name: *const u8,
        name_len: u32,
        out_chan: *mut Handle,
    ) -> Status,
>;
pub type DeviceRegisterFn =
    Option<unsafe extern "C" fn(ctx: Handle, desc: *const DeviceDesc, out: *mut Handle) -> Status>;
pub type DeviceReadFn =
    Option<unsafe extern "C" fn(dev: Handle, offset: u64, buf: *mut u8, len: u32) -> Status>;
pub type DeviceWriteFn =
    Option<unsafe extern "C" fn(dev: Handle, offset: u64, buf: *const u8, len: u32) -> Status>;

/// Function table provided by the framework to the driver.
///
/// Adding a function = end of the structure + minor bump. Never
/// reorder: the offset of each callback is part of the contract.
#[cfg_attr(target_pointer_width = "64", repr(C, align(8)))]
#[cfg_attr(target_pointer_width = "32", repr(C, align(4)))]
pub struct DriverApi {
    pub size: u32,
    pub abi_version: u32,
    pub log: LogFn,
    pub mem_alloc: MemAllocFn,
    pub mem_free: MemFreeFn,
    pub mmio_map: MmioMapFn,
    pub irq_register: IrqRegisterFn,
    pub irq_ack: IrqAckFn,
    pub dma_alloc: DmaAllocFn,
    pub ipc_open: IpcOpenFn,
    pub device_register: DeviceRegisterFn,
    pub device_read: DeviceReadFn,
    pub device_write: DeviceWriteFn,
}

impl DriverApi {
    pub const SIZE: usize = size_of::<Self>();

    pub const fn new(abi_version: u32) -> Self {
        Self {
            size: Self::SIZE as u32,
            abi_version,
            log: None,
            mem_alloc: None,
            mem_free: None,
            mmio_map: None,
            irq_register: None,
            irq_ack: None,
            dma_alloc: None,
            ipc_open: None,
            device_register: None,
            device_read: None,
            device_write: None,
        }
    }

    /// Checks that the received structure is large enough to read a field.
    pub const fn meets_min_size(&self, min_size: usize) -> bool {
        (self.size as usize) >= min_size
    }

    /// Checks that it is safe to read up to the last v1 field.
    pub const fn meets_v1(&self) -> bool {
        self.meets_min_size(offset_of!(Self, device_write) + size_of::<DeviceWriteFn>())
    }

    /// Checks that the framework version satisfies the driver's range.
    pub const fn supports(&self, range: VersionRange) -> bool {
        self.meets_min_size(8) && range.accepts(self.abi_version)
    }
}

/* Vtable provided by the driver. */

pub type InitFn = Option<
    unsafe extern "C" fn(
        api: *const DriverApi,
        ctx: Handle,
        config: *const u8,
        config_len: u32,
    ) -> Status,
>;
pub type ProbeFn =
    Option<unsafe extern "C" fn(ctx: Handle, dev: *const DeviceDesc, out: *mut Handle) -> Status>;
pub type StartFn = Option<unsafe extern "C" fn(dev: Handle) -> Status>;
pub type IrqFn = Option<unsafe extern "C" fn(dev: Handle, irq_index: u32) -> Status>;
pub type SuspendFn = Option<unsafe extern "C" fn(dev: Handle) -> Status>;
pub type ResumeFn = Option<unsafe extern "C" fn(dev: Handle) -> Status>;
pub type StopFn = Option<unsafe extern "C" fn(dev: Handle) -> Status>;
pub type RemoveFn = Option<unsafe extern "C" fn(dev: Handle) -> Status>;
pub type ShutdownFn = Option<unsafe extern "C" fn(ctx: Handle)>;

/// Function table provided by the driver to the framework.
#[cfg_attr(target_pointer_width = "64", repr(C, align(8)))]
#[cfg_attr(target_pointer_width = "32", repr(C, align(4)))]
pub struct DriverEntry {
    pub size: u32,
    pub abi_version: u32,
    pub init: InitFn,
    pub probe: ProbeFn,
    pub start: StartFn,
    pub irq: IrqFn,
    pub suspend: SuspendFn,
    pub resume: ResumeFn,
    pub stop: StopFn,
    pub remove: RemoveFn,
    pub shutdown: ShutdownFn,
}

impl DriverEntry {
    pub const SIZE: usize = size_of::<Self>();

    pub const fn new(abi_version: u32) -> Self {
        Self {
            size: Self::SIZE as u32,
            abi_version,
            init: None,
            probe: None,
            start: None,
            irq: None,
            suspend: None,
            resume: None,
            stop: None,
            remove: None,
            shutdown: None,
        }
    }

    pub const fn meets_min_size(&self, min_size: usize) -> bool {
        (self.size as usize) >= min_size
    }
}

/// Signature of the symbol exported by each `.drv` (name: `lmfk_driver_entry`).
pub type DriverEntryPoint = unsafe extern "C" fn(
    api: *const DriverApi,
    ctx: Handle,
    config: *const u8,
    config_len: u32,
    out_entry: *mut *const DriverEntry,
) -> Status;
