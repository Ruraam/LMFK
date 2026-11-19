/*
 * C verification of ABI v1. The values must match the assertions in
 * crates/lmfk-abi/src/lib.rs and tests/layout.rs for both native profiles.
 *
 *   cc -std=c11 -Wall -Wextra -fsyntax-only -Iinclude tests/abi_layout.c
 *   cc -std=c11 -Wall -Wextra -Iinclude tests/abi_layout.c -o /tmp/abi_layout && /tmp/abi_layout
 */

#include <lmfk/abi.h>
#include <stddef.h>

_Static_assert(sizeof(lmfk_handle_t) == 8, "handle must be 64 bits");
_Static_assert(sizeof(lmfk_status_t) == 4, "status must be 32 bits");

/* Data-only structures are identical on every profile. */
_Static_assert(sizeof(lmfk_device_desc_t) == 96, "device_desc size");
_Static_assert(_Alignof(lmfk_device_desc_t) == 8, "device_desc alignment");
_Static_assert(offsetof(lmfk_device_desc_t, size) == 0, "device_desc.size");
_Static_assert(offsetof(lmfk_device_desc_t, bus) == 4, "device_desc.bus");
_Static_assert(offsetof(lmfk_device_desc_t, vendor_id) == 8, "device_desc.vendor_id");
_Static_assert(offsetof(lmfk_device_desc_t, name) == 32, "device_desc.name");

/* Function-pointer tables follow the native pointer width. */
#if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 4
_Static_assert(sizeof(lmfk_driver_api_t) == 52, "ILP32 driver_api size");
_Static_assert(_Alignof(lmfk_driver_api_t) == 4, "ILP32 driver_api alignment");
_Static_assert(offsetof(lmfk_driver_api_t, device_write) == 48, "ILP32 device_write");
_Static_assert(sizeof(lmfk_driver_entry_t) == 44, "ILP32 driver_entry size");
_Static_assert(_Alignof(lmfk_driver_entry_t) == 4, "ILP32 driver_entry alignment");
_Static_assert(offsetof(lmfk_driver_entry_t, shutdown) == 40, "ILP32 shutdown");
#else
_Static_assert(sizeof(lmfk_driver_api_t) == 96, "LP64 driver_api size");
_Static_assert(_Alignof(lmfk_driver_api_t) == 8, "LP64 driver_api alignment");
_Static_assert(offsetof(lmfk_driver_api_t, log) == 8, "driver_api.log");
_Static_assert(offsetof(lmfk_driver_api_t, mem_alloc) == 16, "driver_api.mem_alloc");
_Static_assert(offsetof(lmfk_driver_api_t, mmio_map) == 32, "driver_api.mmio_map");
_Static_assert(offsetof(lmfk_driver_api_t, irq_register) == 40, "driver_api.irq_register");
_Static_assert(offsetof(lmfk_driver_api_t, dma_alloc) == 56, "driver_api.dma_alloc");
_Static_assert(offsetof(lmfk_driver_api_t, ipc_open) == 64, "driver_api.ipc_open");
_Static_assert(offsetof(lmfk_driver_api_t, device_register) == 72, "driver_api.device_register");
_Static_assert(offsetof(lmfk_driver_api_t, device_read) == 80, "driver_api.device_read");
_Static_assert(offsetof(lmfk_driver_api_t, device_write) == 88, "driver_api.device_write");
_Static_assert(sizeof(lmfk_driver_entry_t) == 80, "LP64 driver_entry size");
_Static_assert(_Alignof(lmfk_driver_entry_t) == 8, "LP64 driver_entry alignment");
_Static_assert(offsetof(lmfk_driver_entry_t, init) == 8, "driver_entry.init");
_Static_assert(offsetof(lmfk_driver_entry_t, probe) == 16, "driver_entry.probe");
_Static_assert(offsetof(lmfk_driver_entry_t, irq) == 32, "driver_entry.irq");
_Static_assert(offsetof(lmfk_driver_entry_t, stop) == 56, "driver_entry.stop");
_Static_assert(offsetof(lmfk_driver_entry_t, shutdown) == 72, "driver_entry.shutdown");
#endif

_Static_assert(LMFK_ABI_V1 == 0x00010000u, "v1 encoding");
_Static_assert(LMFK_ABI_MAJOR(LMFK_ABI_V1) == 1, "v1 major");
_Static_assert(LMFK_ABI_MINOR(LMFK_ABI_MAKE(1, 7)) == 7, "minor extraction");
_Static_assert(LMFK_ERR_ABI_MISMATCH == -11, "stable error code");

int main(void) {
    return 0;
}
