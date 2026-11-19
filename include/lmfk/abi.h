/*
 * LMFK Driver ABI v1.0
 *
 * CONTRACT - This header defines the boundary between the kernel and drivers.
 * It never exposes a kernel-internal structure or a pointer to kernel memory.
 *
 * TWO BOUNDARIES
 *   - Native ABI (lmfk_driver_api_t / lmfk_driver_entry_t): in-process
 *     drivers sharing an address space with their framework. It contains
 *     function pointers, so its size follows the target pointer width:
 *       LP64  (x86_64, aarch64): api=96, entry=80, alignment 8.
 *       ILP32 (armv7):          api=52, entry=44, alignment 4.
 *   - IPC wire protocol (see crates/lmfk-abi/src/ipc.rs): isolated userspace
 *     drivers. Pointer-free, little-endian, identical on every target.
 *
 * Data-only structures (lmfk_device_desc_t, handles, status codes) have the
 * same representation on every profile: explicit uint32_t/uint64_t only.
 *
 * VERSIONING RULES
 *   - Every structure starts with uint32_t size (sizeof when writing).
 *     A reader accepts size >= the smallest layout it knows and ignores the
 *     tail.
 *   - Fields are never reordered; additions go to the end only.
 *   - Function tables are never reordered; additions go to the end and are
 *     detected via size. A missing function is a NULL pointer.
 *   - Versions are major << 16 | minor. Addition = minor, semantic break =
 *     major. The framework may host several major shims simultaneously.
 *   - A driver declares a RANGE abi_min..abi_max (0xffff = any minor).
 *
 * OWNERSHIP, LIFETIME AND VALIDATION
 *   - Buffer pointers are borrowed for the duration of the call only. The
 *     caller owns them and may reclaim them as soon as the call returns.
 *     Lengths are explicit; no NUL-termination is assumed by either side.
 *   - lmfk_handle_t is an opaque token owned by the framework, never an
 *     address. Drivers borrow it; they must not fabricate, guess or retain
 *     it across a framework restart. Using an invalid handle returns
 *     LMFK_ERR_INVAL and must never trap.
 *   - The framework validates handles and ranges using overflow-safe
 *     arithmetic. Drivers must check every status and must not assume a
 *     handle survives an error, a stop/remove, or a policy revocation.
 *
 * CONCURRENCY AND EXECUTION CONTEXT
 *   - Callbacks may be entered on different threads; drivers synchronize
 *     their own state. No callback is reentered for the same instance while
 *     another callback of that instance is running.
 *   - Callbacks run on the driver's executor, never in an arbitrary kernel
 *     interrupt context. Interrupt delivery is the irq callback and
 *     acknowledgement is explicit. No unwinding across the ABI (panic=abort).
 *   - shutdown is the last callback for a context; afterwards every handle
 *     issued to that context is invalid.
 *
 * Verified by _Static_assert in tests/abi_layout.c on LP64 and ILP32.
 */

#ifndef LMFK_ABI_H
#define LMFK_ABI_H

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define LMFK_ALIGNED8 __attribute__((aligned(8)))
#if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 4
#define LMFK_ALIGNED_PTR __attribute__((aligned(4)))
#else
#define LMFK_ALIGNED_PTR __attribute__((aligned(8)))
#endif
#else
#define LMFK_ALIGNED8
#define LMFK_ALIGNED_PTR
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Version                                                                   */
/* ------------------------------------------------------------------------- */

#define LMFK_ABI_MAKE(major, minor) \
    (((uint32_t)(major) << 16) | ((uint32_t)(minor) & 0xffffu))
#define LMFK_ABI_MAJOR(v) ((uint32_t)(v) >> 16)
#define LMFK_ABI_MINOR(v) ((uint32_t)(v) & 0xffffu)

#define LMFK_ABI_V1 LMFK_ABI_MAKE(1, 0)
#define LMFK_ABI_ANY_MINOR 0xffffu

/* ------------------------------------------------------------------------- */
/* Codes de statut — valeurs stables, jamais reutilisees                     */
/* ------------------------------------------------------------------------- */

typedef int32_t lmfk_status_t;

enum {
    LMFK_OK               =   0,
    LMFK_ERR_UNKNOWN      =  -1,
    LMFK_ERR_INVAL        =  -2,
    LMFK_ERR_NOMEM        =  -3,
    LMFK_ERR_NOTSUP       =  -4,
    LMFK_ERR_NOSYS        =  -5,
    LMFK_ERR_BUSY         =  -6,
    LMFK_ERR_TIMEOUT      =  -7,
    LMFK_ERR_IO           =  -8,
    LMFK_ERR_PERM         =  -9,
    LMFK_ERR_NOTFOUND     = -10,
    LMFK_ERR_ABI_MISMATCH = -11,
    LMFK_ERR_ALREADY      = -12,
    LMFK_ERR_AGAIN        = -13
};

/* ------------------------------------------------------------------------- */
/* Handles opaques — jetons, jamais des pointeurs. 0 = invalide.             */
/* ------------------------------------------------------------------------- */

typedef uint64_t lmfk_handle_t;

/* ------------------------------------------------------------------------- */
/* Bus et niveaux de log — valeurs stables                                   */
/* ------------------------------------------------------------------------- */

enum lmfk_bus {
    LMFK_BUS_UNKNOWN  = 0,
    LMFK_BUS_PCI      = 1,
    LMFK_BUS_USB      = 2,
    LMFK_BUS_ACPI     = 3,
    LMFK_BUS_DT       = 4,
    LMFK_BUS_PLATFORM = 5
};

enum {
    LMFK_LOG_ERROR = 0,
    LMFK_LOG_WARN  = 1,
    LMFK_LOG_INFO  = 2,
    LMFK_LOG_DEBUG = 3,
    LMFK_LOG_TRACE = 4
};

/* ------------------------------------------------------------------------- */
/* Descripteur de device                                                     */
/* ------------------------------------------------------------------------- */

typedef struct lmfk_device_desc {
    uint32_t size;            /* offset 0  : sizeof(lmfk_device_desc_t) */
    uint16_t bus;             /* offset 4  : enum lmfk_bus */
    uint16_t reserved0;       /* offset 6  : doit etre 0 */
    uint32_t vendor_id;       /* offset 8  */
    uint32_t device_id;       /* offset 12 */
    uint32_t sub_vendor_id;   /* offset 16 */
    uint32_t sub_device_id;   /* offset 20 */
    uint32_t class_code;      /* offset 24 */
    uint32_t instance;        /* offset 28 : index unique sur le bus */
    uint8_t  name[64];        /* offset 32 : UTF-8, non garanti NUL-termine */
} LMFK_ALIGNED8 lmfk_device_desc_t; /* sizeof = 96, align = 8 */

/* ------------------------------------------------------------------------- */
/* Types de callbacks                                                        */
/* ------------------------------------------------------------------------- */

typedef lmfk_status_t (*lmfk_log_fn)(
    lmfk_handle_t ctx, uint32_t level, const uint8_t *msg, uint32_t len);

typedef lmfk_status_t (*lmfk_mem_alloc_fn)(
    lmfk_handle_t ctx, uint64_t size, uint64_t align, lmfk_handle_t *out);

typedef lmfk_status_t (*lmfk_mem_free_fn)(lmfk_handle_t mem);

typedef lmfk_status_t (*lmfk_mmio_map_fn)(
    lmfk_handle_t dev, uint32_t bar,
    lmfk_handle_t *out_vaddr, uint64_t *out_len);

typedef lmfk_status_t (*lmfk_irq_register_fn)(
    lmfk_handle_t dev, uint32_t index, uint32_t flags, lmfk_handle_t *out_event);

typedef lmfk_status_t (*lmfk_irq_ack_fn)(lmfk_handle_t dev, uint32_t irq_index);

typedef lmfk_status_t (*lmfk_dma_alloc_fn)(
    lmfk_handle_t dev, uint64_t size, uint64_t *out_iova, lmfk_handle_t *out_cpu);

typedef lmfk_status_t (*lmfk_ipc_open_fn)(
    lmfk_handle_t ctx, const uint8_t *name, uint32_t name_len,
    lmfk_handle_t *out_chan);

typedef lmfk_status_t (*lmfk_device_register_fn)(
    lmfk_handle_t ctx, const lmfk_device_desc_t *desc, lmfk_handle_t *out);

typedef lmfk_status_t (*lmfk_device_read_fn)(
    lmfk_handle_t dev, uint64_t offset, uint8_t *buf, uint32_t len);

typedef lmfk_status_t (*lmfk_device_write_fn)(
    lmfk_handle_t dev, uint64_t offset, const uint8_t *buf, uint32_t len);

/* ------------------------------------------------------------------------- */
/* API fournie par le framework au pilote                                    */
/* ------------------------------------------------------------------------- */

typedef struct lmfk_driver_api {
    uint32_t size;        /* offset 0  : sizeof(lmfk_driver_api_t) */
    uint32_t abi_version; /* offset 4  : version reelle du framework */
    lmfk_log_fn           log;            /* offset 8  */
    lmfk_mem_alloc_fn     mem_alloc;      /* offset 16 */
    lmfk_mem_free_fn      mem_free;       /* offset 24 */
    lmfk_mmio_map_fn      mmio_map;       /* offset 32 */
    lmfk_irq_register_fn  irq_register;   /* offset 40 */
    lmfk_irq_ack_fn       irq_ack;        /* offset 48 */
    lmfk_dma_alloc_fn     dma_alloc;      /* offset 56 */
    lmfk_ipc_open_fn      ipc_open;       /* offset 64 */
    lmfk_device_register_fn device_register; /* offset 72 */
    lmfk_device_read_fn   device_read;    /* offset 80 */
    lmfk_device_write_fn  device_write;   /* offset 88 */
} LMFK_ALIGNED_PTR lmfk_driver_api_t; /* LP64: 96/8, ILP32: 52/4 */

/* ------------------------------------------------------------------------- */
/* Vtable fournie par le pilote au framework                                 */
/* ------------------------------------------------------------------------- */

typedef lmfk_status_t (*lmfk_init_fn)(
    const lmfk_driver_api_t *api, lmfk_handle_t ctx,
    const uint8_t *config, uint32_t config_len);
typedef lmfk_status_t (*lmfk_probe_fn)(
    lmfk_handle_t ctx, const lmfk_device_desc_t *dev, lmfk_handle_t *out);
typedef lmfk_status_t (*lmfk_start_fn)(lmfk_handle_t dev);
typedef lmfk_status_t (*lmfk_irq_fn)(lmfk_handle_t dev, uint32_t irq_index);
typedef lmfk_status_t (*lmfk_suspend_fn)(lmfk_handle_t dev);
typedef lmfk_status_t (*lmfk_resume_fn)(lmfk_handle_t dev);
typedef lmfk_status_t (*lmfk_stop_fn)(lmfk_handle_t dev);
typedef lmfk_status_t (*lmfk_remove_fn)(lmfk_handle_t dev);
typedef void            (*lmfk_shutdown_fn)(lmfk_handle_t ctx);

typedef struct lmfk_driver_entry {
    uint32_t size;        /* offset 0  : sizeof(lmfk_driver_entry_t) */
    uint32_t abi_version; /* offset 4  : version declaree par le pilote */
    lmfk_init_fn     init;     /* offset 8  */
    lmfk_probe_fn    probe;    /* offset 16 */
    lmfk_start_fn    start;    /* offset 24 */
    lmfk_irq_fn      irq;      /* offset 32 */
    lmfk_suspend_fn  suspend;  /* offset 40 */
    lmfk_resume_fn   resume;   /* offset 48 */
    lmfk_stop_fn     stop;     /* offset 56 */
    lmfk_remove_fn   remove;   /* offset 64 */
    lmfk_shutdown_fn shutdown; /* offset 72 */
} LMFK_ALIGNED_PTR lmfk_driver_entry_t; /* LP64: 80/8, ILP32: 44/4 */

/* ------------------------------------------------------------------------- */
/* Point d'entree exporte par chaque .drv                                    */
/* ------------------------------------------------------------------------- */

typedef lmfk_status_t (*lmfk_driver_entry_point_fn)(
    const lmfk_driver_api_t *api, lmfk_handle_t ctx,
    const uint8_t *config, uint32_t config_len,
    const lmfk_driver_entry_t **out_entry);

#ifdef __cplusplus
}
#endif

#endif /* LMFK_ABI_H */
