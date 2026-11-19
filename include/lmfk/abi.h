/*
 * LMFK Driver ABI v1.0
 *
 * CONTRAT — Ce fichier definit la frontiere entre le noyau et les pilotes.
 * Il ne doit jamais exposer une structure interne du noyau, ni un pointeur
 * vers la memoire du noyau, ni un type dont la representation depend de
 * l'architecture (tout est uint32_t/uint64_t explicite).
 *
 * REGLES DE VERSIONNAGE
 *   - Toute structure commence par uint32_t size (sizeof a l'ecriture).
 *     Un lecteur accepte size >= taille minimale connue et ignore la queue.
 *   - Les champs ne sont jamais reordonnnes ; ajout uniquement a la fin.
 *   - Les tables de fonctions ne sont jamais reordonnnees ; ajout a la fin,
 *     detecte via size. Une fonction absente est un pointeur NULL.
 *   - Versions : major << 16 | minor. Ajout = mineur, rupture = majeur.
 *     Le framework peut charger plusieurs ABI majeures simultanement.
 *   - Le pilote declare une PLAGE abi_min..abi_max (0xffff = tout minor).
 *
 * CONTRAINTES D'APPEL
 *   - Convention d'appel C, sans exception ni unwinding (panic = abort).
 *   - Les callbacks s'executent sur le thread/executor du pilote, jamais
 *     dans un contexte IRQ noyau arbitraire.
 *   - Les buffers pointes par les parametres appartiennent a l'appelant
 *     sauf indication contraire ; le pilote ne les conserve pas.
 *
 * Ce header est complete par des _Static_assert dans tests/abi_layout.c.
 */

#ifndef LMFK_ABI_H
#define LMFK_ABI_H

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define LMFK_ALIGNED8 __attribute__((aligned(8)))
#else
#define LMFK_ALIGNED8
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
} LMFK_ALIGNED8 lmfk_driver_api_t; /* sizeof = 96, align = 8 */

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
} LMFK_ALIGNED8 lmfk_driver_entry_t; /* sizeof = 80, align = 8 */

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
