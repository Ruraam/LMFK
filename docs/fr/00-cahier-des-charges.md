# LMFK — Cahier des charges technique v0.1

*Document de travail. Décisions déjà arbitrées selon la recommandation initiale : **noyau hybride**, base Linux conservée, Driver Framework indépendant, compatibilité Linux progressive.*

> Ce document est volontairement séparé du dépôt `B-Web` (moteur de navigateur Rust). LMFK est un projet distinct.

---

## 0. Périmètre et non-objectifs

| | |
|---|---|
| **Périmètre** | Définir une frontière de pilotes stable (ABI), indépendante de la version du noyau, au-dessus d'un noyau Linux réduit. |
| **Non-objectif v1** | Réécrire Linux. Remplacer universellement les pilotes noyau par des pilotes utilisateur. Supporter GPU/DRM dès le départ. |
| **Principe directeur** | On ne fige pas l'intérieur du noyau, on fige **l'interface publique** vers les pilotes. C'est la seule manière de garder la liberté d'évolution interne. |

⚠️ Précision fondamentale : l'architecture décrite est très proche de **Fuchsia** (FIDL/banjo, `driver_host`, pilotes en userspace) et de **seL4 / MINIX 3** pour l'isolation. L'apport spécifique de LMFK serait de greffer cette architecture sur un socle Linux. C'est utile, mais il faut le dire clairement : l'innovation est dans l'**intégration**, pas dans le concept pur.

## 1. Objectifs mesurables

1. **Indépendance de version** : un `.drv` compilé pour `ABI 1.x` se charge sur tout noyau `1.y` sans recompilation, vérifié par une matrice CI `ABI × versions du noyau`.
2. **Mise à jour sans reconstruction** : installer ou mettre à jour un pilote userspace sans reconstruire ni redémarrer le noyau.
3. **Isolation réelle** : un crash ou une faute mémoire dans un pilote userspace ne doit pas mettre le système à terre (tests d'injection de fautes).
4. **Chaîne de confiance** : 100 % des `.drv` chargés en production sont signés et vérifiés ; refus en mode Secure Boot.
5. **Couverture progressive** : à la phase 5, au moins 20 pilotes Linux courants (PCI/USB/réseau/audio) fonctionnels via la couche de compatibilité.

## 2. Architecture cible

```
RING 0  ── Kernel Core ──────────────────────────────────────────
│  Ordonnanceur · Mémoire · Processus · IPC · VFS · Réseau · Sécurité
│  Driver Core (noyau, minimal) : bus, IRQ, IOMMU, ABI shims, registre
└──────────────────────────┬──────────────────────────────────────
         IPC / handles / capabilities (frontière stable)
RING 3  ── Driver Framework ─────────────────────────────────────
│  driver-manager : détection, matching, dépendances, politique, MAJ
│  driver-host/userspace : 1 processus par pilote, IOMMU + eventfd-like
│  driver-host/isolated : WASM/eBPF ou CSpace capability, permissions fines
├─────────────────────────────────────────────────────────────────
│  Applications : ABI système Linux conservée (aucun changement)
└─────────────────────────────────────────────────────────────────
RING 3  ── Matériel : CPU · GPU · USB · PCIe · Audio · Wi-Fi · Stockage
```

**Règle de placement d'un pilote :** par défaut *userspace* ; *isolated* si le pilote est tiers ou non fiable ; *noyau* uniquement si le matériel est sur le chemin critique avant l'existence des userspace hosts (contrôleur d'interruptions, IOMMU, horloge, console early, boot storage).

## 3. L'ABI stable — le cœur du projet

### 3.1 Règles de conception (non négociables)

- **Handles opaques** : aucune structure interne du noyau ne traverse la frontière. Un `uint64_t` opaque, jamais un pointeur. C'est ce qui permet de changer l'implémentation interne sans casser les pilotes.
- **Tables de fonction (vtable)** passées à l'entrée, jamais de symboles importés. Le pilote ne lie que contre l'ABI, pas contre le noyau.
- **Types à largeur fixe** (`uint32_t`, `uint64_t`), taille explicite en tête de chaque structure (`uint32_t size`), champs ajoutés uniquement **à la fin**.
- **Versionnage `major << 16 | minor`**. Ajout de fonction = bump mineur. Changement sémantique = bump majeur. Le framework embarque plusieurs shims de ABI majeurs en parallèle (comme Linux garde une compatibilité 32-bit).
- **Codes d'erreur stables** (enum type `errno`), jamais de `-1` ambigu.
- **Interdictions** : pointeur brut vers la mémoire noyau, appel synchrone dans un contexte IRQ arbitraire, dépendance à la disposition mémoire du compilateur, appel à libc.
- **Callbacks** : exécutées sur le thread ou l'executor du pilote avec un `drv_handle_t ctx`, jamais dans un contexte noyau arbitraire.

### 3.2 Surface ABI (extrait)

L'exemple initial `int (*allocate_memory)(size_t size)` est le piège classique : il faut un **handle en sortie**, pas un `int`. Version corrigée :

```c
typedef uint64_t drv_handle_t;  /* opaque : jamais un pointeur noyau */

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
} lmfk_driver_api_t;             /* fournie par le framework */

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
} lmfk_driver_entry_t;           /* fournie par le pilote */
```

### 3.3 Règles de compatibilité

- ABI mineure : tout pilote `1.0` tourne sur un framework `1.7` ; les nouvelles fonctions sont détectées via `size`.
- ABI majeure : un pilote `1.x` est chargé via le shim `v1` ; plusieurs shims coexistent.
- Dépréciation : deux versions d'avertissement avant retrait à la majeure suivante.
- Un fichier `.drv` déclare une **plage** `abi_min..abi_max`, pas une version unique.

## 4. Format `.drv`

### 4.1 En-tête (tout little-endian)

| Offset | Taille | Champ |
|---|---|---|
| 0 | 8 | Magic `LMFKDRV\0` |
| 8 | 2 | `format_version` = 1 |
| 10 | 2 | `header_size` |
| 12 | 4 | `flags` (signé, compressé, PIE, …) |
| 16 | 4 | `abi_min` (u16) / `abi_max` (u16) |
| 20 | 4 | arch (1 = x86_64, 2 = aarch64, 3 = armv7, 4 = riscv64) |
| 24 | 4 | `section_count` |
| 28 | … | table des sections (nom, type, offset, taille, align, SHA-256) |

**Sections** : `.text`, `.rodata`, `.data`, `.bss` (taille seule), `.reloc` (réallocations PIE), `.manifest` (CBOR), `.resources`, `.signature`.

**Contrainte de chargement** : code position-independent, pas de symbole externe excepté la vtable reçue à l'entrée. Le framework applique les relocations, puis transfère le contrôle à `lmfk_driver_entry`.

### 4.2 Manifest (exemple)

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

Ed25519 sur l'empreinte (Merkle) du manifest et des sections, chaînée à une clé plateforme ancrée dans le Secure Boot. Liste de révocation distribuée avec le noyau. En production, tout `.drv` non signé est refusé.

**Outils** : `drvpack`, `drvinfo`, `drvverify`, `drvsign`, `drvstrip`.

## 5. Driver Manager

**Responsabilités** : découverte (`/System/Drivers`), lecture des manifests, matching PCI/USB/ACPI/Device Tree, résolution de dépendances (tri topologique), arbitrage de priorité, application de la politique de capabilities, hotplug, cycle de vie, rollback, journal d'audit.

**Cycle de vie** : `DISCOVERED → VERIFIED → MATCHED → LOADED → PROBED → STARTED → (SUSPENDED) → STOPPED → REMOVED → UNLOADED`. Toute transition est auditée et réversible si possible.

**Interface IPC** : `Register`, `Query`, `Load`, `Unload`, `Enable`, `Disable`, `Update`, `ListDevices`. Accès via une socket de service et un token de capability — pas d'accès direct au registre.

**CLI** : `lmfk-drv list|info|verify|install|enable|disable|update|rollback`.

## 6. Sécurité

| Menace | Mitigation |
|---|---|
| Pilote bogue ou malveillant | Processus séparé, IOMMU, capabilities minimales, sandbox WASM/eBPF pour les pilotes tiers |
| DMA hostile | IOMMU par domaine, `dma_alloc` via IOVA, pas d'accès physique brut |
| Chaîne d'approvisionnement | Signature Ed25519, Secure Boot, révocation, builds reproductibles |
| Confused deputy | Le manager ne transmet que des handles, jamais de droits implicites |
| Escalade via interrupt | IRQ routées comme événements, accusé de réception explicite, files bornées |

**Modèle de capabilities** : `mmio:barN`, `irq:index`, `dma:width`, `io:bus`, `ipc:name`, `clock`, `power`. Un pilote ne reçoit que ce que son manifest demande **et** que la politique autorise.

## 7. Compatibilité Linux — la décision la plus risquée

| Approche | Avantage | Coût | Verdict |
|---|---|---|---|
| Intégration statique des pilotes dans le noyau | Simple, immédiat | Recouple au version, plus de MAJ indépendante | **Stopgap phases 1–2** |
| Couche de compatibilité (shim API Linux → ABI LMFK) | Réutilise l'écosystème | Très lourd : `device`, `pci`, workqueues, alloc, locks, DRM… doit suivre upstream | **Phase 5, ciblé** |
| Runtime Linux complet en userspace | Isolement fort | Lourd, proche de UML, performances | À étudier, pas en v1 |
| Pilotes natifs `.drv` | Propre, indépendant | Tout est à écrire | **Objectif long terme** |

**Limites à acter** : les pilotes userspace ne remplacent pas universellement le noyau (IRQ, DMA, latence, GPU). Commencer par PCI/USB/réseau/audio simples ; exclure DRM/GPU et le stockage de boot de la phase 5.

**⚖️ Juridique** : réutiliser du code de pilotes Linux (GPLv2) impose des obligations de licence sur les `.drv` dérivés et potentiellement sur le framework. À trancher avec un conseil juridique avant d'annoncer un projet « indépendant ». C'est un vrai risque, pas un détail.

## 8. Compilation et outillage

- **Rust** pour les nouveaux composants (manager, hosts, outils, bindings ABI), **C** pour le noyau conservé et les shims.
- Workspace type : `lmfk-abi`, `lmfk-drv-format`, `lmfk-manager`, `lmfk-host`, `lmfk-compat`, `lmfk-sdk`, `lmfk-tools`.
- Cibles : `x86_64`, `aarch64`, `armv7` (riscv64 en stretch).
- Builds reproductibles, pins de toolchain, SBOM par `.drv`.
- Tests : CI `ABI × noyau`, QEMU multi-arch, injection de fautes, fuzzing du parser `.drv`, vérification de signature négative.

## 9. Mises à jour

Paquets `.drv` signés, présents dans un dépôt signé. Mise à jour atomique du manifest et des sections, avec rollback automatique si le pilote échoue à `probe` ou `start`. Noyau en A/B avec `kexec` pour les changements d'ABI majeure. Les pilotes userspace se mettent à jour à chaud ; les pilotes noyau nécessitent un redémarrage.

## 10. Feuille de route

| Phase | Livrable | Critère de sortie |
|---|---|---|
| 1 — Kernel Core | Linux réduit, frontière définie | Noyau bootable, ABI gelée en spec |
| 2 — Driver Framework | ABI v1, shims, registre | `.drv` de test chargé sur deux versions de noyau |
| 3 — Driver Manager | Détection, matching, cycle de vie | Hotplug USB fonctionnel |
| 4 — Driver Runtime | Hosts userspace et isolation | Crash injecté = pilote redémarré, noyau intact |
| 5 — Compatibilité Linux | Shim ciblé PCI/USB/réseau | 20 pilotes courants fonctionnels |
| 6 — Pilotes natifs | Écosystème `.drv` natif | Premiers pilotes écrits directement contre l'ABI |

## 11. Risques majeurs

1. **Le piège de l'ABI gelée** : figer une interface peut figer l'implémentation si le shim devient une couche épaisse. Mitigation : garder le shim mince et accepter que seules certaines opérations soient dans l'ABI v1.
2. **Couche de compatibilité sans fin** : suivre les API internes Linux est un travail permanent. Mitigation : la limiter à un sous-ensemble explicite et documenté.
3. **Coût de maintenance d'un fork** : divergence avec upstream. Mitigation : rester aussi proche que possible d'un LTS, contribuer en amont.
4. **Performance IPC/DMA** : overhead pour le réseau et le GPU. Mitigation : chemins rapides partagés, ring buffers, mesures dès la phase 4.
5. **Double discours** : « indépendant » mais dépendant du code Linux. Mitigation : clarifier la licence et le positionnement dès le départ.

## 12. Décisions encore à trancher

1. **Type de noyau** : hybride (recommandé) / microkernel / fork profond. → *recommandation : hybride.*
2. **Compatibilité matérielle** : Linux + natifs / natifs seuls / tout Linux. → *recommandation : Linux d'abord, natifs progressivement.*
3. **Périmètre matériel initial** : quels trois à cinq périphériques pour le prototype ? (ex. : une carte réseau Intel, un contrôleur USB xHCI, un codec audio).
4. **Licence du projet** et stratégie vis-à-vis du GPLv2.
5. **Architecture de sandbox** : WASM/eBPF ou capability CSpace style seL4.

---

*Prochaine étape suggérée : figer l'ABI v1 et le format `.drv` avant toute modification du noyau. C'est la seule partie réellement nouvelle et elle conditionne tout le reste.*
