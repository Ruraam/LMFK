# LMFK — Contrat ABI v1

*Document normatif. Cette page définit la frontière stable entre le framework et ses pilotes. Elle distingue volontairement deux frontières qu'il ne faut pas confondre : un ABI natif « in-process » et un protocole filaire IPC sans pointeurs. L'implémentation de référence se trouve dans `crates/lmfk-abi` et `include/lmfk/abi.h`.*

Le principe directeur reste celui de la spécification technique : nous ne figeons pas les internals du noyau, nous figeons **l'interface publique** exposée aux pilotes.

## 1. Les deux frontières

| | ABI natif | Protocole filaire IPC |
|---|---|---|
| Public cible | Pilotes « in-process » partageant un espace d'adressage avec le framework | Pilotes utilisateurs isolés (espace d'adressage / processus distinct) |
| Représentation | Tables de fonctions (vtables) : `lmfk_driver_api_t` (framework → pilote) et `lmfk_driver_entry_t` (pilote → framework) | Trames d'octets avec un en-tête fixe de **32 octets, sans pointeur, little-endian** (`IpcMessageHeader`) |
| Référence | `crates/lmfk-abi/src/api.rs`, `include/lmfk/abi.h` | `crates/lmfk-abi/src/ipc.rs` |
| Portabilité | La taille dépend de la largeur de pointeur de la cible (profil) | Identique sur toutes les architectures ; un hôte 32 bits et un hôte 64 bits échangent les mêmes octets |
| Adresses | Des pointeurs locaux apparaissent uniquement dans les vtables et ne sont jamais sérialisés | Aucun pointeur, aucune fonction pointeur ; les handles restent des jetons `u64` opaques et les buffers suivent l'en-tête sous forme de tableaux d'octets préfixés par leur longueur |

Les deux frontières sont des contrats distincts. Un pilote utilisant l'ABI natif n'a aucune obligation de compatibilité filaire, et un pilote IPC n'expose jamais de vtable native. Les confondre est la principale source d'erreurs de layout passées.

L'en-tête IPC contient `magic`, `version`, `opcode`, `request_id`, `handle_count`, `payload_len`, `flags` et `reserved`. `from_bytes` valide le magic et la version, `to_bytes` émet toujours exactement 32 octets little-endian, et `frame_len` calcule la longueur totale de la trame avec une arithmétique vérifiée (`handle_count * 8 + payload_len + 32`).

## 2. Profils et layout des données

Les pointeurs de fonction ne sont **pas de largeur fixe** : ils occupent 4 octets sur une cible 32 bits et 8 octets sur une cible 64 bits. Par conséquent, toute structure qui en contient n'est **pas universelle** sans mécanisme de profil. Les vtables natives dépendent du profil ; les structures de données seules ne dépendent pas.

| Profil | Cibles | Pointeur | `DriverApi` natif | `DriverEntry` natif | Alignement |
|---|---|---|---|---|---|
| LP64 | x86_64, aarch64 | 8 octets | 96 octets | 80 octets | 8 |
| ILP32 | armv7 | 4 octets | 52 octets | 44 octets | 4 |

Les formules de taille sont `8 + 11 * pointeur` pour `DriverApi` (deux en-têtes `uint32` plus onze pointeurs de fonction) et `8 + 9 * pointeur` pour `DriverEntry` (deux en-têtes plus neuf pointeurs de fonction). Les deux commencent par un champ `size` de 4 octets et un champ `abi_version` de 4 octets ; les offsets des champs après l'en-tête sont relatifs à la largeur de pointeur et ne doivent jamais être réordonnés.

Les structures de données seules utilisent exclusivement des entiers de largeur fixe et sont **identiques sur tous les profils** :

| Structure | Taille | Alignement |
|---|---|---|
| `DeviceDesc` (`lmfk_device_desc_t`) | 96 octets | 8 |
| `Handle` (`lmfk_handle_t`) | 8 octets | — |
| `Status` (`lmfk_status_t`) | 4 octets | — |
| `Bus` (`enum lmfk_bus`) | 2 octets | — |

`DeviceDesc` expose des offsets stables (`size` 0, `bus` 4, `vendor_id` 8, `name` 32) et un champ `name` UTF-8 de 64 octets qui n'est **pas garanti terminé par un NUL**. Un pilote sélectionne le shim natif avec `abi_profile()` / `AbiProfile` (`Lp64` ou `Ilp32`) ; c'est le shim ILP32 qui couvre armv7. Les structures de données ne doivent jamais être modifiées silencieusement entre profils.

## 3. Règles du contrat

### 3.1 Buffers

Les paramètres pointeurs sont **empruntés pour la durée de l'appel uniquement**. L'appelé ne doit pas les conserver. Chaque buffer est accompagné d'une longueur explicite ; **aucune terminaison NUL n'est supposée** par l'une ou l'autre partie. L'appelant conserve la propriété et peut libérer ou réutiliser le buffer dès que l'appel retourne.

### 3.2 Handles

Un `Handle` est un **jeton opaque possédé par le framework**, jamais une adresse et jamais un pointeur noyau. Le pilote l'emprunte ; il ne doit pas le fabriquer, le deviner, le déréférencer ni le copier dans un stockage persistant à travers un redémarrage du framework. Utiliser un handle invalide retourne `Status::ERR_INVAL` (`LMFK_ERR_INVAL`) et ne doit jamais provoquer de trap.

### 3.3 Validation

Le framework valide chaque handle et chaque plage avant utilisation avec une **arithmétique vérifiée (sans débordement)** et retourne un `Status` stable — jamais un `-1` ambigu. Les pilotes doivent vérifier chaque statut retourné et ne pas supposer qu'un handle reste utilisable après une erreur.

### 3.4 Concurrence et réentrance

- Les callbacks peuvent être exécutés sur **des threads différents** ; les pilotes doivent synchroniser leur propre état.
- Le framework **n'appelle jamais** un callback de pilote de façon réentrante depuis un autre callback de la **même instance**.
- Un callback ne doit **pas se bloquer** sur un autre callback de cette même instance.

### 3.5 Contexte d'exécution

Les callbacks s'exécutent sur **l'exécuteur propre au pilote**, jamais dans un contexte d'interruption noyau arbitraire. La livraison d'interruption est représentée par le callback `irq` (`api::IrqFn`) et l'acquittement est explicite (`irq_ack`). **Aucun déroulement (unwinding)** n'est autorisé à travers l'ABI (`panic = abort`).

### 3.6 Destruction et invalidation

`shutdown` (`api::ShutdownFn`) est le **dernier callback** émis pour un contexte ; après son retour, tous les handles émis pour ce contexte sont invalides. Des handles individuels peuvent être invalidés plus tôt par une opération en échec, par `stop`/`remove`, ou par une révocation de clé ou de politique. Les pilotes doivent traiter chaque handle comme un emprunt et revérifier les statuts à chaque appel.

## 4. Versionnage

- Une version est encodée en `major << 16 | minor` (`ABI_V1 = 0x0001_0000`). Un changement mineur est un ajout rétrocompatible ; une rupture sémantique exige un nouveau major.
- Chaque structure commence par un champ `uint32_t size` contenant le `sizeof` de l'émetteur. Un lecteur accepte `size >=` le plus petit layout qu'il connaît et ignore la fin ; `meets_min_size` / `meets_v1` effectuent ce contrôle.
- Les champs sont **ajoutés uniquement à la fin** : jamais de réordonnancement, jamais d'insertion. La même règle s'applique aux tables de fonctions — une fonction absente est un pointeur NULL.
- Le framework peut héberger **plusieurs shims de majors différents simultanément** (comme Linux conserve la compatibilité 32 bits).
- Un pilote déclare une **plage acceptée `abi_min..abi_max`** dans son manifeste ; un `minor` à `0xffff` est un joker pour « n'importe quel minor de ce major » (`ABI_ANY_MINOR`). `VersionRange::accepts` implémente la comparaison.

## 5. Vérification du layout

- Les assertions Rust de compilation (`crates/lmfk-abi/src/lib.rs`) et les tests d'intégration (`crates/lmfk-abi/tests/layout.rs`) utilisent des **formules relatives à la largeur de pointeur** : `size_of::<DriverApi>() == 8 + 11 * size_of::<usize>()`, `size_of::<DriverEntry>() == 8 + 9 * size_of::<usize>()`, avec `abi_profile()` qui sélectionne les attentes exactes LP64/ILP32. Les tailles des structures de données seules sont assertées comme constantes absolues.
- Les `_Static_assert` C (`tests/abi_layout.c`) branchent sur `__SIZEOF_POINTER__ == 4` pour le cas ILP32 et utilisent les valeurs LP64 sinon ; les structures de données seules sont vérifiées sans condition.
- Le **layout de l'en-tête IPC est fixé à 32 octets sur tous les profils**, asserté en Rust (`IPC_HEADER_SIZE == 32`) et vérifié par des tests d'aller-retour encodage/décodage dans `crates/lmfk-abi/src/ipc.rs`.

Voir `03-rapport-revue.md` pour les décisions et les résultats de validation associés à ce contrat.
