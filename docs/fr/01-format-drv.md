# LMFK — Format de paquet `.drv` v1

*Spécification binaire. Ce document définit le conteneur, le manifeste et la zone de signature. La vérification cryptographique est implémentée dans une phase ultérieure ; le format, lui, est dès maintenant figé.*

Tous les champs numériques du conteneur sont **little-endian**. Le CBOR du manifeste est **big-endian** (norme CBOR) et doit utiliser un encodage déterministe (longueurs minimales, longueurs définitives uniquement, ordre canonique des clés de map — voir §2).

## 1. Conteneur

### 1.1 En-tête fixe — 96 octets

| Offset | Taille | Champ | Description |
|---|---|---|---|
| 0 | 8 | `magic` | `4C 4D 46 4B 44 52 56 00` (`"LMFKDRV\0"`) |
| 8 | 2 | `format_version` | 1 pour cette spec |
| 10 | 2 | `header_size` | 96, doit correspondre |
| 12 | 4 | `flags` | voir 1.4 |
| 16 | 4 | `abi_min` | version ABI minimale (`major<<16\|minor`) |
| 20 | 4 | `abi_max` | version ABI maximale (`0xffff` minor = joker) |
| 24 | 4 | `section_count` | 1..=256 |
| 28 | 4 | `arch_mask` | masque des architectures, `1 << (code-1)` |
| 32 | 4 | `reserved0` | 0 |
| 36 | 4 | `reserved1` | 0 |
| 40 | 8 | `total_size` | taille exacte du fichier |
| 48 | 8 | `section_table_offset` | offset de la table, aligné sur 8 |
| 56 | 8 | `manifest_offset` | offset du CBOR du manifeste, aligné sur 8 |
| 64 | 8 | `manifest_length` | longueur du CBOR du manifeste |
| 72 | 8 | `signature_offset` | offset de la zone de signature, aligné sur 8 |
| 80 | 8 | `signature_length` | longueur de la zone de signature |
| 88 | 8 | `reserved2` | 0 |

Codes d'architecture : `1 = x86_64`, `2 = aarch64`, `3 = armv7`, `4 = riscv64`.

### 1.2 Table des sections

`section_count` entrées de **80 octets**, à `section_table_offset` :

| Offset | Taille | Champ |
|---|---|---|
| 0 | 16 | `name` : ASCII imprimable, rempli de zéros après le NUL |
| 16 | 4 | `type` : 1=TEXT, 2=RODATA, 3=DATA, 4=BSS, 5=RELOC, 6=RESOURCE |
| 20 | 4 | `flags` : 1=ALLOC, 2=EXEC, 4=WRITE |
| 24 | 8 | `offset` : offset absolu dans le fichier |
| 32 | 8 | `size` : taille de la section |
| 40 | 8 | `align` : puissance de 2, `offset % align == 0` |
| 48 | 32 | `sha256` : empreinte du contenu de la section |

Les sections `BSS` déclarent une taille mais **n'occupent aucun octet** dans le fichier ; leur `offset` est ignoré pour la validation des chevauchements.

Noms réservés v1 : `.text`, `.rodata`, `.data`, `.bss`, `.reloc`, `.resources`. Au moins une section `TEXT` est obligatoire ; les noms doivent être uniques.

**Validation des flags de section.** Pour chaque type de section, le parser applique un masque *autorisé* (allowed) et un masque *requis* (required). Une section est rejetée comme `ParseError::InvalidSectionFlags` si elle pose un bit hors du masque autorisé ou si elle n'y pose pas tous les bits requis — les bits de flags inconnus ou interdits sont donc rejetés.

| Type | Flags autorisés | Flags requis |
|---|---|---|
| TEXT | `ALLOC \| EXEC` | `ALLOC \| EXEC` (pas de `WRITE`) |
| RODATA | `ALLOC` | `ALLOC` (pas de `WRITE`/`EXEC`) |
| DATA | `ALLOC \| WRITE` | `ALLOC \| WRITE` |
| BSS | `ALLOC \| WRITE` | `ALLOC \| WRITE` (aucun contenu dans le fichier) |
| RELOC | aucun | flags doivent valoir `0` |
| RESOURCE | aucun | flags doivent valoir `0` |

### 1.3 Invariants vérifiés par le parser

- `total_size == taille réelle du fichier` (ni troncature, ni données superflues). **Aucune donnée ne peut suivre la zone de signature.**
- Pour un paquet signé, la zone de signature doit terminer le fichier : `signature_offset + signature_length == total_size`. Toute autre disposition est rejetée comme `ParseError::SignatureNotAtEnd`.
- `total_size` est toujours égal à la longueur réelle du fichier.
- Tous les offsets et tailles sont calculés avec arithmétique vérifiée (pas de débordement).
- La table des sections, chaque section non-BSS, le manifeste et la signature sont **contenus dans le fichier** et **ne se chevauchent pas mutuellement**.
- `format_version`, `header_size`, les champs réservés et les bits de flags inconnus sont strictement validés.
- Le masque d'architecture de l'en-tête doit correspondre exactement à l'union des architectures du manifeste.
- `abi_min`/`abi_max` de l'en-tête doivent correspondre à ceux du manifeste.
- Une zone de signature non vide exige le bit `SIGNED`, et réciproquement.
- **L'analyse structurelle reste exempte de toute vérification cryptographique** : le parser valide le conteneur, la table des sections et le manifeste, et expose la signature comme octets opacifiés. Il ne vérifie jamais les empreintes SHA-256 ni la signature Ed25519 (voir §4).

### 1.4 Flags du paquet

| Bit | Nom | Règle |
|---|---|---|
| 0 | `SIGNED` | Zone de signature présente |
| 1 | `COMPRESSED` | Refusé en v1 (non implémenté) |
| 2 | `RELOCATABLE` | Le code nécessite des relocations |

## 2. Manifeste (CBOR)

Map CBOR avec clés texte. **Les clés inconnues sont ignorées** (évolution future) ; les clés connues ne doivent pas être dupliquées (le décodeur rejette tout doublon de clé).

| Clé | Type | Obligatoire | Description |
|---|---|---|---|
| `id` | bytes(16) | oui | Identifiant unique du pilote |
| `name` | text | oui | Nom, 1..128 caractères |
| `version` | text | oui | Version sémantique du pilote |
| `abi_min` | uint | oui | Version ABI minimale acceptée |
| `abi_max` | uint | oui | Version ABI maximale acceptée |
| `arch` | array<uint> | oui | 1..8 codes d'architecture |
| `devices` | array<map> | oui | 1..256 entrées de correspondance matérielle |
| `caps` | array<text> | oui | 0..64 capabilities requises |
| `deps` | array<map> | oui | 0..64 dépendances |
| `mode` | uint | oui | 0=kernel, 1=userspace, 2=isolated |
| `entry` | text | oui | Symbole exporté du pilote |
| `license` | text | non | Identifiant de licence SPDX |

Entrée de `devices` : `{ "bus": uint, "vendor": uint, "device": uint, "sub_vendor": uint?, "sub_device": uint?, "class": uint? }`.

Entrée de `deps` : `{ "name": text, "min": text?, "max": text? }`.

Le décodeur impose : profondeur ≤ 16, ≤ 8192 items, longueurs CBOR déterministes, UTF-8 valide, aucune longueur indéfinie, aucune donnée après la valeur racine.

**Profil déterministe — ordre canonique des clés de map.** Au-delà des longueurs minimales et définitives, l'encodage déterministe fixe désormais aussi l'**ordre des clés de map** : une clé est ordonnée selon ses octets *encodés*, avec la **clé encodée la plus courte en premier, puis l'ordre lexicographique octet par octet** en cas d'égalité de longueur. L'encodeur trie les clés de chaque map selon cet ordre ; le décodeur rejette tout autre ordre avec `NonCanonicalOrder`. Les doublons de clés restent rejetés (`DuplicateKey`). Cet ordre s'applique à toutes les maps CBOR, y compris le manifeste, les entrées `devices`/`deps` et le blob de signature.

## 3. Signature

La zone de signature est un blob CBOR :

```text
{ "alg": "ed25519", "key_id": bytes(32), "signature": bytes(64) }
```

L'empreinte signée porte sur **tous les octets du fichier situés avant `signature_offset`**, y compris l'en-tête (dont `signature_length` est connu). La zone de signature doit être la **dernière région du fichier** : `signature_offset + signature_length == total_size`, et aucune donnée ne peut la suivre. Un paquet signé dont la signature ne termine pas le fichier est rejeté comme `ParseError::SignatureNotAtEnd` ; `total_size` est toujours égal à la longueur réelle du fichier. Le parser expose cette zone comme octets bruts ; `drvverify` effectue la vérification avant toute installation ou exécution. En développement, `signature_length = 0` est autorisé ; en production, le bit `SIGNED` est obligatoire.

## 4. Séparation des préoccupations

```
conteneur (format)  →  manifeste (CBOR typé)  →  signature (blob opacifié)  →  code (sections)
```

Chaque élément peut évoluer indépendamment : le numéro de version du format couvre le conteneur, les clés inconnues du manifeste sont ignorées, l'algorithme de signature est déclaré dans le blob, et le code reste un simple contenu de sections.

**L'analyse structurelle n'est pas une vérification cryptographique.** `lmfk-drv-parser` ne contrôle que les invariants structurels (bornes, offsets, chevauchements, masques de flags, cohérence manifeste/en-tête) ; il ne vérifie **pas** les empreintes SHA-256 des sections ni la signature Ed25519. L'intégrité et l'authenticité constituent une étape distincte, réalisée par `lmfk-drv-crypto` / `drvverify`. Un paquet structurellement valide n'est donc jamais automatiquement approuvé — voir la règle de vérification en trois étapes dans `README-fr.md`.
