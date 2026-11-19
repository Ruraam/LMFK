# LMFK — `.drv` Package Format v1

*Binary specification. This document defines the container, the manifest and the signature zone. Cryptographic verification is implemented in a later phase; the format, however, is frozen now.*

All numeric fields of the container are **little-endian**. The manifest CBOR is **big-endian** (CBOR standard) and must use deterministic encoding (minimal lengths, definite lengths only, canonical map key order — see §2).

## 1. Container

### 1.1 Fixed header — 96 bytes

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 8 | `magic` | `4C 4D 46 4B 44 52 56 00` (`"LMFKDRV\0"`) |
| 8 | 2 | `format_version` | 1 for this spec |
| 10 | 2 | `header_size` | 96, must match |
| 12 | 4 | `flags` | see 1.4 |
| 16 | 4 | `abi_min` | minimum ABI version (`major<<16\|minor`) |
| 20 | 4 | `abi_max` | maximum ABI version (`0xffff` minor = wildcard) |
| 24 | 4 | `section_count` | 1..=256 |
| 28 | 4 | `arch_mask` | architecture mask, `1 << (code-1)` |
| 32 | 4 | `reserved0` | 0 |
| 36 | 4 | `reserved1` | 0 |
| 40 | 8 | `total_size` | exact size of the file |
| 48 | 8 | `section_table_offset` | offset of the table, aligned to 8 |
| 56 | 8 | `manifest_offset` | offset of the manifest CBOR, aligned to 8 |
| 64 | 8 | `manifest_length` | length of the manifest CBOR |
| 72 | 8 | `signature_offset` | offset of the signature zone, aligned to 8 |
| 80 | 8 | `signature_length` | length of the signature zone |
| 88 | 8 | `reserved2` | 0 |

Architecture codes: `1 = x86_64`, `2 = aarch64`, `3 = armv7`, `4 = riscv64`.

### 1.2 Section table

`section_count` entries of **80 bytes**, at `section_table_offset`:

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | `name`: printable ASCII, zero-filled after the NUL |
| 16 | 4 | `type`: 1=TEXT, 2=RODATA, 3=DATA, 4=BSS, 5=RELOC, 6=RESOURCE |
| 20 | 4 | `flags`: 1=ALLOC, 2=EXEC, 4=WRITE |
| 24 | 8 | `offset`: absolute offset in the file |
| 32 | 8 | `size`: size of the section |
| 40 | 8 | `align`: power of 2, `offset % align == 0` |
| 48 | 32 | `sha256`: digest of the section content |

`BSS` sections declare a size but **occupy no bytes** in the file; their `offset` is ignored for overlap validation.

Reserved names in v1: `.text`, `.rodata`, `.data`, `.bss`, `.reloc`, `.resources`. At least one `TEXT` section is mandatory; names must be unique.

**Section flag validation.** For each section type the parser applies an *allowed* mask and a *required* mask. A section is rejected as `ParseError::InvalidSectionFlags` if it sets any bit outside the allowed mask or fails to set every required bit — unknown or forbidden flag bits are therefore rejected.

| Type | Allowed flags | Required flags |
|---|---|---|
| TEXT | `ALLOC \| EXEC` | `ALLOC \| EXEC` (no `WRITE`) |
| RODATA | `ALLOC` | `ALLOC` (no `WRITE`/`EXEC`) |
| DATA | `ALLOC \| WRITE` | `ALLOC \| WRITE` |
| BSS | `ALLOC \| WRITE` | `ALLOC \| WRITE` (no file payload) |
| RELOC | none | flags must be `0` |
| RESOURCE | none | flags must be `0` |

### 1.3 Invariants verified by the parser

- `total_size == actual file size` (no truncation, no superfluous data). **No data may follow the signature zone.**
- For a signed package, the signature zone must end the file: `signature_offset + signature_length == total_size`. Any other layout is rejected as `ParseError::SignatureNotAtEnd`.
- `total_size` always equals the real file length.
- All offsets and sizes are computed with checked arithmetic (no overflow).
- The section table, each non-BSS section, the manifest and the signature are **contained in the file** and **do not overlap each other**.
- `format_version`, `header_size`, reserved fields and unknown flag bits are strictly validated.
- The header architecture mask must match exactly the union of the manifest's architectures.
- The header's `abi_min`/`abi_max` must match those of the manifest.
- A non-empty signature zone requires the `SIGNED` bit, and vice versa.
- **Structural parsing stays free of any cryptographic verification**: the parser validates the container, the section table and the manifest, and exposes the signature as opaque bytes. It never checks SHA-256 digests or the Ed25519 signature (see §4).

### 1.4 Package flags

| Bit | Name | Rule |
|---|---|---|
| 0 | `SIGNED` | Signature zone present |
| 1 | `COMPRESSED` | Refused in v1 (not implemented) |
| 2 | `RELOCATABLE` | Code requires relocations |

## 2. Manifest (CBOR)

CBOR map with text keys. **Unknown keys are ignored** (future evolution); known keys must not be duplicated (the decoder rejects any duplicate key).

| Key | Type | Required | Description |
|---|---|---|---|
| `id` | bytes(16) | yes | Unique driver identifier |
| `name` | text | yes | Name, 1..128 characters |
| `version` | text | yes | Semantic version of the driver |
| `abi_min` | uint | yes | Minimum accepted ABI version |
| `abi_max` | uint | yes | Maximum accepted ABI version |
| `arch` | array<uint> | yes | 1..8 architecture codes |
| `devices` | array<map> | yes | 1..256 hardware matching entries |
| `caps` | array<text> | yes | 0..64 required capabilities |
| `deps` | array<map> | yes | 0..64 dependencies |
| `mode` | uint | yes | 0=kernel, 1=userspace, 2=isolated |
| `entry` | text | yes | Exported symbol of the driver |
| `license` | text | no | SPDX license identifier |

`devices` entry: `{ "bus": uint, "vendor": uint, "device": uint, "sub_vendor": uint?, "sub_device": uint?, "class": uint? }`.

`deps` entry: `{ "name": text, "min": text?, "max": text? }`.

The decoder enforces: depth ≤ 16, ≤ 8192 items, deterministic CBOR lengths, valid UTF-8, no indefinite lengths, no data after the root value.

**Deterministic profile — canonical map key order.** Beyond minimal, definite lengths, deterministic encoding now also fixes the **order of map keys**: a key is ordered by its *encoded* bytes, with the **shortest encoded key first, then bytewise lexicographic order** for equal lengths. The encoder sorts every map's keys into this order; the decoder rejects any other order as `NonCanonicalOrder`. Duplicate keys remain rejected (`DuplicateKey`). This order applies to all CBOR maps, including the manifest, the `devices`/`deps` entries and the signature blob.

## 3. Signature

The signature zone is a CBOR blob:

```text
{ "alg": "ed25519", "key_id": bytes(32), "signature": bytes(64) }
```

The signed digest covers **all bytes of the file located before `signature_offset`**, including the header (of which `signature_length` is known). The signature zone must be the **last region of the file**: `signature_offset + signature_length == total_size`, and no data may follow it. A signed package whose signature does not end the file is rejected as `ParseError::SignatureNotAtEnd`; `total_size` always equals the real file length. The parser exposes this zone as raw bytes; `drvverify` performs verification before any installation or execution. In development, `signature_length = 0` is allowed; in production, the `SIGNED` bit is mandatory.

## 4. Separation of concerns

```
container (format)  →  manifest (typed CBOR)  →  signature (opaque blob)  →  code (sections)
```

Each element can evolve independently: the format version number covers the container, unknown manifest keys are ignored, the signature algorithm is declared in the blob, and the code remains mere section content.

**Structural parsing is not cryptographic verification.** `lmfk-drv-parser` checks only structural invariants (bounds, offsets, overlaps, flag masks, manifest/header consistency); it does **not** verify SHA-256 section digests or the Ed25519 signature. Integrity and authenticity are a distinct stage performed by `lmfk-drv-crypto` / `drvverify`. A structurally valid package is therefore never automatically trusted — see the three-stage verification rule in `README-en.md`.
