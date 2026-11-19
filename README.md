# LMFK

Linux Modular-Free Kernel — noyau hybride à ABI de pilotes stable.

- [Cahier des charges technique](docs/00-cahier-des-charges.md)
- [Format `.drv` v1](docs/01-drv-format.md)
- `crates/lmfk-abi` — ABI v1, indépendante de toute implémentation noyau.
- `crates/lmfk-drv-format` — conteneur, manifeste CBOR typé, encodeur/décodeur strict.
- `crates/lmfk-drv-parser` — validation bornée des paquets, tests de fichiers malformés.

## État

| Composant | État |
| --- | --- |
| Cahier des charges | Rédigé (v0.1) |
| ABI v1 (header C + crate Rust) | Livrée |
| Format `.drv` (spécification + parser) | Livrée |
| Signature Ed25519 + SHA-256 | À venir |
| Outils `drvinfo` / `drvverify` / `drvpack` | À venir |
| Driver Manager | À venir |
| Prototype matériel | À venir |

## ABI v1

```sh
cargo test -p lmfk-abi
cc -std=c11 -fsyntax-only -Iinclude tests/abi_layout.c   # gcc/clang
```

L'ABI est un **contrat**, pas une représentation de l'implémentation interne.
Aucune structure noyau, aucun pointeur et aucun type dépendant de l'architecture
ne traverse la frontière. Voir `include/lmfk/abi.h` pour les règles de versionnage.

Le parser vérifie la cohérence du conteneur (offsets, chevauchements, manifeste,
cohérence ABI/architecture) mais **ne vérifie pas encore la signature** : la zone
est exposée comme octets bruts via `DrvFile::signature()` et `signed_region()`.
