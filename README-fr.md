# LMFK — Linux Modular-Free Kernel

LMFK est un projet de noyau hybride articulé autour d'une **ABI de pilotes stable**. L'objectif est de définir une interface publique et versionnée vers les pilotes de périphériques, indépendante de toute implémentation particulière du noyau, afin qu'un pilote compilé une seule fois continue de fonctionner sur plusieurs versions du noyau et puisse être installé ou mis à jour sans recompiler ni redémarrer le noyau.

L'idée directrice : *nous ne figeons pas les internes du noyau, nous figeons l'interface publique vers les pilotes.* Les pilotes s'exécutent par défaut en espace utilisateur (isolés lorsqu'ils ne sont pas fiables), sont distribués sous forme de paquets `.drv` signés, et ne franchissent la frontière du noyau que par des handles opacifiés et une table de fonctions — jamais par des pointeurs bruts ni des symboles importés.

> LMFK est un projet distinct du moteur de navigateur Rust `B-Web`.

## Documentation

Documentation française (dans [`docs/fr/`](docs/fr/)) :

- [Cahier des charges technique v0.1](docs/fr/00-cahier-des-charges.md) — périmètre, architecture, règles de conception de l'ABI, feuille de route et risques.
- [Format de paquet `.drv` v1](docs/fr/01-format-drv.md) — conteneur binaire, manifeste CBOR typé, flags de sections et zone de signature.

Documentation anglaise (dans [`docs/en/`](docs/en/)) :

- [Technical Specification v0.1](docs/en/00-technical-spec.md)
- [`.drv` Package Format v1](docs/en/01-drv-format.md)

Pour un index de ce dépôt, voir [README.md](README.md).

## Crates du workspace

Le workspace Cargo contient quatre crates de bibliothèque et trois outils en ligne de commande.

| Crate | Chemin | Rôle |
|---|---|---|
| `lmfk-abi` | `crates/lmfk-abi` | Définitions de l'ABI v1 — le contrat pilote/noyau uniquement, sans implémentation noyau. Handles opacifiés, codes de statut, types IPC et versionnage `major << 16 \| minor`. |
| `lmfk-drv-format` | `crates/lmfk-drv-format` | Définitions du conteneur binaire `.drv` (en-tête, table des sections) et encodeur/décodeur CBOR strict et typé du manifeste, avec profil déterministe. |
| `lmfk-drv-parser` | `crates/lmfk-drv-parser` | Parser et validateur des paquets `.drv`, avec vérification des bornes et sans débordement arithmétique ; tests de fichiers malformés et cas négatifs. Expose la zone de signature comme octets opacifiés. |
| `lmfk-drv-crypto` | `crates/lmfk-drv-crypto` | Vérification d'intégrité (SHA-256) et d'authenticité (Ed25519), magasin de confiance, cycle de vie des clés, révocation et politique anti-rétrogradation. |
| `drvinfo` | `tools/drvinfo` | Inspecter l'en-tête, les sections et le manifeste d'un paquet `.drv`. |
| `drvverify` | `tools/drvverify` | Vérifier la structure, l'intégrité et l'authenticité d'un paquet ; ne court-circuite jamais les étapes. |
| `drvpack` | `tools/drvpack` | Construire un conteneur `.drv` à partir d'un manifeste CBOR et de fichiers de sections, puis le signer. |

L'en-tête ABI en C se trouve dans [`include/lmfk/abi.h`](include/lmfk/abi.h) ; sa disposition est vérifiée par [`tests/abi_layout.c`](tests/abi_layout.c) et par les tests Rust dans `crates/lmfk-abi/tests/`.

## Compilation et tests

```sh
# Compiler tous les crates et outils du workspace
cargo build --workspace

# Exécuter toute la suite de tests
cargo test --workspace

# Travailler sur un crate en particulier
cargo test -p lmfk-abi
cargo test -p lmfk-drv-format
cargo test -p lmfk-drv-parser
cargo test -p lmfk-drv-crypto

# Vérifier la disposition de l'en-tête ABI en C (gcc ou clang)
cc -std=c11 -fsyntax-only -Iinclude tests/abi_layout.c
```

Le workspace cible Rust 1.85 (édition 2024). L'ABI est un **contrat**, et non une représentation d'une implémentation interne : aucune structure noyau, aucun pointeur et aucun type dépendant de l'architecture ne traverse la frontière. Voir [`include/lmfk/abi.h`](include/lmfk/abi.h) pour les règles de versionnage.

## État actuel

| Composant | État |
|---|---|
| Spécification technique / cahier des charges | Livré (v0.1) |
| Spécification du format `.drv` + parser structurel | Livré |
| ABI v1 (en-tête C + crate Rust) | Livré |
| Vérification cryptographique Ed25519 / SHA-256 (`lmfk-drv-crypto`) | Implémentée — en attente de revue |
| Outils (`drvinfo`, `drvverify`, `drvpack`) | Implémentés — en attente de revue |
| Driver Manager (détection, correspondance, cycle de vie) | Non démarré |

## La règle de vérification en trois étapes

La vérification est délibérément divisée en **trois étapes distinctes**, qui ne sont jamais confondues. Un empreinte SHA-256 valide n'implique jamais l'authenticité.

1. **Structure** — analyse structurelle par `lmfk-drv-parser`. Cette étape est **exempte de toute vérification cryptographique** : elle contrôle les bornes, les offsets, l'absence de chevauchements, les masques de flags de sections et la cohérence manifeste/en-tête, et expose la signature comme octets opacifiés. Elle ne vérifie jamais les empreintes ni la signature. Rapportée comme `VerificationLevel::Structure`.
2. **Intégrité** — `verify_integrity()` compare chaque section non-BSS à son empreinte SHA-256 dans la table des sections. Cela détecte la corruption et la falsification des charges utiles, mais ne dit rien de l'origine des empreintes. Rapportée comme `VerificationLevel::Integrity`. Si une empreinte est erronée, le niveau maximal reste `Structure`.
3. **Authenticité** — `verify_authenticity()` vérifie la signature Ed25519 sur la région signée, contrôle la clé par rapport au magasin de confiance (y compris la révocation) et applique les règles anti-rétrogradation sur la version du format et la politique de sécurité. Cette étape ne vérifie **pas** les empreintes des sections. Rapportée comme `VerificationLevel::Authenticated`.

`verify_all()` exécute les étapes d'intégrité et d'authenticité indépendamment et **ne court-circuite jamais**, afin que l'appelant voie exactement quelle étape a échoué. Un paquet n'est **ACCEPTÉ que si l'intégrité et l'authenticité réussissent toutes deux** — une signature valide sur des empreintes de sections corrompues est rapportée comme `Structure`, jamais comme `Authenticated`. En production, tout `.drv` non signé est refusé ; `drvverify` doit réussir avant toute installation ou exécution.

Pour les invariants exacts du conteneur (règle de signature en fin de fichier, masques de flags de sections, ordre canonique des clés CBOR), voir la [spécification du format `.drv`](docs/fr/01-format-drv.md).
