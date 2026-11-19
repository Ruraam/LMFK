# LMFK — Gestionnaire de pilotes Linux

LMFK est un **gestionnaire de pilotes Linux**. Il se concentre sur les pilotes qui existent déjà pour Linux : détecter le matériel d'une machine, identifier quel pilote Linux le prend en charge et dans quel état il se trouve, trouver les paquets nécessaires, puis — plus tard — simplifier l'installation et la maintenance.

Il travaille avec les **pilotes Linux existants** : les modules noyau, les firmwares et les paquets de distribution déjà disponibles. LMFK n'est pas un nouveau noyau et n'invente pas une nouvelle catégorie de pilotes.

> LMFK est un projet distinct du moteur de navigateur Rust `B-Web`.

## Ce que fait LMFK

Concrètement, le gestionnaire de pilotes est destiné à répondre aux questions courantes sur le matériel :

- **Vous branchez une carte Wi-Fi** → LMFK identifie le matériel et le pilote Linux qui le prend en charge.
- **Vous avez un GPU** → LMFK propose un pilote compatible pour cette puce.
- **Vous connectez un périphérique USB** → LMFK recherche le module noyau et le firmware dont il a besoin.
- **Un pilote est manquant ou obsolète** → LMFK donne une explication claire du problème et une solution concrète.

## Prévu ensuite

- **Une installation assistée** via le gestionnaire de paquets natif de la distribution (pas de système de paquets parallèle).
- **Les mises à jour des pilotes et des firmwares**, avec une vue claire de ce qui est installé et de ce qui peut être amélioré.
- **La prise en charge multi-distributions** : le premier backend de référence cible **Debian 13**, mais l'architecture est conçue pour être indépendante de la distribution et pour s'étendre à d'autres distributions.

## Ce que LMFK ne remplace pas

- **Aucun nouveau noyau.** LMFK fonctionne sur le noyau Linux que vous avez déjà.
- **Aucun remplacement des modules `.ko`.** Les modules noyau existants continuent de fonctionner comme aujourd'hui.
- **Aucune nouvelle ABI de pilotes.** LMFK ne définit pas d'interface binaire concurrente pour les pilotes.
- **Aucun sous-système de pilotes universel.** Il ne cherche pas à remplacer l'infrastructure de pilotes du noyau.

## Documentation

La feuille de route actuelle est publiée **en anglais uniquement** (voir `docs/en/` ci-dessous). Les documents `docs/fr/00..03` sont historiques.

Documentation historique / expérimentale (dans `docs/fr/`, conservée pour référence — **hors** feuille de route actuelle) :

- [Cahier des charges technique v0.1](docs/fr/00-cahier-des-charges.md) — historique.
- [Format de paquet `.drv` v1](docs/fr/01-format-drv.md) — historique.
- [Contrat ABI v1](docs/fr/02-contrat-abi.md) — historique.
- [Revue technique et décisions](docs/fr/03-rapport-revue.md) — historique.

English documentation (under [`docs/en/`](docs/en/)) — current roadmap:

- [Driver Manager Specification](docs/en/04-driver-manager-spec.md)
- [Hardware Scanner Specification](docs/en/05-hw-scanner-spec.md)
- [Inventory Schema](docs/en/06-inventory-schema.md)

Historical / experimental documentation (under `docs/en/`, preserved for reference — **not** the current roadmap):

- [Technical Specification v0.1](docs/en/00-technical-spec.md) — historical.
- [`.drv` Package Format v1](docs/en/01-drv-format.md) — historical.
- [ABI v1 Contract](docs/en/02-abi-contract.md) — historical.
- [Technical Review and Decisions](docs/en/03-review-report.md) — historical.

Pour un index de ce dépôt, voir [README.md](README.md).

## Crates du workspace

Le workspace Cargo contient toujours les crates de bibliothèque et les outils en ligne de commande de l'ancien projet. Ce sont du code **préservé, historique/expérimental**, conservé intact mais hors du chemin critique actuel.

| Crate | Chemin | État |
|---|---|---|
| `lmfk-abi` | `crates/lmfk-abi` | Historique/expérimental, préservé — anciennes définitions de l'ABI v1. |
| `lmfk-drv-format` | `crates/lmfk-drv-format` | Historique/expérimental, préservé — ancien conteneur `.drv` et manifeste CBOR. |
| `lmfk-drv-parser` | `crates/lmfk-drv-parser` | Historique/expérimental, préservé — ancien parser/validateur `.drv`. |
| `lmfk-drv-crypto` | `crates/lmfk-drv-crypto` | Historique/expérimental, préservé — ancienne vérification SHA-256/Ed25519. |
| `drvinfo` | `tools/drvinfo` | Historique/expérimental, préservé — inspecteur `.drv`. |
| `drvverify` | `tools/drvverify` | Historique/expérimental, préservé — vérificateur `.drv`. |
| `drvpack` | `tools/drvpack` | Historique/expérimental, préservé — constructeur/signataire de conteneurs `.drv`. |

Ces crates et outils sont **commités** dans le dépôt ; ils ne sont pas en attente de revue. Ils sont conservés pour référence et réutilisation éventuelle, et ne sont pas développés dans le cadre de la feuille de route du gestionnaire de pilotes.

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

Le workspace cible Rust 1.85 (édition 2024).

## État actuel

| Composant | État |
|---|---|
| Nouveau gestionnaire de pilotes Linux (spécifications, architecture) | Documentation de phase 0 — non implémenté |
| Anciens crates ABI / `.drv` / crypto et outils | Préservés — expérimentaux/historiques (commités) |
| Gestionnaire de pilotes (détection, correspondance, inventaire, cycle de vie) | Non démarré |
