# LMFK — Revue technique et décisions

*Document de revue pour le lot courant (contrat ABI v1, durcissement du conteneur `.drv` et CBOR déterministe). Ce lot n'est **pas commité** : il est soumis à revue et à autorisation. Aucune phase cryptographique ne sera reprise avant cette autorisation.*

Documents associés : `00-cahier-des-charges.md`, `01-format-drv.md`, `02-contrat-abi.md`.

## 1. Décisions

| # | Décision | Statut |
|---|---|---|
| 1 | **Séparation ABI natif / protocole IPC.** Deux frontières distinctes sont désormais documentées et implémentées : les vtables « in-process » d'un côté, un protocole filaire IPC sans pointeurs de l'autre. Un nouveau module `crates/lmfk-abi/src/ipc.rs` a été ajouté pour la voie utilisateur isolée. | Acceptée — implémentée |
| 2 | **Stratégie 32/64 bits.** Les vtables natives dépendent du profil (`LP64` / `ILP32`) ; les structures de données (`DeviceDesc`, `Handle`, `Status`, `Bus`) restent universelles. `armv7` est couvert par le shim `ILP32` sélectionné via `abi_profile()`. **Aucune modification silencieuse** des structures de données entre profils. | Acceptée — implémentée |
| 3 | Les **commentaires de l'en-tête C** ont été corrigés en anglais et rendus précis concernant les pointeurs (ce qui est un pointeur, ce qui est un jeton opaque, quelles tailles suivent la largeur de pointeur). Les tests de layout Rust et C sont **sensibles au profil**. | Acceptée — implémentée |
| 4 | **Conteneur : la zone de signature doit terminer le fichier.** Une signature qui n'atteint pas `EOF` est rejetée par `ParseError::SignatureNotAtEnd` ; aucune donnée n'est autorisée après la signature ; `total_size` doit égaler la longueur réelle du fichier. | Acceptée — implémentée |
| 5 | **Flags de sections : masques autorisés/requis par type.** `TEXT` : `ALLOC|EXEC` ; `RODATA` : `ALLOC` ; `DATA` : `ALLOC|WRITE` ; `BSS` : `ALLOC|WRITE` **sans payload** ; `RELOC`/`RESOURCE` : masques nuls. Les bits inconnus sont rejetés (tout comme les bits requis absents). | Acceptée — implémentée |
| 6 | **CBOR : le profil déterministe impose désormais l'ordre canonique des clés de map** — clé encodée la plus courte en premier, puis comparaison octet par octet. L'encodeur trie les clés (`canonical_cmp`), le décodeur rejette tout autre ordre par `Error::NonCanonicalOrder`. **Les doublons de clés restent rejetés** (`Error::DuplicateKey`), indépendamment de l'ordre. | Acceptée — implémentée |
| 7 | **L'analyse structurelle reste séparée de la vérification cryptographique.** Le parser établit uniquement que le conteneur est cohérent et signable ; il expose `signature()` et `signed_region()` comme tranches d'octets brutes et n'effectue aucune opération crypto. | Acceptée — inchangée |

## 2. Modifications de code

| Fichier | Modification |
|---|---|
| `crates/lmfk-abi/src/ipc.rs` | **Ajouté.** Protocole filaire IPC sans pointeurs : `IpcMessageHeader` (en-tête little-endian de 32 octets), `to_bytes` / `from_bytes` / `frame_len`, validation du magic et de la version, calcul de longueur de trame avec vérification de débordement. |
| `crates/lmfk-abi/src/lib.rs` et modules associés | **Modifié.** Layout sensible au profil (`AbiProfile`, `abi_profile()`, vtables `repr(C, align(8/4))`), assertions de compilation relatives à la largeur de pointeur, règles du contrat dans la documentation de module. |
| `include/lmfk/abi.h` | **Modifié.** Commentaires traduits en anglais et clarifiés (deux frontières, tailles dépendant du pointeur, propriété, validation, contexte d'exécution) ; macro d'alignement dépendante du profil via `__SIZEOF_POINTER__`. |
| `tests/abi_layout.c` | **Modifié / ajouté.** Suite de `_Static_assert` avec branches `__SIZEOF_POINTER__` pour LP64 vs ILP32 ; assertions absolues pour les structures de données seules. |
| `crates/lmfk-drv-format/src/cbor.rs` | **Modifié.** Ordre canonique des clés de map dans l'encodeur et le décodeur (`NonCanonicalOrder`), en plus des contrôles d'encodage déterministe déjà présents. |
| `crates/lmfk-drv-parser/src/lib.rs` | **Modifié.** Contrôle `SignatureNotAtEnd` (`signature_offset + signature_length == total_size`), masques de flags de sections par type (`section_flags`), tous les calculs d'offsets/plages vérifiés, séparation de l'analyse et de la vérification. |
| `crates/lmfk-drv-parser/src/tests.rs` | **Modifié / ajouté.** Fixtures de paquets malformés et tests de non-régression listés à la section 3. |

## 3. Tests ajoutés

- **Troncatures exhaustives** : chaque troncature d'un paquet valide est rejetée (`rejects_every_truncation`).
- **Offsets extrêmes / débordants** : offsets de payload de section alignés sur `u64::MAX`, régions de table, manifeste et signature hors limites — tous rejetés sans panic.
- **Chevauchements** : chevauchement entre le payload d'une section et le manifeste, et entre sections, détectés par intervalles triés.
- **Flags inconnus et combinaisons de flags** : bits de flags de paquet inconnus, `COMPRESSED` en v1, bits de flags de section manquants ou incompatibles (ajoutés en trop) pour chaque type de section.
- **CBOR non canonique** : le décodeur rejette les clés de map hors ordre canonique ; l'encodeur produit l'ordre canonique ; les doublons de clés restent rejetés.
- **Données après la signature** : les octets ajoutés après la zone de signature sont rejetés par `ParseError::SignatureNotAtEnd`.
- **Boucle de fuzzing déterministe à 2000 mutations** (`deterministic_mutation_fuzz_does_not_panic`) : 2000 mutations reproductibles d'un octet d'un paquet valide ; l'analyse ne doit jamais paniquer.
- **Tests de l'en-tête IPC** : layout de 32 octets indépendant de la largeur de pointeur, aller-retour encodage/décodage, rejet d'un magic invalide et d'une trame trop courte, `frame_len` avec vérification de débordement.
- **Assertions statiques C sensibles au profil** : branches LP64/ILP32 sur `__SIZEOF_POINTER__` pour les deux vtables, plus assertions inconditionnelles sur les structures de données.

## 4. Résultats de validation

| Commande | Résultat |
|---|---|
| `cargo test --workspace` | **58 tests réussis.** |
| `cc -std=c11 -Wall -Wextra -fsyntax-only -Iinclude tests/abi_layout.c` | **OK** (aucun diagnostic). |
| `cargo fmt` / rustfmt | **Appliqué** aux sources Rust modifiées. |
| `cargo check -p lmfk-abi --target i686-unknown-linux-gnu` | **OK** (ABI native 32 bits compile). |
| `cargo clippy --workspace --all-targets -- -D warnings` | **OK** (aucun avertissement). |
| `.github/workflows/ci.yml` | **Ajouté** : fmt, tests, clippy, contrôle ILP32, assertions C. |

## 5. Points ouverts

- **ILP32 non exécuté sur matériel.** La cible `i686-unknown-linux-gnu` a été installée et `lmfk-abi` compile pour elle ; `.github/workflows/ci.yml` exécute ce contrôle 32 bits ainsi que la suite d'assertions C. Les tests n'ont toutefois **pas été exécutés** sur un hôte 32 bits réel ni sur armv7 : la mise en page ILP32 est validée par des assertions C conditionnelles et des formules Rust relatives à la largeur du pointeur. L'exécution de la suite de tests sur du matériel armv7 reste à faire.
- **Pas encore d'intégration cargo-fuzz / `arbitrary`.** La boucle déterministe de 2000 mutations est un substitut, pas une véritable campagne de fuzzing ; le fuzzing guidé par couverture reste à brancher.
- **Sémantique IPC incomplète.** La sémantique des opcodes et les cas limites de révocation de handles (course avec une requête en vol, réémission après redémarrage du framework, durée de vie des handles par opcode) doivent encore être spécifiés avant de déclarer le protocole IPC terminé.
- **Crate crypto et outils CLI GELÉS et non commités.** `crates/lmfk-drv-crypto` et les trois outils `drvinfo`, `drvverify` et `drvpack` ont été implémentés localement mais sont **gelés dans l'attente de cette revue** — ils sont volontairement hors de ce lot.
- **Aucun commit n'a été effectué** pour ce lot. L'arbre de travail contient les modifications décrites ci-dessus, non commitées.

## 6. Conclusion

Ce lot est complet et sa partie non cryptographique est validée dans la mesure documentée ci-dessus. **Nous demandons une revue et une autorisation explicites avant tout commit et avant la reprise de la phase cryptographique.** Les points ouverts de la section 5 — en particulier l'exécution réelle en ILP32, l'intégration du fuzzing et la sémantique des opcodes/révocations IPC — doivent être pris en compte ou assignés avant validation.
