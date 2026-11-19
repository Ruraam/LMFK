# LMFK — Technical Review and Decisions

*Review document for the current batch (ABI v1 contract, `.drv` container hardening and deterministic CBOR). This lot is **not committed**: it is submitted for review and authorization. No cryptographic phase work is resumed before that authorization.*

Companion documents: `00-technical-spec.md`, `01-drv-format.md`, `02-abi-contract.md`.

## 1. Decisions

| # | Decision | Status |
|---|---|---|
| 1 | **Native ABI vs IPC protocol separated.** Two distinct boundaries are now documented and implemented: in-process vtables on one side, a pointer-free IPC wire protocol on the other. A new module `crates/lmfk-abi/src/ipc.rs` was added for the isolated-userspace path. | Accepted — implemented |
| 2 | **32/64-bit strategy.** Native vtables are profile-dependent (`LP64` / `ILP32`); data structures (`DeviceDesc`, `Handle`, `Status`, `Bus`) remain universal. `armv7` is handled by the `ILP32` shim selected through `abi_profile()`. There is **no silent change** to data structures between profiles. | Accepted — implemented |
| 3 | **C header comments** were corrected to English and made precise about pointers (what is a pointer, what is an opaque token, which sizes follow the pointer width). Rust and C layout tests are **profile-aware**. | Accepted — implemented |
| 4 | **Container: the signature zone must end the file.** A signature that does not reach `EOF` is rejected with `ParseError::SignatureNotAtEnd`; no data is allowed after the signature; `total_size` must equal the real file length. | Accepted — implemented |
| 5 | **Section flags: per-type allowed/required masks.** `TEXT`: `ALLOC|EXEC`; `RODATA`: `ALLOC`; `DATA`: `ALLOC|WRITE`; `BSS`: `ALLOC|WRITE` with **no payload**; `RELOC`/`RESOURCE`: zero masks. Unknown bits are rejected (as are missing required bits). | Accepted — implemented |
| 6 | **CBOR: deterministic profile now enforces canonical map key order** — shortest encoded key first, then bytewise comparison. The encoder sorts keys (`canonical_cmp`), the decoder rejects any other order with `Error::NonCanonicalOrder`. **Duplicate keys are still rejected** (`Error::DuplicateKey`), independently of ordering. | Accepted — implemented |
| 7 | **Structural parsing remains separate from cryptographic verification.** The parser only establishes that the container is coherent and signable; it exposes `signature()` and `signed_region()` as raw byte slices and performs no crypto. | Accepted — unchanged |

## 2. Code changes

| File | Change |
|---|---|
| `crates/lmfk-abi/src/ipc.rs` | **Added.** Pointer-free IPC wire protocol: `IpcMessageHeader` (32-byte little-endian header), `to_bytes` / `from_bytes` / `frame_len`, magic/version validation, overflow-checked frame length. |
| `crates/lmfk-abi/src/lib.rs` and related modules | **Modified.** Profile-aware layout (`AbiProfile`, `abi_profile()`, `repr(C, align(8/4))` vtables), pointer-width-relative compile-time assertions, contract rules in module docs. |
| `include/lmfk/abi.h` | **Modified.** Comments translated to English and clarified (two boundaries, pointer-dependent sizes, ownership, validation, execution context); profile-dependent alignment macro via `__SIZEOF_POINTER__`. |
| `tests/abi_layout.c` | **Modified / added.** `_Static_assert` suite with `__SIZEOF_POINTER__` branches for LP64 vs ILP32; absolute assertions for data-only structures. |
| `crates/lmfk-drv-format/src/cbor.rs` | **Modified.** Canonical map key ordering in encoder and decoder (`NonCanonicalOrder`), plus the deterministic-encoding checks already present. |
| `crates/lmfk-drv-parser/src/lib.rs` | **Modified.** `SignatureNotAtEnd` check (`signature_offset + signature_length == total_size`), per-type section-flag masks (`section_flags`), all range/offset arithmetic checked, separation of parsing from verification. |
| `crates/lmfk-drv-parser/src/tests.rs` | **Modified / added.** Malformed-package fixtures and regression tests listed in section 3. |

## 3. Tests added

- **Exhaustive truncation**: every truncation of a valid package is rejected (`rejects_every_truncation`).
- **Extreme / overflowing offsets**: `u64::MAX`-aligned section payload offsets, out-of-bounds table, manifest and signature regions — all rejected without panicking.
- **Overlaps**: overlap between the section payload and the manifest, and between sections, detected via sorted region intervals.
- **Unknown flags and flag combinations**: unknown package flag bits, `COMPRESSED` in v1, missing and extra/incompatible section-flag bits for each section type.
- **Non-canonical CBOR**: decoder rejects map keys out of canonical order; encoder emits canonical order; duplicate keys still rejected.
- **Data after signature**: appended bytes behind the signature zone rejected with `ParseError::SignatureNotAtEnd`.
- **Deterministic 2000-mutation fuzz loop** (`deterministic_mutation_fuzz_does_not_panic`): 2000 reproducible single-byte mutations of a valid package; parsing must never panic.
- **IPC header tests**: 32-byte pointer-independent layout, encode/decode round trip, bad magic and short-frame rejection, overflow-checked `frame_len`.
- **Profile-aware C static asserts**: LP64/ILP32 branches on `__SIZEOF_POINTER__` for both vtables, plus unconditional data-structure assertions.

## 4. Validation results

| Command | Result |
|---|---|
| `cargo test --workspace` | **58 tests passing.** |
| `cc -std=c11 -Wall -Wextra -fsyntax-only -Iinclude tests/abi_layout.c` | **OK** (no diagnostics). |
| `cargo fmt` / rustfmt | **Applied** to the modified Rust sources. |
| `cargo check -p lmfk-abi --target i686-unknown-linux-gnu` | **OK** (32-bit native ABI compiles). |
| `cargo clippy --workspace --all-targets -- -D warnings` | **OK** (no warnings). |
| `.github/workflows/ci.yml` | **Added**: fmt, tests, clippy, ILP32 check, C asserts. |

## 5. Open issues

- **ILP32 not executed on hardware.** The `i686-unknown-linux-gnu` target was installed and `lmfk-abi` compiles for it, and `.github/workflows/ci.yml` runs that 32-bit check plus the C assertion suite. However, tests were **not executed** on an actual 32-bit host or on armv7; ILP32 layout is validated by conditional C assertions and pointer-relative Rust formulas. Running the test suite on real armv7 hardware remains open.
- **No cargo-fuzz / `arbitrary` integration yet.** The 2000-mutation deterministic loop is a substitute, not a real fuzzing campaign; coverage-guided fuzzing is still to be wired in.
- **IPC semantics incomplete.** Opcode semantics and handle-revocation edge cases (race with in-flight requests, reissue after framework restart, per-opcode handle lifetime) still need to be specified before the IPC protocol can be declared complete.
- **Crypto crate and CLI tools are FROZEN and uncommitted.** `crates/lmfk-drv-crypto` and the three tools `drvinfo`, `drvverify` and `drvpack` have been implemented locally but are **frozen pending this review** — they are deliberately outside this lot.
- **No commit has been made** for this lot. The working tree contains the changes described above, uncommitted.

## 6. Conclusion

This batch is complete and its non-cryptographic part is validated to the extent documented above. **We request review and explicit authorization before any commit is made and before the cryptographic phase is resumed.** Open issues in section 5 — in particular real ILP32 execution, fuzzing integration and IPC opcode/revocation semantics — should be acknowledged or assigned before sign-off.
