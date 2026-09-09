WPA3-SAE (PSA Certified Crypto API 1.4) — design note
=====================================================

Status: **draft for maintainer review** (Phase 0). Tracking issue:
[#709](https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/709).

This note proposes an implementation of the WPA3-SAE password-authenticated key
exchange (PAKE), as specified by the [PSA Certified Crypto API
1.4](https://arm-software.github.io/psa-api/crypto/1.4/) (§10.13.12–13,
Appendix B), for the built-in software driver. It is a design proposal only: no
implementation code is written yet. The goal is to agree the scope, API
surface, new primitives, constant-time strategy, and PR phasing **before** any
code lands.

All PSA symbols below are quoted from the 1.4 specification with a section
reference. Where the spec is ambiguous, it is flagged as an open question
rather than guessed.

## 1. Scope

**In scope**

- WPA3-SAE as defined by IEEE 802.11-2024 §12.4, exposed through the PSA 1.4
  PAKE interface.
- **Hash-to-element (H2E)** password-element derivation only.
- ECC groups: **19 / 20 / 21** (`secp256r1` / `secp384r1` / `secp521r1`).
- FFDH groups: **`PSA_DH_FAMILY_RFC3526`** (IANA groups 15–18) — see §9, open
  question 1 (this differs from an earlier informal "groups 22/23/24" scope).
- Both the **fixed-hash** (`PSA_ALG_WPA3_SAE_FIXED`) and
  **group-dependent-hash** (`PSA_ALG_WPA3_SAE_GDH`) algorithm variants, and the
  H2E password-token key-derivation (`PSA_ALG_WPA3_SAE_H2E`).

**Explicitly out of scope** (these belong in the Wi-Fi supplicant/stack, not
the crypto library):

- The **Looping** ("hunting-and-pecking") PWE method. It is the method H2E was
  designed to replace precisely because it cannot be implemented in constant
  time (Dragonblood, CVE-2019-9494). See §9, open question 2.
- Anti-clogging tokens, rejected-groups negotiation beyond the salt input,
  password identifiers beyond the `INPUT_INFO` KDF input, group negotiation,
  SAE-PK, and mesh peering.
- The Hunting-and-Pecking (HNP) construction generally.

## 2. API surface (PSA Crypto API 1.4)

### 2.1 Algorithms — §10.13.13, Appendix B.1.8/B.1.13

| Macro | Encoding | Purpose |
|---|---|---|
| `PSA_ALG_WPA3_SAE_FIXED(hash_alg)` | `0x0A0008hh` | Fixed-size-PMK variant (Looping + H2E) |
| `PSA_ALG_WPA3_SAE_GDH(hash_alg)` | `0x0A0009hh` | Group-dependent-hash variant |
| `PSA_ALG_WPA3_SAE_ANY` | `0x0A0088FF` | Wildcard key policy |
| `PSA_ALG_IS_WPA3_SAE(alg)` / `_FIXED` / `_GDH` | — | Predicates |
| `PSA_ALG_WPA3_SAE_H2E(hash_alg)` | `0x088004hh` | KDF: derive password token (PT) |

`hh` = HASH-TYPE of `hash_alg`. IEEE variant → macro mapping: Looping →
`FIXED(SHA_256)` (out of scope here); H2E → `FIXED(hash)`; group-dependent-hash
→ `GDH(hash)`. Hash is fixed by the group prime size (IEEE Table 12-1):
256→SHA-256, 384→SHA-384, 521→SHA-512.

### 2.2 Primitive / cipher suite — §10.13.12

Standard `PSA_PAKE_PRIMITIVE(type, family, bits)`:

- ECC: `PSA_PAKE_PRIMITIVE_TYPE_ECC`, `PSA_ECC_FAMILY_SECP_R1`, bits ∈ {256,384,521}.
- FFDH: `PSA_PAKE_PRIMITIVE_TYPE_DH`, `PSA_DH_FAMILY_RFC3526`.

A hash/group mismatch in the cipher suite makes `psa_pake_setup()` return
`PSA_ERROR_INVALID_ARGUMENT`.

### 2.3 Keys — §10.13.12, key-types, Appendix B.2

- **Password**: `PSA_KEY_TYPE_PASSWORD`, encoded per IEEE §12.4.3.
- **Password token (PT)** — output of the H2E KDF:
  - `PSA_KEY_TYPE_WPA3_SAE_ECC(curve)` — `SECP_R1`→`0x3292`,
    `BRAINPOOL_P_R1`→`0x32b0` (only these two ECC families defined). Key format
    is `x ‖ y`, each big-endian `m` bytes.
  - `PSA_KEY_TYPE_WPA3_SAE_DH(group)` — `RFC3526`→`0x3305`.
- The wildcard policy `PSA_ALG_WPA3_SAE_ANY` lets one password key serve any
  suite/derivation, and one PT serve both `FIXED` and `GDH`.

### 2.4 PT derivation (H2E KDF) — key-derivation §, IEEE §12.4.4

`PSA_ALG_WPA3_SAE_H2E(hash_alg)` inputs **in order**:
`PSA_KEY_DERIVATION_INPUT_SALT` = SSID, `PSA_KEY_DERIVATION_INPUT_PASSWORD` =
password, `PSA_KEY_DERIVATION_INPUT_INFO` = password identifier (optional).
Produces exactly one key via `psa_key_derivation_output_key()`, of type
`PSA_KEY_TYPE_WPA3_SAE_ECC/DH`. This is a key→key derivation: the PT never
materialises as a plaintext buffer.

### 2.5 Operation flow and step types — §10.13.5, §10.13.12

SAE is **balanced**: identical flow on both sides, no `psa_pake_set_role()`;
`psa_pake_set_user()` / `set_peer()` carry the two **MAC addresses**;
`psa_pake_set_context()` returns `PSA_ERROR_BAD_STATE`.

| Step | Value | Dir | WPA3-SAE format |
|---|---|---|---|
| `PSA_PAKE_STEP_COMMIT` | `0x06` | out & in | `commit-scalar ‖ COMMIT-ELEMENT` (IEEE §12.4.7.3) |
| `PSA_PAKE_STEP_SALT` | `0x05` | in | rejected-groups list (IEEE §12.4.5.4) |
| `PSA_PAKE_STEP_CONFIRM_COUNT` | `0x07` | in | 2-byte LE send-confirm counter |
| `PSA_PAKE_STEP_CONFIRM` | `0x04` | out & in | 2-byte LE counter ‖ confirm (hash output) |
| `PSA_PAKE_STEP_KEY_ID` | `0x08` | out | 16-byte PMKID |

Sequence: `setup(pt_key,&cs)` → `set_user(mac_a)` → `set_peer(mac_b)` →
**Commit** `output(COMMIT)` / `input(COMMIT)` + `input(SALT)` → **Confirm**
`input(CONFIRM_COUNT)` + `output(CONFIRM)`; verify peer via `input(CONFIRM)` →
optional `output(KEY_ID)` → `get_shared_key()`. Commit-validation failure →
`PSA_ERROR_INVALID_ARGUMENT`; confirm-verification failure →
`PSA_ERROR_INVALID_SIGNATURE`.

### 2.6 Shared key (PMK) — §10.13.12

`psa_pake_get_shared_key(&op, &att, &pmk)` — the caller controls the output key
attributes (type, usage, algorithm, lifetime). PMK is pseudorandom; the spec
recommends using it as a key-derivation input. This directly supports the
opacity requirement: a PMK created with `PSA_KEY_USAGE_DERIVE` and **without**
`PSA_KEY_USAGE_EXPORT` cannot be exported but can still feed a KDF.

### 2.7 Support macros — §10.13.7

Generic and already present: `PSA_PAKE_{OUTPUT,INPUT}_SIZE(alg,primitive,step)`
and `…_MAX_SIZE`. These currently hard-code J-PAKE/`secp256r1` (=65) in
`crypto_extra.h` and **must be extended** to compute SAE sizes: COMMIT =
`scalar ‖ element`, CONFIRM = `2 + hashlen`, KEY_ID = 16.

## 3. Proposed file layout and files to touch

Derived from the existing J-PAKE plumbing (built-in driver) and the SPAKE2+
API-encoding precedent.

**Public API (`include/psa/`)**

- `crypto_extra.h` — new algorithm macros, `PSA_KEY_TYPE_WPA3_SAE_ECC/DH`, an
  `sae` member in the operation-struct computation-stage union, and extended
  `PSA_PAKE_*_SIZE` macros.
- `crypto_values.h` — `PSA_DH_FAMILY_RFC3526` (FFDH, P3).
- `crypto_config.h` — `PSA_WANT_ALG_WPA3_SAE_*` gates.

**Config gating**

- `include/tf-psa-crypto/private/crypto_adjust_config_derived.h` — feed
  `PSA_WANT_ALG_SOME_PAKE`.
- `drivers/builtin/include/mbedtls/private/crypto_adjust_config_enable_builtins.h`
  — derive `MBEDTLS_PSA_BUILTIN_ALG_WPA3_SAE_*` / `MBEDTLS_PSA_BUILTIN_PAKE`,
  pull in ECP/bignum (and, P3, FFDH/RFC3526) modules.
- `core/check_crypto_config.h` — dependency `#error` checks.
- `drivers/builtin/include/mbedtls/private/config_adjust_test_accelerators.h`.
- `scripts/data_files/config-options-current.txt` — list the new
  `PSA_WANT_ALG_WPA3_SAE_*` options.

**Dispatch** — expected **no change**: `psa_driver_wrapper_pake_*` (generated
from `scripts/data_files/driver_templates/psa_crypto_driver_wrappers*.jinja`)
is algorithm-agnostic; per-algorithm branching lives inside the built-in. To be
confirmed in P4.

**Built-in driver + new primitive**

- `drivers/builtin/src/psa_crypto_pake.c` / `.h` — branch the five entry points
  (setup / output / input / get_implicit_key / abort) on the SAE algorithm; add
  H2E KDF handling to the key-derivation path.
- **new** `drivers/builtin/src/sae.c` + private header — the SAE engine
  (PWE/commit/confirm/PMK/PMKID), analogue of `ecjpake.c`.
- **new** `drivers/builtin/src/hash_to_curve.c` + private header — RFC 9380
  `hash_to_field` + Simplified SWU.
- `drivers/builtin/src/ecp.c` — refactor the existing modular square root out of
  `mbedtls_ecp_sw_derive_y()` so it can be shared (see §4.1).

No `CMakeLists.txt` change is needed: `drivers/builtin/CMakeLists.txt` globs
`src/*.c`.

**Tests**

- **new** `tests/suites/test_suite_sae.{data,function}` — low-level KATs
  (RFC 9380 + hostap SAE vectors).
- `tests/suites/test_suite_psa_crypto_pake.{data,function}` — behavioural /
  negative / opacity / policy cases.
- `tests/suites/test_suite_psa_crypto_metadata.{data,function}` — algorithm
  encodings, plus a new `ALG_IS_WPA3_SAE` classification flag in the
  `.function` file.

**Framework submodule (separate repo)**

- `framework/scripts/mbedtls_framework/crypto_knowledge.py` — register the new
  algorithm prefixes as `AlgorithmCategory.PAKE`; `macro_collector.py` /
  `psa_information.py` as needed.
- `framework/tests/src/psa_exercise_key.c` — a branch in the key-derivation
  exerciser for the H2E KDF (`SALT` / `PASSWORD` / optional `INFO`).

The framework PR is submitted and merged **first**, and is written to work with
both the current code and the new code — which is straightforward for a purely
additive feature. The coordination is only that we want CI on the consuming
TF-PSA-Crypto PR to pass before the framework PR merges, as evidence that the
framework side is complete.

**Housekeeping**: `ChangeLog.d/*.txt` fragment; SPDX header
`Apache-2.0 OR GPL-2.0-or-later` on every new `.c`/`.h`; DCO `Signed-off-by` on
every commit.

## 4. New primitives and how each will be implemented

In dependency order.

### 4.1 Modular square root + `is_square` (CT)

A `p ≡ 3 (mod 4)` square root already exists inside
`mbedtls_ecp_sw_derive_y()` (`drivers/builtin/src/ecp.c`), so this is a
**refactor**, not new code: lift `w^((p+1)/4) mod p` into a reusable helper and
have `mbedtls_ecp_sw_derive_y()` call it. Three deltas are needed for SAE/SSWU
use, none of which change existing behaviour:

- The existing function computes its own operand (`ecp_sw_rhs()`); SSWU needs
  the square root of an arbitrary field element, so the operand becomes a
  parameter.
- The existing function documents that it "will return garbage in Y if X does
  not correspond to a point on the curve" — it does not test squareness. SSWU
  needs `is_square`, so the helper also returns a CT squareness flag (verify by
  squaring the result back, rather than a second `exp_mod` for the Legendre
  symbol).
- Root selection stays in the callers, because they need different things:
  `mbedtls_ecp_sw_derive_y()` selects on a parity bit from a public compressed
  point and its existing `if` is fine there; SSWU selects on secret data and
  uses `mbedtls_mpi_core_cond_assign`.

All three curves in scope satisfy `p ≡ 3 (mod 4)`, so the existing
prerequisite check carries over unchanged.

The helper is written at the `bignum_core.h` level (limb array + limb count),
for the reasons in §4.3. `mbedtls_ecp_sw_derive_y()` can call it directly by
growing its operand to `grp->P.n` and passing `Y->p, Y->n` — the same thing
`bignum.c` does internally when it delegates to `mbedtls_mpi_core_*`.

### 4.2 Remaining components

- **Hash-to-curve (RFC 9380, Simplified SWU).** The largest new component.
  `hash_to_field` (expand_message_xmd over the cipher-suite hash) + SSWU
  `map_to_curve`; cofactor is 1 for these curves. Implemented branch-free.
- **SAE engine (`sae.c`).** PWE-from-PT (IEEE §12.4.4.2.3), commit
  (scalar/element generation with blinded scalar mult via `mbedtls_ecp_mul`),
  confirm (SAE KDF + HMAC over the transcript), PMK, PMKID, and peer-input
  validation (`mbedtls_ecp_check_pubkey`, range/identity/reflection checks).
- **SAE KDF.** IEEE `KDF-Hash-Length`, a thin HMAC-based expansion assembled
  from the existing HMAC.
- **FFDH** (separate PR, see §7). New `PSA_DH_FAMILY_RFC3526` + RFC 3526 MODP
  group constants + the FFDH H2E direct method (IEEE §12.4.4.3.3, iterated
  exponentiation + QR test). None of this exists today (only
  `PSA_DH_FAMILY_RFC7919`).

### 4.3 Bignum abstraction level

`bignum_mod.h` is the preferred level for new code, and on paper it fits: SSWU
works modulo one fixed prime for a long run of operations, which is exactly the
case the modulus/residue structures are built for. In practice it does not
currently reach, for four reasons:

- **No exponentiation.** The module exposes `mul`, `sub`, `add`, `inv`,
  `random`, `read`, `write` and modulus/residue lifecycle — and nothing else.
  The square root is `w^((p+1)/4) mod p`, so it cannot be expressed there.
  Modular exponentiation exists only as `mbedtls_mpi_exp_mod()` and
  `mbedtls_mpi_core_exp_mod()` (`bignum_core.h`, documented constant-time with
  respect to `A`, `N` and `E`).
- **No conditional assign.** CMOV is `mbedtls_mpi_mod_raw_cond_assign()`, one
  layer down; SSWU needs it throughout.
- **No comparison.** The CT predicates (`mbedtls_mpi_core_lt_ct`,
  `mbedtls_mpi_core_check_zero_ct`) live in `bignum_core.h`.
- **Montgomery representation gets in the way of `sgn0`.** Residues may be held
  in Montgomery form depending on the modulus `int_rep`, so a bit-level parity
  test — which RFC 9380 `sgn0` needs — reads the wrong value unless converted
  out first.

Proposal, therefore:

- **`hash_to_curve.c` and the square-root helper → `bignum_core.h`.** Fixed
  limb counts, no allocation, and it has the whole toolkit this code needs:
  `exp_mod`, `cond_assign`, `lt_ct`, `check_zero_ct`, and explicit
  `to_mont_rep`/`from_mont_rep` when we want Montgomery form. The cost is
  manual management of the Montgomery form, the precomputed `RR`, and the `T`
  working buffer sized by `mbedtls_mpi_core_exp_mod_working_limbs()`.
- **`sae.c` → `mbedtls_mpi` / `mbedtls_ecp_*`.** It is mostly orchestrating
  existing ECP calls, so any other level only buys conversions at every
  boundary.

Note that the fixed-limb levels are not merely stylistically preferred here.
An `mbedtls_mpi` carries a *normalized* limb count, so a secret value that
happens to be numerically small occupies fewer limbs and operations on it run
shorter — the magnitude leaks through timing. That is the same class of defect
as Dragonblood, so for secret-dependent field arithmetic the fixed-size levels
are the correct default. (`mbedtls_mpi_exp_mod()` is safe on this point: it
grows its operands to `N->n` before delegating to `mbedtls_mpi_core_exp_mod()`.)

Adopting `bignum_mod.h` instead would mean extending it with exponentiation,
comparison and conditional assign. That may well be desirable for the library
independently of this work, but it is a larger change than this feature needs
and would put SAE on the critical path of a bignum API extension. See §9, open
question 5.

Existing building blocks we rely on: the constant-time module
(`include/mbedtls/constant_time.h`), bignum CT ops
(`mbedtls_mpi_core_cond_assign/cond_swap`, `mbedtls_mpi_core_lt_ct`,
`mbedtls_mpi_core_check_zero_ct`, `mbedtls_mpi_core_random`), the legacy
`mbedtls_mpi_safe_cond_assign` where `sae.c` stays on MPIs,
`mbedtls_ecp_mul` (CT with RNG
blinding), `mbedtls_ecp_check_pubkey`, `mbedtls_ecp_point_read/write_binary`,
and SHA-256/384/512 + HMAC.

## 5. Constant-time strategy, per secret-dependent step

Constant-timeness is a correctness requirement here, not hardening: Dragonblood
was a timing/cache side channel in exactly this derivation.

| Step | Secret input | CT approach |
|---|---|---|
| `hash_to_field` | password (via PT/PWE) | Fixed-length hashing; no data-dependent length or branch. |
| SSWU `map_to_curve` | field element `u` | Branch-free: compute both candidate x-values and CMOV via `mbedtls_mpi_core_cond_assign`; `sgn0` reads parity of the canonical (non-Montgomery) value. |
| mod-sqrt / `is_square` | field element | `mbedtls_mpi_core_exp_mod` (documented CT in `A`, `N`, `E`) with a public exponent; squareness checked by squaring the result back and comparing with `mbedtls_mpi_core_lt_ct` / CT equality — no early exit and no second exponentiation. |
| PWE-from-PT | PT | Fixed scalar mult; blinded `mbedtls_ecp_mul`. |
| commit scalar mult | commit-scalar (random) | `mbedtls_ecp_mul` with RNG blinding. |
| confirm KDF / MAC | PMK, KCK | HMAC is CT over its inputs; comparison of received vs computed confirm uses `mbedtls_ct_memcmp`. |
| peer-input validation | (peer values are public, but rejection must not leak PT) | On-curve/range/identity/reflection checks return the same error code and do not branch on the PT. |

The Looping method is excluded specifically because it has no constant-time
implementation (see §1, §9-Q2).

## 6. Test plan (summary; full detail in Task 4 of the recon)

- **Low-level KATs** in `test_suite_sae.*`: RFC 9380 App J vectors (checking
  intermediate `u`, `Q0`, `Q1`, `P`, not just the final point) and hostap
  (BSD-3-Clause) SAE vectors for PT/PWE/commit/confirm/PMK/PMKID.
- **Behavioural** in `test_suite_psa_crypto_pake.*`: full `psa_pake_*` flow per
  group; algorithm-encoding lines in `test_suite_psa_crypto_metadata.data`.
- **Negative set**: point-not-on-curve, identity element, out-of-range scalar,
  reflection, malformed COMMIT (length), wrong confirm/counter/replay, wrong
  password, `set_context` rejected, incompatible hash/group.
- **Algorithm policies**: a non-wildcard key policy must require an exact
  algorithm match (e.g. a key with `PSA_ALG_WPA3_SAE_FIXED(SHA_256)` rejected
  for `…_GDH(SHA_256)` and for `…_FIXED(SHA_384)`), and the exact extent of
  `PSA_ALG_WPA3_SAE_ANY` — which algorithms it does and does not permit,
  including that it does not permit non-SAE algorithms.
- **Opacity (acceptance criteria)**: (a) PMK from `get_shared_key()` with
  `DERIVE` but no `EXPORT` → `psa_export_key` returns `PSA_ERROR_NOT_PERMITTED`
  yet `psa_key_derivation_input_key` succeeds; both peers derive the same PMK
  (checked via KDF output, not by exporting). (b) PT supplied only as a
  persistent, non-exportable key ID; a PT key lacking `DERIVE` fails setup.
- **Constant-time in CI**: mark secrets with `TEST_CF_SECRET`; run under the
  existing `component_tf_psa_crypto_test_memsan_constant_flow_psa` (MSan) and
  `…_valgrind_constant_flow_psa` (Valgrind) in
  `tests/scripts/components-sanitizers.sh`. New CT cases must drive the
  SAE/SSWU/mod-sqrt paths with poisoned secret inputs. These annotations and
  cases land in the PR that introduces the code they cover, not in a later
  hardening pass. Documented limit: this catches secret-dependent
  branches/indexing, not micro-architectural timing.

## 7. Proposed PR phasing

Each phase is independently reviewable; earlier phases land without depending
on later ones. Three rules apply to every phase rather than to a phase of their
own:

- **Tests land with the code they exercise.** No PR adds test vectors ahead of
  the algorithm that consumes them.
- **Constant-time annotations from the start.** They are a small amount of
  code, and adding them later would mean re-reviewing the same code twice.
- **Documentation with the code.** Doxygen for new public macros, types and
  behaviour is written in the PR that introduces them, not retrofitted.

Phases:

- **P1 — square-root refactor + hash-to-curve.** The §4.1 refactor of
  `mbedtls_ecp_sw_derive_y()` plus `hash_to_curve.c` (RFC 9380 `hash_to_field`
  + Simplified SWU), with RFC 9380 Appendix J known-answer tests and CT cases.
  No SAE-specific code. Internal only, so no ChangeLog entry.
- **P2 — SAE engine.** `sae.c`: PWE-from-PT, commit, confirm, SAE KDF,
  PMK/PMKID, peer-input validation, with hostap-derived KATs and CT cases.
  Internal only, so no ChangeLog entry.
- **P3 — `PSA_DH_FAMILY_RFC3526`.** The new DH family encoding plus RFC 3526
  MODP group data and its config/metadata plumbing, standalone. No H2E or SAE
  code. Independent of P1 and P2; can land in any order relative to them.
- **P4 — PSA integration: group 19 / H2E / fixed hash, end to end.** Algorithm
  macros, key types, config gates, built-in driver entry points,
  `get_shared_key` path; full `psa_pake_*` flow for `secp256r1`. This is the
  first API-visible phase and carries the ChangeLog entry.
- **P5 — remaining groups and variants.** ECC groups 20/21, the GDH variant,
  and FFDH H2E on top of P3.
- **P6 — fuzzing.** Fuzzing of peer-supplied inputs, added separately once the
  algorithm is in place.

## 8. Process conformance (CONTRIBUTING.md)

- **License**: dual `Apache-2.0 OR GPL-2.0-or-later`; SPDX identifier on every
  new source file; "Copyright The Mbed TLS Contributors" comment.
- **DCO**: `Signed-off-by:` on every commit (this repo's configured git
  identity).
- **ChangeLog**: a `ChangeLog.d/*.txt` fragment (Features section) per the
  `ChangeLog.d/00README.md` format, only for what is visible through the API.
  The internal-primitive phases (P1, P2) are not reachable from the API and
  therefore get no ChangeLog entry; the entry goes with P4.
- **Tests**: comprehensive tests required with the feature; coverage comparable
  to existing code.
- **Coding style**: Mbed TLS coding standards, enforced with **uncrustify
  0.75.1** and the in-tree `.uncrustify.cfg`.
- **API stability**: this is additive (new macros/types/functions); it can only
  merge at a major/minor release per the API-extension policy. The framework
  submodule change is a separate PR — see §3.

## 9. Open questions for maintainers

1. **FFDH group set.** The 1.4 spec defines only `PSA_DH_FAMILY_RFC3526`
   (MODP primes ≥ 3072 bits, IANA groups 15–18) for SAE FFDH tokens. An earlier
   informal scope named "groups 22/23/24" (RFC 5114), which are not encodable
   under the spec. This note follows the spec (RFC 3526). Please confirm the
   intended FFDH set. *(If 22/23/24 are genuinely required by deployments, that
   is a spec question to raise against `GlobalPlatform/psa-api`, not something
   this implementation can encode unilaterally.)*
2. **Looping variant.** We propose *not* implementing the Looping PWE method
   (no constant-time implementation; H2E supersedes it). A caller requesting
   `FIXED(SHA_256)` with a plain `PSA_KEY_TYPE_PASSWORD` key and no PT would get
   `PSA_ERROR_NOT_SUPPORTED`. Acceptable?
3. **Built-in vs driver-only.** SPAKE2+ ships as API-encoding-only (external
   driver). We propose a full **built-in** SAE implementation. Confirm that is
   the desired direction (vs. encoding-only + reference test driver).
4. **Spec example errata — fixed upstream.** Corrections to the PAKE example
   code in §10.13 were merged as
   [GlobalPlatform/psa-api#372](https://github.com/GlobalPlatform/psa-api/pull/372)
   (targeted for the 1.5.1 publication):
   - §10.13.12 (WPA3-SAE) example used the undefined `PSA_PAKE_STEP_SEND_CONFIRM`;
     the defined step is `PSA_PAKE_STEP_CONFIRM_COUNT` (0x07).
   - §10.13.12 (WPA3-SAE) `get_shared_key` example passed `&spake2p_p`
     (copy-paste from the SPAKE2+ section) instead of the SAE operation.
   - §10.13.10 (SPAKE2+) example used the undefined `PSA_PAKE_STEP_KEY_CONFIRM`;
     the defined step is `PSA_PAKE_STEP_CONFIRM` (0x04).
5. **Bignum abstraction level.** See §4.3. `bignum_mod.h` is the preferred
   level for new code, but as it stands it has no exponentiation, no
   conditional assign and no comparison, and its Montgomery representation
   breaks RFC 9380 `sgn0`. So the choice is really: use `bignum_core.h`, or
   extend `bignum_mod.h` first. We propose `bignum_core.h` for
   `hash_to_curve.c` and the shared square root, and `mbedtls_mpi` for
   `sae.c`. If extending `bignum_mod.h` is wanted instead, we would rather do
   it as its own piece of work than on this feature's critical path.

Test vectors will be sourced from hostap (BSD-3-Clause) and cross-checked
against the IEEE 802.11-2024 §12.4 worked examples.
