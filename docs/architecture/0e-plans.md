TF-PSA-Crypto minimal interfaces
================================

## Introduction

This document describes plans for a minimalist TF-PSA-Crypto, tentatively called TF-PSA-Crypto 0ε, and a matching Mbed TLS consuming it. The general idea is to start from PSA interfaces, and expose additional interfaces to provide functionality that PSA does not currently offer. Most additional interfaces will be existing ones, but they can be new interfaces if it makes more sense.

Mbed TLS will continue using internal interfaces of TF-PSA-Crypto, even after the release of TF-PSA-Crypto 1.0 and Mbed TLS 4.0. However, it is an objective that some 4.x version will no longer need to use any internal interface of TF-PSA-Crypto. As a result, we will remove some functionality from Mbed TLS. In the 0ε version, it is an objective that no public interface of Mbed TLS will expose an internal interface of TF-PSA-Crypto.

Note that the name “TF-PSA-Crypto 0ε” is for convenience only. At this time, we are not planning a release of this version. We are planning a beta release of TF-PSA-Crypto before the 1.0 release, but this may come before or after the 0ε described in this document.

This document is about C-level interfaces for applications and integration. Other aspects of the project, such as build and test scripts, are out of scope.

## Glossary

This document uses a few unusual terms, and a few generic terms with a specific meaning. This section explains those terms.

**0ε**: a version of TF-PSA-Crypto that minimally meets the formal requirements for TF-PSA-Crypto 1.0. This may not be something we want to release, for example because it lacks critical features, is insufficiently tested, has insufficient documentation, or would be too much of a burden to maintain. It comes before the TF-PSA-Crypto **MVP**.

**1.0**: The first ever stable release of TF-PSA-Crypto. Its publicly documented APIs will remain supported throughout the lifecycle of TF-PSA-Crypto 1.x.

**3ε**: A version of Mbed TLS corresponding to TF-PSA-Crypto 0ε.

**4.0**: The first stable release of Mbed TLS consuming TF-PSA-Crypto. Its publicly documented APIs will remain supported throughout the lifecycle of Mbed TLS 4.x.

**Alpha**: A release of TF-PSA-Crypto or Mbed TLS that is not widely advertized and that may have known major gaps that make it unsuitable for **MVP** or even **0ε/3ε**. There are no commitments to API stability.

**Beta**: A release of TF-PSA-Crypto or Mbed TLS that is advertized to integrators and application writers and that may have known minor gaps that make it unsuitable for **MVP** or even **0ε/3ε**. There are no commitments to API stability.

**Exposed** (interface): An interface (such as a header, type, function or configuration option) that is not publicly documented and not part of the stable API, but that is visible to the compiler when building application code. A typical example is types that are used in fields of structs whose content is not stable, but that it must be possible to allocate on the stack or statically.

**MVP** (minimum viable product): A version of TF-PSA-Crypto and a corresponding version of Mbed TLS that meet the requirements for TF-PSA-Crypto 1.0, and that would be acceptable for a 1.0/4.0 release.

**Private** (interface): An interface (such as a header, type, function or macro) that is not publicly documented, and that may change or be removed without warning. This is the opposite of **public**. To the extent that it is practical, the library should prevent applications from accidentally relying on private interfaces, but some private interfaces have to be **exposed**.

**Public** (interface): An interface (such as a header, type, function or configuration option) that is publicly documented, and that is covered by API stability guarantees within a major version of TF-PSA-Crypto or Mbed TLS. This is the opposite of **private**, and does not include **exposed** interfaces.

The **Split** (repository split): the split between TF-PSA-Crypto and Mbed TLS, where `tf-psa-crypto` became a submodule instead of a subdirectory. This happened on 2024-12-16.

## Project goals

### Starting point

Our starting point is TF-PSA-Crypto and Mbed TLS as of the repository split, or equivalently as of 2025-01-01. Compared with Mbed TLS 3.6:

* `MBEDTLS_USE_PSA_CRYPTO` is always enabled: PK, X.509 and TLS always use PSA APIs for cryptography, except for a few limitations documented in [`use-psa-crypto.md`](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6/docs/use-psa-crypto.md).
* `MBEDTLS_PSA_CRYPTO_CONFIG` is always enabled: only `PSA_WANT_xxx` symbols can be used to configure which cryptographic mechanisms are enabled, not `MBEDTLS_xxx`.
* The only public interfaces in TF-PSA-Crypto are the ones in `<psa/crypto.h>` (including interfaces in `include/psa/crypto_*.h` which are exposed indirectly via `crypto.h`). The crypto interfaces in `<mbedtls/*.h>` are considered private, but not marked as such, at the start of the project.

### Feature goals

Ideally, TF-PSA-Crypto 1.0 and Mbed TLS 4.0 would have the same features as Mbed TLS 3.6, except for a small set of features that we have decided to remove (e.g. obsolescent cryptographic mechanisms). This would include creating PSA interfaces where 3.6 only has non-PSA (Mbed TLS legacy) interfaces.

By removing legacy crypto interfaces, we are removing many features for which no corresponding PSA interface exists. For example:

* Configuring an entropy source relies on `<mbedtls/entropy.h>`
* Parsing or formatting a key in common formats relies on `<mbedtls/pk.h>`.
* X.509 fundamentally relies on some features that are not strictly speaking cryptography, but are implemented in TF-PSA-Crypto which needs them for its own use as well: ASN.1 (`<mbedtls/asn1.h>` and `<mbedtls/asn1write.h>`), PEM (`<mbedtls/pem.h>`).
* Parsing or constructing X.509 extensions tends to require ASN.1 functions.

Given the available time and resources, we cannot ensure that 1.0/4.0 will be suitable for all the same use cases as 3.6. However, compared to the project starting point, we will bring back essential use cases. The use cases listed just above are examples of essential features that we want to provide in 0ε. More use cases can be brought back later by exposing more internal legacy interfaces or designing new PSA interfaces.

### Maintainability goals

We don't want to keep maintaining the legacy crypto APIs. They are too low-level, and we want the ability to fully migrate to PSA APIs for cryptography.

This goal will mainly act as a moderator on bringing back features by just exposing legacy interfaces.

For example, we do not want the type `mbedtls_mpi` to be part of the 0ε or 1.0/4.0 API, because it leaks the internal representation of integers, and this limits us when doing optimizations and security improvements.

### Quality goals

TF-PSA-Crypto and Mbed TLS must continue to be high-quality products. Given our limited bandwidth, 0ε and possibly even 1.0/4.0 may compromise on some aspects of quality. However, this needs to be balanced carefully, and not all aspects of quality are up for compromise. As an extreme example, security shall not be compromised at any point.

Some considerations on quality have come up:

* Documentation in the 1.0/4.0 release must be good enough for users and should match our standards for 3.6. We may skip some documentation tasks in 0ε, but the remaining tasks should be clearly identified.
* For users who migrate from 3.6, there should be a clear upgrade path, and there should be an easy way for users to ensure that they have finished migrating, i.e. that they are no longer accidentally using an interface that is now private. This aspect may be compromised in 0ε, although it is not clear whether this is desirable, since having a clear way to flag uses of legacy APIs is a convenient way of evaluating whether 0ε is fit for purpose.
* We have few sample programs for the PSA API. It is unfortunately likely that this will continue past the TF-PSA-Crypto 1.0 release.
* At this point, the TF-PSA-Crypto project does not have self-reliant testing. As outlined in the introduction above, this is out of scope of this document.

### Project 0ε goals

1. In TF-PSA-Crypto, ensure a clear separation between public interfaces (part of the API stability promise) and private interfaces (which may change at any time, even if they are used in Mbed TLS code, or embedded in private structure types).
2. Remove selected features of Mbed TLS. This is mainly driven by the desire to stop maintaining some features that cannot be easily provided without legacy crypto APIs.
3. Expose selected legacy interfaces to fill some functionality gaps. In a few cases, this can also include new interfaces, generally tweaks on the legacy interface (e.g. replacing an `mbedtls_mpi*` argument of a public function by a byte array).

## Hiding low-level cryptography interfaces

### Deciding what to hide

#### Degrees of public interfaces

There are several potential criteria for whether an interface is part of the library's stable API. Roughly from the most permissive to the most restrictive:

* Declared in a public header.
* Declared in a public header, without a comment indicating that it's private or unstable.
* Present in the rendered documentation.
* Present in the rendered documentation, and not documented as unstable.

In [`BRANCHES.md`](https://github.com/Mbed-TLS/mbedtls/blob/development/BRANCHES.md#backwards-compatibility-for-application-code), we promise backward compatibility for “code that's working and secure with Mbed TLS x.y.z and does not rely on undocumented features”. That roughly corresponds to the most restrictive criteria.

#### Exposed interfaces

There are two main reasons why interfaces are declared in public headers, but not part of the stable API of the library:

* Historically, all non-static functions were declared in public headers. This started changing during the Mbed TLS 2.x era, and Mbed TLS 3.6.0 removed most of the remaining functions that were declared in a public header with a comment stating that they were not part of the API. However, some functions may have been missed, or may become non-desired in the API in 4.0/1.0.
* Several elements have to be visible to the compiler, even though they are not part of the public interface. In particular:
    * The definition of types, where we only promise the stability of the existence of the type, but not of how it is implemented. These are **opaque types**.
    * The existence of types whose purpose is to define opaque types. These have to be in a header that is visible to the compiler, but we don't want to make any stability commitment about them. For example, `mbedtls_aes_context` is needed to define the opaque type `psa_cipher_operation_t`. Let us call such types **exposed types**.
    * The implementation of static inline functions. This is generally not a problem since you can't do anything other than call the function anyway.
    * **Intermediate macros** which were only intended to define other macros and not intended to be stable. There are many such macros in `psa/crypto_values.h` and `psa/crypto_sizes.h`, for example. They are identified by not having Doxygen documentation, but this is discreet.

For the 0ε target, and likely even the 1.0/4.0 release, we aim to make the situation not worse than it is in 3.6. We don't plan to go on a hunt for ambiguous declarations in headers, but we should make sure we don't create new ambiguities. In particular, if an interface was part of the public API of Mbed TLS 3.6, but we don't consider it part of the public API of 1.0/4.0, we should make this clear, preferably by ensuring that applications won't compile if they try to use such interfaces.

#### Quasi-private interfaces of TF-PSA-Crypto

The separation between TF-PSA-Crypto and Mbed TLS adds another layer of complexity: some interfaces are considered private in TF-PSA-Crypto, but are still used in Mbed TLS. This includes code used in the library itself, or in test code, or in sample programs. This excludes code guarded by `!defined(MBEDTLS_USE_PSA_CRYPTO)` which is still present but never built. Given the engineering bandwidth available for the Mbed TLS 4.0 release, we know that we will not be able to eliminate such interfaces.

Note that private interfaces of TF-PSA-Crypto may only be used internally in Mbed TLS. They may not leak though the public interface of Mbed TLS. This is an objective for 0ε as well as for the 4.0 release. (Exposed interfaces of TF-PSA-Crypto may be exposed in Mbed TLS as well.)

It is a common use case that TF-PSA-Crypto is integrated on a platform as part of the basic board support package (BSP). It may be a lightweight integration with just a default configuration file and some platform customization, or a more elaborate integration such as TF-M which runs the bulk of the crypto library in a separate runtime environment. In the latter case, the source code of the customized crypto library might even not be present when compiling Mbed TLS.

To allow such builds, the interfaces of TF-PSA-Crypto that are used internally in Mbed TLS will be declared in public headers, but in such a way that applications cannot use them without going out of their way.

#### Categories of crypto headers

At the start of the 0ε work, all legacy headers of TF-PSA-Crypto are located under `drivers/*/include`. This includes the definitions of many exposed types, as well as many TF-PSA-Crypto interfaces used by Mbed TLS. Thus it is impossible to build TF-PSA-Crypto or Mbed TLS without having these headers in the include path (except maybe some configurations that exclusively use third-party PSA drivers).

For the 0ε target, we will separate headers that are only needed to compile TF-PSA-Crypto itself from headers that are needed when compiling applications or Mbed TLS. We distinguish three categories of headers:

* Public legacy headers: they contain public interfaces of TF-PSA-Crypto. For example, `"mbedtls/platform.h"` and `"mbedtls/asn1.h"`. Just move them wholesale.
* Exposed headers: these headers do not define any public interface, but they define exposed interfaces, typically types. For example, `"mbedtls/aes.h"` (where the type `mbedtls_aes_context` needs to be exposed, but the functions `mbedtls_aes_xxx()` are only meant to be used inside TF-PSA-Crypto). We will move these headers to a public directory, but ensure that exposed interfaces are clearly documented as such and that private interfaces are not casually usable by applications. See [“Hiding functions in an exposed header”](#hiding-functions-in-an-exposed-header).
* Purely private headers: these headers only define interfaces used to compile TF-PSA-Crypto itself, not interfaces that are exposed or that are used by Mbed TLS. In the long term, most mixed-use headers should be split into an exposed part (typically defining only types and perhaps macros) and a private part.

### Analysis of legacy crypto headers

#### Table of legacy crypto headers

The following table lists the headers that, as of the repository split, are located in `tf-psa-crypto/drivers/builtin/include/mbedtls/`. This is essentially the crypto or platform headers formerly in `include/mbedtls/` in Mbed TLS.

| Header | Function prefix | Fate | Notes |
| ------ | --------------- | ---- | ----- |
| `aes.h` | `mbedtls_aes_` | Expose | [context types](#headers-with-context-types) |
| `aria.h` | `mbedtls_aria_` | Expose | [context types](#headers-with-context-types) |
| `asn1.h` | `mbedtls_asn1_` | Public | [cryptography-adjacent](#cryptography-adjacent-headers) |
| `asn1write.h` | `mbedtls_asn1_write_` | Public | [cryptography-adjacent](#cryptography-adjacent-headers) |
| `base64.h` | `mbedtls_base64_` | TBD | [Base64 and PEM](#base64-and-pem) |
| `bignum.h` | `mbedtls_mpi_` | Expose | [context types](#headers-with-context-types) |
| `block_ciper.h` | `mbedtls_block_cipher_` | Expose | [context types](#headers-with-context-types) |
| `build_info.h` | `MBEDTLS_` | Exposed | [can be made fully private](#headers-that-can-be-made-fully-private) |
| `camellia.h` | `mbedtls_camellia_` | Expose | [context types](#headers-with-context-types) |
| `ccm.h` | `mbedtls_ccm_` | Expose | [context types](#headers-with-context-types) |
| `chacha20.h` | `mbedtls_chacha20_` | Expose | [context types](#headers-with-context-types) |
| `chachapoly.h` | `mbedtls_chachapoly_` | Expose | [context types](#headers-with-context-types) |
| `cipher.h` | `mbedtls_cipher_` | Expose | [context types](#headers-with-context-types) |
| `cmac.h` | `mbedtls_cipher_cmac_` | Expose | [context types](#headers-with-context-types) |
| `config_adjust_*.h` | N/A | Exposed | [Only for exposed macros ](#headers-that-remain-public-for-exposed-macros) |
| `config_psa.h` | N/A | Exposed | [Only for exposed macros ](#headers-that-remain-public-for-exposed-macros) |
| `constant_time.h` | `mbedtls_ct_` | Public | [cryptography-adjacent](#cryptography-adjacent-headers) |
| `ctr_drbg.h` | `mbedtls_ctr_drbg_` | Private | [RNG header privatization](#rng-header-privatization) |
| `des.h` | `mbedtls_des_` | Expose | [context types](#headers-with-context-types) |
| `dhm.h` | `mbedtls_dhm_` | Private | [can be made fully private](#headers-that-can-be-made-fully-private) |
| `ecdh.h` | `mbedtls_ecdh_` | Expose | [context types](#headers-with-context-types) |
| `ecdsa.h` | `mbedtls_ecdsa_` | Expose | [context types](#headers-with-context-types) |
| `ecjpake.h` | `mbedtls_ecjpake_` | Expose | [context types](#headers-with-context-types) |
| `ecp.h` | `mbedtls_ecp_` | Expose | [context types](#headers-with-context-types) |
| `entropy.h` | `mbedtls_entropy_` | Private | [RNG header privatization](#rng-header-privatization) |
| `error_common.h` | `mbedtls_*err*` | Private | TODO |
| `gcm.h` | `mbedtls_gcm_` | Expose | [context types](#headers-with-context-types) |
| `hkdf.h` | `mbedtls_hkdf_` | Delete | https://github.com/Mbed-TLS/mbedtls/issues/9150 |
| `hmac_drbg.h` | `mbedtls_hmac_drbg_` | Private | [can be made fully private](#headers-that-can-be-made-fully-private) with a little work for [RNG header privatization](#rng-header-privatization) |
| `lms.h` | `mbedtls_lms_` | Public | [no PSA equivalent](#cryptographic-mechanisms-with-no-PSA-equivalent) |
| `md.h` | `mbedtls_md_` | Expose | [context types](#headers-with-context-types), but likely [Public hash-only `md.h`](#public-hash-only-md.h) |
| `md5.h` | `mbedtls_md5_` | Expose | [context types](#headers-with-context-types) |
| `memory_buffer_alloc.h` | `mbedtls_memory_buffer_alloc_` | Public | [Platform headers](#platform-headers) |
| `nist_kw.h` | `mbedtls_nist_kw_` | Public | [no PSA equivalent](#cryptographic-mechanisms-with-no-PSA-equivalent) |
| `oid.h` | `mbedtls_oid_` | Private | [OID interface](#oid-interface) |
| `pem.h` | `mbedtls_pem_` | TBD | [Base64 and PEM](#base64-and-pem) |
| `pk.h` | `mbedtls_pk_` | Public | [cryptography-adjacent](#cryptography-adjacent-headers) |
| `pkcs12.h` | `mbedtls_pkcs12_` | Private | [can be made fully private](#headers-that-can-be-made-fully-private) |
| `pkcs5.h` | `mbedtls_pkcs5_` | Private | [can be made fully private](#headers-that-can-be-made-fully-private) |
| `platform.h` | `mbedtls_platform_` | Public | [Platform headers](#platform-headers) |
| `platform_time.h` | `mbedtls_*time*` | Public | [Platform headers](#platform-headers) |
| `platform_util.h` | `mbedtls_platform_` | Public | [Platform headers](#platform-headers) |
| `poly1305.h` | `mbedtls_poly1305_` | Expose | [context types](#headers-with-context-types) |
| `private_access.h` | N/A | Exposed | [Only for exposed macros ](#headers-that-remain-public-for-exposed-macros) |
| `psa_util.h` | N/A | Public | [Evolution of `psa_util.h`](#evolution-of-psa-util.h) |
| `ripemd160.h` | `mbedtls_ripemd160_` | Expose | [context types](#headers-with-context-types) |
| `rsa.h` | `mbedtls_rsa_` | Private | [can be made fully private](#headers-that-can-be-made-fully-private) with a little work (TODO) |
| `sha1.h` | `mbedtls_sha1_` | Expose | [context types](#headers-with-context-types) |
| `sha256.h` | `mbedtls_sha256_` | Expose | [context types](#headers-with-context-types) |
| `sha3.h` | `mbedtls_sha3_` | Expose | [context types](#headers-with-context-types) |
| `sha512.h` | `mbedtls_sha512_` | Expose | [context types](#headers-with-context-types) |
| `threading.h` | `mbedtls_threading_` | Public | [Platform headers](#platform-headers) |

#### Cryptographic mechanisms with no PSA equivalent

The header files listed in this section define cryptographic mechanisms which do not currently fit well in the PSA API, are useful, and have an acceptable ad hoc interface. We will therefore keep this interface in TF-PSA-Crypto 1.x, possibly with minor tweaks to make them fit a PSA-only API. They may evolve later in the life of TF-PSA-Crypto 1.x.

* `lms.h`: The PSA API does not support stateful signatures yet. This is planned, but the API design is still under discussion. This is a critical feature in TF-A, hence considered necessary in the TF-PSA-Crypto MVP.
* `nist_kw.h`: The PSA API does not have an encoding for KW. It is under discussion, but it is mostly used to wrap key material or blobs containing key material, rather than to directly manipulate text, which complicates the API design. This is a request from many silicon vendors, hence considered necessary in the TF-PSA-Crypto MVP.

#### Cryptography-adjacent headers

The following header files define cryptography-adjacent interfaces which we have no plans to replace.

* `asn1.`, `asn1write.h`: ASN.1, needed for key parsing/writing as well as for X.509.
* `constant_time.h`: This header defines `mbedtls_ct_memcmp()` which is in the public API because it is useful to application code (including but not limited to the TLS layer in Mbed TLS).
* `pk.h`: There is no equivalent PSA API. (One is planned, but the design won't be ready until after 1.0.) This is critical for parsing and writing keys. We plan to keep parts of the existing `pk.h` for parsing, writing and signature, and to remove `mbedtls_pk_type_t`, encrypt/decrypt and a few other bits. For 0ε, `pk.h` goes into the public category, and we will remove parts of it. Continued in https://github.com/Mbed-TLS/mbedtls/issues/8452 .

We will therefore keep those headers public in TF-PSA-Crypto 0ε and 1.x.

#### Base64 and PEM

Base64 and PEM are cryptography-adjacent interfaces which we have no plans to replace. In particular, they are outside the scope of PSA APIs.

PEM is used:

* Inside the crypto library, to parse and write keys.
* Inside the Mbed TLS library, to parse and write X.509 objects.
* In application code, very occasionally. (Examples: [Fire-evacuation-guidance-system-IoT](https://github.com/2nd-Chance/Fire-evacuation-guidance-system-IoT/blob/33031a8255fe1ae516ddd58f1baa808801cd3abf/iotivity/resource/csdk/security/src/credresource.c#L3185) (dead project), [SiLabs Bluetooth attestation server](https://github.com/SiliconLabs/bluetooth_applications/blob/3eb0f3c9e234ada1f10714fb9376fcbc8e95807f/bluetooth_secure_attestation/bt_secure_attestation_server/src/ecdh_util3.c#L375))

The use of PEM inside the Mbed TLS is intrinsic. It doesn't leak through the API of Mbed TLS, but Mbed TLS cannot be implemented without PEM. This is different from other private modules that Mbed TLS currently calls internally, but will no longer need to call once Mbed TLS has fully migrated to PSA. Thus, in the long term, TF-PSA-Crypto needs to expose its PEM API to Mbed TLS. (We reject the hypotheses of independent PEM implementations, or of making PEM its own library, as too much maintenance work.)

The current PEM interface is unsatisfactory. We would like to improve it (https://github.com/Mbed-TLS/mbedtls/issues/9374) but it is unlikely that we will have enough bandwidth to do so before the 1.0 release. We need to make the PEM interface public to reach the milestone where Mbed TLS stops relying on private interfaces of TF-PSA-Crypto. We can choose to make it public now, or wait until later. Waiting is only advantageous if we believe that we will have enough bandwidth to actually clean up the PEM interface.

Base64 is used:

* Inside the crypto library, to implement PEM.
* In the `pem2der` sample program.
* In Mbed TLS SSL test programs, for context serialization. (It's not clear to me why we encode in Base64 rather than binary.)
* In the Mbed TLS sample program `ssl_mail_client`, for a tiny bit of SMTP that requires Base64.
* In application code, sometimes, for miscellaneous things, often not directly related to cryptography. On the one hand, many of these uses are out of scope. On the other hand, since TF-PSA-Crypto has a Base64 implementation anyway, users who like TF-PSA-Crypto for its small code size would be justifiably disappointed not to have a Base64 interface.

TODO: decide.

#### OID interface

`oid.h` and `MBEDTLS_OID_C` are in charge of defining all the OIDs used internally or by application code. This is a known problem which can result in applications wasting code size on many OIDs that they don't care about. We are planning a redesign: https://github.com/Mbed-TLS/mbedtls/issues/9380 .

At this point, we do not consider this critical for TF-PSA-Crypto 1.0, and we are likely to work on it during the lifetime of TF-PSA-Crypto 1.x. This may change if we reevaluate the priority based on concrete use cases. In the meantime, `oid.h` will become private, but will remain used in Mbed TLS.

#### Platform headers

Due to a lack of bandwidth, we are not planning any major changes to most platform interfaces. As of the 0ε target, the following platform-related headers remain public.

* `memory_buffer_alloc.h`: a feature used by some applications, with close to 0 maintenance cost for us.
* `platform.h`, `platform_time.h`, `platform_util.h`: platform abstractions. We would like to adapt them, but we do not think we will have time in before 1.0, so this will have to wait until the next major version.
* `threading.h`: We want to change the threading abstraction, but this is out of scope of the 0ε project. https://github.com/Mbed-TLS/mbedtls/issues/8455

### Plans for hiding

In an exposed header, the minimum work for 0ε is:

* Ensure that exposed interfaces are not listed in the rendered Doxygen documentation.
* Ensure that applications cannot inadvertently call private functions that are declared in exposed headers.

#### TF-PSA-Crypto header locations

We distinguish between three categories of headers:

* Public headers define public, stable APIs.
* Exposed headers define exposed interfaces, as well as private interfaces used by Mbed TLS. They need to be present when building Mbed TLS.
* Private headers are only needed when building TF-PSA-Crypto itself.

The following table summarizes the characteristics of each category.

| Category | Location | In include path? |
| -------- | -------- | ---------------- |
| Public   | `include` | yes |
| Exposed  | `include` | yes except for Doxygen |
| Private  | `drivers/*/include` | only for crypto |

TODO: Task to set up the Doxygen build

#### Hiding functions in an exposed header

For TF-PSA-Crypto 0ε, all private functions defined in private headers will be guarded by `defined(MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS)`. We define this macro when building TF-PSA-Crypto and Mbed TLS, but applications should not define it, and our Doxygen build will not define it.

This is similar to `MBEDTLS_ALLOW_PRIVATE_ACCESS` to “bless” access to structure fields.

Prototype: https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/132

Thus, for the 0ε milestone, in each affected header, we just need to place `#ifdef` guards around the function declarations.

Rationale:

* This is a small amount of work.
* This requires few changes to the code, and they are very localized, so it will not disrupt other work happening in parallel.

TODO: this leaves Doxygen comments around, e.g. `\file` comments and the documentation of exposed types.

#### Separating private interfaces from exposed interfaces

If a private interface of TF-PSA-Crypto is declared in an exposed header, in the medium term, we should move it to a private header. Note that we can only do that if the interface is not called from Mbed TLS code.

At some point, perhaps after the 1.0 release, we expect that all the functions declared in an exposed header will be private and will not be called by Mbed TLS. That point may be reached at different times for different headers. When we reach that point for a header, we can run a script to move the declarations guarded by `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` to a private header file and adjust `#include` directives accordingly.

### Analysis of privatization by header

#### Headers that remain public

The headers listed below declare functionality that has no PSA equivalent and that is desirable in 1.0/4.0. We will just move these headers to the public include directory. We may make further changes to some of these headers, but it is out of scope of this chapter.

```
asn1.h
asn1write.h
base64.h
constant_time.h
lms.h
memory_buffer_alloc.h
nist_kw.h
pem.h
pk.h
platform.h
platform_time.h
platform_util.h
psa_util.h
threading.h
```

#### Headers that remain public for exposed macros

The following headers solely define exposed macros, and must remain exposed. They can be excluded from Doxygen parsing.

```
config_adjust_legacy_from_psa.h
config_adjust_psa_superset_legacy.h
config_adjust_test_accelerators.h
config_psa.h
private_access.h
```

#### Headers with context types

The headers listed below are used in operation context types. The types that they define must remain exposed, and possibly some macros as well. The functions that they declare will be made private by guarding them with `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS`.

```
aes.h
aria.h
bignum.h
block_cipher.h
camellia.h
ccm.h
chacha20.h
chachapoly.h
cipher.h
cmac.h
des.h
ecdh.h
ecdsa.h
ecjpake.h
ecp.h
gcm.h
md.h
md5.h
poly1305.h
ripemd160.h
sha1.h
sha256.h
sha3.h
sha512.h
```

Main loss of functionality:

* Self-test functions. See TODO
* Access to bignum and ECC arithmetic. We've decided that this is acceptable.

Note: see also [Everest](#privatization-of-everest-headers).

#### Headers that can be made fully private

The headers listed below are not used in Mbed TLS, except in places that should be removed and can be removed easily.

```
build_info.h
dhm.h
hmac_drbg.h
pkcs12.h
pkcs5.h
rsa.h
```

Places where some of these headers are used:

* `library/ssl_*.c` (for DHM in TLS 1.2, which is going to be removed: https://github.com/Mbed-TLS/mbedtls/issues/9685)
* `programs/fuzz/fuzz_*key.c` (to fuzz RSA functions that are now private)
* `programs/ssl/ssl_test_lib.c` (HMAC\_DRBG; can move to only using the PSA RNG)
* `programs/test/benchmark.c` (HMAC\_DRBG)
* `programs/test/selftest.c`
* `scripts/data_files/query_config.fmt`

Main loss of functionality:

* Finite-field Diffie-Hellman with arbitrary groups. We've decided that this is acceptable.
* Custom RSA mechanisms. We've decided that this is acceptable.
* PKCS5 and PKCS12 mechanisms except as exposed by the pk module. We've decided that this is acceptable.
* HMAC\_DRBG in itself (i.e. outside of deterministic ECDSA and for the PSA Crypto RNG instance). We intend to restore this functionality through a PSA API, but the API isn't designed yet, so this will happen after 1.0 and not with the existing API.

`drivers/builtin/include/mbedtls/build_info.h` is a special case that exists only as a transition for the sake of our source files contains `#include <mbedtls/build_info.h>` and that must be buildable against either TF-PSA-Crypto or Mbed TLS. It should be removed: https://github.com/Mbed-TLS/mbedtls/issues/9862 .

The [p256-m headers](#privatization-of-p256-m-headers) fall in the same category.

#### Headers that will become private eventually

The headers listed below should be private, but are currently used in Mbed TLS to an extent that makes it hard to remove before the 1.0/4.0 release. As a result, they need to remain visible to Mbed TLS, but should be clearly indicated as not part of the stable API.

```
ctr_drbg.h
entropy.h
error_common.h
oid.h
```

Main loss of functionality:

* CTR\_DRBG in itself (i.e. other than for the PSA Crypto RNG instance). We intend to restore this functionality through a PSA API, but the API isn't designed yet, so this will happen after 1.0 and not with the existing API.
* Direct access to entropy sources. We've decided that this is acceptable.
* The ability to configure entropy sources on a platform. This is not an acceptable loss. In the long term (likely after 1.0), this will be resolved by the PSA crypto random driver API. In the short term, we will expose a modified `mbedtls_hardware_poll()` (https://github.com/Mbed-TLS/mbedtls/issues/9618).

#### Privatization of Everest headers

Everest headers (`drivers/everest/include/everest/include/**/*.h`) contain some exposed types: they are exposed via `mbedtls_ecdh_context` from `mbedtls/ecdh.h` which is exposed via `mbedtls_psa_key_agreement_interruptible_operation_t` indirectly from `psa/crypto.h`. The rest of their content is private (to be consumed only by `ecdh.c`) or internal (to be consumed only by `everest/**/*.c`) definitions.

For 0ε, guard everything that isn't an exposed type (or necessary macros, if any) by `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS`.

#### Privatization of 256-m headers

P256-m headers only declare private functions (called by PSA driver wrappers). They do not expose anything. So they can be made private to TF-PSA-Crypto.

### Renaming mbedtls interfaces that remain public

Some existing `mbedtls_xxx` interfaces declared in `<mbedtls/*.h>` headers will remain public in TF-PSA-Crypto 1.0 (e.g. `mbedtls_asn1_xxx` from `<mbedtls/asn1*.h`, `mbedtls_pk_xxx` from `<mbedtls/pk.h>`). Arguably, since they are no longer in Mbed TLS but in TF-PSA-Crypto, the interfaces should be renamed to `tfc_xxx` in `<tf-psa-crypto/*.h>`.

Prioritization:

* Feature: irrelevant.
* Maintainability: negative, since it would complicate backports.
* Quality: dubious. It's better for new users to have API names that reflect the product names. But it's worse for existing users who would have more code to rewrite.

At the moment, renaming existing interfaces (headers files, types, functions, macros, etc.) is out of scope of 0ε.

## Private interfaces leaking through public interfaces

Public interface elements must be usable without requiring private interfaces. Concretely, a public function must not have an argument type or a return type that uses a private type.

### Legacy type report

Output of `scripts/legacy_report.py -DMBEDTLS_USER_CONFIG_FILE='<../tests/configs/user_config_no_deprecated.h>' -I include -I tf-psa-crypto/include -I tf-psa-crypto/drivers/builtin/include include/mbedtls/*.h tf-psa-crypto/drivers/builtin/include/mbedtls/{asn1.h,asn1write.h,base64.h,constant_time.h,lms.h,memory_buffer_alloc.h,nist_kw.h,pem.h,pk.h,platform.h,platform_time.h,platform_util.h,psa_util.h,threading.h}` from https://github.com/gilles-peskine-arm/mbedtls/tree/legacy-unstable-headers-detect

```
tf-psa-crypto/drivers/builtin/include/mbedtls/pk.h:1035:36: mbedtls_pk_rsa#return: mbedtls_rsa_context *
tf-psa-crypto/drivers/builtin/include/mbedtls/pk.h:1058:36: mbedtls_pk_ec#return: mbedtls_ecp_keypair *
tf-psa-crypto/drivers/builtin/include/mbedtls/asn1.h:543:39: mbedtls_asn1_get_mpi#3=X: mbedtls_mpi *
include/mbedtls/ssl_ticket.h:126:52: mbedtls_ssl_ticket_setup#4=cipher: mbedtls_cipher_type_t
tf-psa-crypto/drivers/builtin/include/mbedtls/asn1write.h:104:47: mbedtls_asn1_write_mpi#3=X: const mbedtls_mpi *
tf-psa-crypto/drivers/builtin/include/mbedtls/nist_kw.h:78:48: mbedtls_nist_kw_setkey#2=cipher: mbedtls_cipher_id_t
tf-psa-crypto/drivers/builtin/include/mbedtls/psa_util.h:87:64: mbedtls_ecc_group_to_psa#1=grpid: mbedtls_ecp_group_id
tf-psa-crypto/drivers/builtin/include/mbedtls/psa_util.h:102:22: mbedtls_ecc_group_from_psa#return: mbedtls_ecp_group_id
```

### Private types in `pk.h`

`pk.h` only exposes private types through deprecated functions which will be removed from the [Shrunk-down `pk.h`](#shrunk-down-pk.h).

### Private types in `asn1.h` and `asn1write.h`

The ASN.1 interfaces use `mbedtls_mpi` for INTEGER parsing/writing. This must change to a byte array. This is filed as https://github.com/Mbed-TLS/mbedtls/issues/9373 and https://github.com/Mbed-TLS/mbedtls/issues/9372 .

### Private types in `nist_kw.h`

`nist_kw.h` must switch from a legacy cipher ID to a PSA key type: https://github.com/Mbed-TLS/mbedtls/issues/9382.

### Private types in `psa_util.h`

The functions `mbedtls_ecc_group_to_psa()` and mbedtls_ecc_group_from_psa()` are no longer relevant for public use since the legacy side of the conversion is no longer a public interface. They are not used in Mbed TLS. They should be moved to an internal header.

### Private types in `ssl_ticket.h`

`ssl_ticket.h` uses a legacy cipher type to specify the AEAD mechanism to use for tickets. Switch to a PSA key type and algorithm: https://github.com/Mbed-TLS/mbedtls/issues/9874.

### Leaking error codes

TODO

#### Publicly documented private error codes

Output of `grep -P 'MBEDTLS_ERR_(?!ASN1_|BASE64_|LMS_|NET_|NIST_KW_|PEM_|PKCS7_|PK_|PLATFORM_|SSL_|THREADING_|X509_)' include/mbedtls/*.h tf-psa-crypto/drivers/builtin/include/mbedtls/{asn1.h,asn1write.h,base64.h,constant_time.h,lms.h,memory_buffer_alloc.h,nist_kw.h,pem.h,pk.h,platform.h,platform_time.h,platform_util.h,psa_util.h,threading.h}`.

```
include/mbedtls/ssl.h: *                  or a specific MBEDTLS_ERR_XXX code, which will cause
include/mbedtls/ssl.h: *                  a specific MBEDTLS_ERR_XXX code.
include/mbedtls/ssl.h: *                 MBEDTLS_ERR_XXX_ALLOC_FAILED on memory allocation error.
include/mbedtls/ssl_ticket.h: *                  or a specific MBEDTLS_ERR_XXX error code
include/mbedtls/ssl_ticket.h: *                  or a specific MBEDTLS_ERR_XXX error code
include/mbedtls/x509.h: *                  MBEDTLS_ERR_OID_BUF_TOO_SMALL in case of error
include/mbedtls/x509_crt.h: * \return         #MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
tf-psa-crypto/drivers/builtin/include/mbedtls/nist_kw.h: * \return          \c MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA for any invalid input.
tf-psa-crypto/drivers/builtin/include/mbedtls/nist_kw.h: * \return          \c MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE for 128-bit block ciphers
tf-psa-crypto/drivers/builtin/include/mbedtls/nist_kw.h: * \return          \c MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA for invalid input length.
tf-psa-crypto/drivers/builtin/include/mbedtls/nist_kw.h: * \return          \c MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA for invalid input length.
tf-psa-crypto/drivers/builtin/include/mbedtls/nist_kw.h: * \return          \c MBEDTLS_ERR_CIPHER_AUTH_FAILED for verification failure of the ciphertext.
tf-psa-crypto/drivers/builtin/include/mbedtls/pk.h: * \return          #MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
tf-psa-crypto/drivers/builtin/include/mbedtls/pk.h: * \return          #MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
tf-psa-crypto/drivers/builtin/include/mbedtls/psa_util.h: * \return              An `MBEDTLS_ERR_ENTROPY_xxx`,
tf-psa-crypto/drivers/builtin/include/mbedtls/psa_util.h: *                      `MBEDTLS_ERR_CTR_DRBG_xxx` or
tf-psa-crypto/drivers/builtin/include/mbedtls/psa_util.h: *                      `MBEDTLS_ERR_HMAC_DRBG_xxx` on error.
```

This tells us which error codes are documented in public headers but defined in private headers. Note that there are likely to be many error codes that are not specifically documented (or only vaguely, e.g. “a low-level error code”), but in such cases we can change which error is returned in a minor release.

## Changes to compilation options

TODO

## Changes to public crypto headers

### Public hash-only `md.h`

To be considered for 1.0: make a subset of `md.h` public. Only hashes, not HMAC.

Reasons to do this:

* The upfront cost is small: we can take the existing `md.h` and just remove the HMAC-related code and some of the metadata-related interfaces.
* As a thin wrapper over PSA (we would not keep direct calls to low-level modules), the maintenance cost is very small.
* It is used in a very large number of places, both in Mbed TLS and in third-party code. Keeping it around will both save us work during the lifetime of TF-PSA-Crypto 1.x and Mbed TLS 4.x, and facilitate the transition for our users.

https://github.com/Mbed-TLS/mbedtls/issues/8450

### Shrunk-down `pk.h`

TODO

https://github.com/Mbed-TLS/mbedtls/issues/8452
