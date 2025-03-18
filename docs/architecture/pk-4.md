The PK module in TF-PSA-Crypto 1 and Mbed TLS 4
===============================================

The goal of this document is to describe the evolution of the `pk.h` interface from Mbed TLS 3.x going into TF-PSA-Crypto 1.0 and Mbed TLS 4.0.

## Requirements

### Project goal

The goal of the PK-4.0 project is to make minimal changes to the `pk.h` interface to make it suitable for TF-PSA-Crypto 1.0, and for consumption in Mbed TLS 4.0. We want to preserve the essential features of PK, while removing aspects of the interface that will make it difficult to finish the migration to PSA, and minimize the amount of work to be done before the 1.0/4.0 releases.

In the short term, before the 1.0/4.0 releases, we will make parts of `pk.h` private, and provide replacements where needed. The goal of the project is to make the desired parts private (i.e. no longer part of the documented API), and to ensure that the replacements are working. The old API can still be used under the hood in Mbed TLS.

In the medium term, in TF-PSA-Crypto 1.x and Mbed TLS 4.x, we will remove the internal uses of private APIs from Mbed TLS and TF-PSA-Crypto, then remove the implementation of those private APIs.

In the long term, we want to fully replace `pk.h` with PSA APIs. This is a work topic for the PSA Crypto API working group. The API design is still at an early stage, far too early to be taken into account here.

### Essential functionality of PK

The following functionality does not exist in PSA, but we consider it absolutely necessary for TF-PSA-Crypto:

* The ability to construct a PSA key from a PK key and vice versa.
* The ability to parse a key in various commonplace formats. These formats include metadata indicating the key type, so this cannot be a simple extension of `psa_import_key`.
* The ability to write a key in various commonplace formats.

In addition, we choose to retain the following functionality, because it is easier to keep it in PK than to reimplement it where it is used:

* A sign/verify interface, using a signature format that's ready for X.509 and TLS.

Any other functionality in the `pk.h` interface in TF-PSA-Crypto will either be justified by these needs (e.g. metadata queries, object creation and destruction), or left over from Mbed TLS 3.x if there's no particular reason to remove it. Everything else will be made private.

### Functionality that is removed from PK

The following features are deliberately removed from the PK API. (They may remain as private interfaces until TF-PSA-Crypto 1.x.)

* The ability to inspect how data is stored in PK contexts: opaque-or-not, `mbedtls_pk_ec()`, `mbedtls_pk_rsa()`, `mbedtls_pk_get_type()`, `mbedtls_pk_info_t`, etc.
* The ability to construct a PK context manually: `mbedtls_pk_setup()`.
* Direct support for opaque keys (`mbedtls_pk_setup_opaque()`, `mbedtls_pk_setup_rsa_alt()`, etc.). Go via PSA instead.
* The poorly defined type `mbedtls_pk_type_t` and the associated function `mbedtls_pk_can_do()`. Use PSA metadata instead.
* Mechanism names: `mbedtls_pk_get_name()`.
* The RSA-oriented length function: `mbedtls_pk_get_len()`. Use `mbedtls_pk_get_bitlen()`.
* PSS-extended functions: `mbedtls_pk_sign_ext()`, `mbedtls_pk_verify_ext()`. PSA has less flexibility than the PK API. Use PSA APIs to get all the flexibility that PSA can have. Use separate key objects if you need multiple algorithms with the same key (e.g. PKCS#1v1.5 and PSS for a TLS server that supports both TLS 1.2 and 1.3).
* Encrypt/decrypt: `mbedtls_pk_decrypt()`, `mbedtls_pk_encrypt()`. Use PSA.

### Design philosophy for the new PK

We retain the concept of a “PK context”, which can either be empty or contain a public key or contain a key pair. The new PK handles key parsing and writing, and has convenience functions to sign with a key.

A PK context has the following conceptual properties:

* A PSA key type (key pair or public key). This is `PSA_KEY_TYPE_NONE` for an empty context.
* A PSA algorithm used for signing. This is `PSA_ALG_NONE` for an empty context, or a signature algorithm, or a signature wildcard algorithm policy (which specifies a signature mechanism, but leaves a hash algorithm unspecified).
* Key material that matches the key type. This can be directly in the PK object, or indirectly via a PSA key identifier.
* Optionally, an associated PSA key identifier. The PSA key may be owned by the PK context and destroyed when the context is destroyed, or it may be referenced by the PK context and left alone when the context is destroyed.

The PK module does not enforce key policies. In particular, it is possible to copy a PK context into a context with a different signature algorithm.

### Private interfaces

In this document, a ***private*** interfaces is one that is not documented. Applications should not use private interfaces, and we do not promise any kind of stability about them. Mbed TLS can use private interfaces of TF-PSA-Crypto, but in the medium term (over the lifetime of TF-PSA-Crypto 1.x and Mbed TLS 4.x), it should stop doing so. Public interfaces must not rely on private interfaces, for example a private type cannot be used in the prototype of a public functions. However, public types can have a private implementation (we guarantee that the type will keep existing, but it may be implemented differently, typically adding and removing fields in a structure).

An ***internal*** interface is only usable inside TF-PSA-Crypto.

## API elements

### PK context type

#### Keep `mbedtls_pk_context`

We keep `mbedtls_pk_context` largely as it is now. It will be reworked after 1.0 as needed. Keep:

```
mbedtls_pk_context
mbedtls_pk_init()
mbedtls_pk_free()
```

#### Context metadata

We explicitly associate an algorithm with each PK context. This is intended to match the algorithm in the underlying PSA key when there is one. Having an algorithm stored in the context lets us treat PK contexts more uniformly regardless of whether they contain a PSA key or a direct pointer to key material.

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/204): populate the field `pk->psa_algorithm` when populating `pk`. Use the same approach as the existing function `mbedtls_pk_get_psa_attributes()` for a signature usage.

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/204): implement a new function to change the algorithm associated with a PK context:
```
void mbedtls_pk_set_algorithm(mbedtls_pk_context *ctx,
                              psa_algorithm_t alg);
```

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/204): change PK operation functions to honor the algorithm set in the context.

Keep:
```
mbedtls_pk_get_bitlen()
mbedtls_pk_can_do_ext()
```

We keep `mbedtls_pk_can_do_ext()` as is because it's useful to check what a key can do after parsing it. It is partially redundant with `mbedtls_pk_get_psa_attributes()`, but it's sometimes more convenient, already implemented, and easy to implement for any evolution of PK that can accommodate `mbedtls_pk_get_psa_attributes()`.

#### Meaning of `mbedtls_pk_type_t`

`mbedtls_pk_type_t` has several subtly different meanings:

* How the key is represented in a `mbedtls_pk_context`, with additional policy information for EC keys. Can be anything except `MBEDTLS_PK_RSAPSS`.
* Key type from parsing. Can be `MBEDTLS_PK_RSA`, `MBEDTLS_PK_ECKEY` or `MBEDTLS_PK_ECKEY_DH`. Note that obtaining `MBEDTLS_PK_ECKEY_DH` from parsing is fully untested.
* Signature algorithm in X.509. Can be `MBEDTLS_PK_RSA`, `MBEDTLS_PK_RSAPSS` or `MBEDTLS_PK_ECDSA`.
* In invocations of `mbedtls_pk_can_do()`, and possibly elsewhere in local variables or internal functions, it can be a union of two or more of the above.

In TF-PSA-Crypto, we don't want to expose the distinction between `MBEDTLS_PK_OPAQUE` (purely PSA-backed key) and other key types (non-PSA-backed, or partially PSA-backed in the case of ECC keys). We also don't want to guarantee the subtle distinctions between `MBEDTLS_PK_ECKEY`, `MBEDTLS_PK_ECKEY_DH` and `MBEDTLS_PK_ECDSA`. Hence the type `mbedtls_pk_type_t` will become private.

#### Public uses of `mbedtls_pk_type_t` or `mbedtls_pk_get_type()`

Public headers and sample programs are considered public. Library code (including Mbed TLS), test code and test programs are not considered public.

* In X.509 types, to specify an X.509 signature algorithm. See “[New type for signature algorithms](#new-type-for-signature-algorithms)”.
* In several of `programs/pkey/*.c`, to differentiate between RSA and ECC. See “[Use new APIs to distinguish between RSA and ECC in sample programs](#use-new-apis-to-distinguish-between-rsa-and-ecc-in-sample-programs)”.

#### New type for signature algorithms

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/204): Define a new type `mbedtls_pk_sigalg_t` which is a subset of `mbedtls_pk_type_t`, containing only the values that are meaningful as a signature algorithm in an X.509 structure.

```
typedef enum {
    MBEDTLS_PK_SIGALG_NONE = MBEDTLS_PK_NONE,
    MBEDTLS_PK_SIGALG_RSA = MBEDTLS_PK_RSA,
    MBEDTLS_PK_SIGALG_ECDSA = MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_SIGALG_RSASSA_PSS = MBEDTLS_PK_RSASSA_PSS,
} mbedtls_pk_sigalg_t;
```

Keep the same numerical values as `mbedtls_pk_type_t`, so that a `mbedtls_pk_sigalg_t` value can be cast to `mbedtls_pk_type_t` in library code that still uses this deprecated type.

Move `x509*.h` and `oid.h` to the new type.

This task removes the need for `mbedtls_pk_type_t` to be in the public API of Mbed TLS. Follow-up: make it (and `mbedtls_pk_get_type()`) private in “[Privatization](#privatization)”.

`mbedtls_pk_sigalg_t` is an exposed type: it needs to be visible to the C compiler when compiling Mbed TLS, but it isn't part of the documented API, since we aren't planning to write any public function that uses this type. In the long term, X.509 should presumably switch to PSA algorithms.

#### `mbedtls_pk_can_do()`

Remove `mbedtls_pk_can_do()` from the public API.

Everyone should use PSA metadata instead.

#### `mbedtls_pk_get_name()`

PK no longer has a concept of a name for a key type or algorithm.

#### Custom PK context data

PK no longer supports custom setup and inspection of a PK object, thus we remove the following elements from the public API, to be done in “[Privatization](#privatization)”:

* `mbedtls_pk_setup()`. Construct from a PSA key or by parsing instead.
* `mbedtls_pk_ec()`, `mbedtls_pk_rsa()`. All code must also work when a PK context is backed by a PSA key.

#### `mbedtls_pk_check_pair()`

Keep `mbedtls_pk_check_pair()`. It's no burden to implement.

### PSA bridges

The new PK needs to have bridges between PK contexts and PSA keys.

Given a key in one form, there are two ways to obtain a key in the other form:

* Make a copy of the key data, so that the destination object lives independently from the source object. This is far easier to use in terms of resource management. However, it may not be possible if the source object's policy makes it impossible to copy. This can be the case with PSA keys, and also with PK contexts if they wrap around a non-copiable PSA key.
* Create an object that aliases the source object: wrap a PSA key in a PK context, or peek at the underlying PSA key of a PK context. The wrapper/underlying object is only valid as long as the source object is valid. A PK context created by wrapping an existing PSA key does not destroy the PSA key. Resource management is tricky, but this has a low overhead and works for keys whose material cannot be copied.

There is currently no way to access the underlying PSA key of a PK context. A nw function to [access the underlying PSA key of a PK context](#access-the-underlying-psa-key-of-a-pk-context) is not planned for TF-PSA-Crypto 1.0.

#### `mbedtls_pk_get_psa_attributes()`

Keep `mbedtls_pk_get_psa_attributes()`.

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/204): update the documentation of `mbedtls_pk_get_psa_attributes()`.

Notes:

* An ECC public key in SubjectPublicKeyInfo format (possibly embedded in a key pair) can specify one of two algorithms: id-ecPublicKey (allows ECDSA signature) or id-ecDH (should not be used for signature). This is encoded in the old API through the PK type: id-ecDH leads to `MBEDTLS_PK_ECKEY_DH`. This is untested (we have no test key with id-ecDH; backlog issue: https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/206). In the new API, you can find out whether a key had id-ecPublicKey or id-ecDH by looking at the algorithm chosen by `mbedtls_pk_get_psa_attributes()`.

* Arguably, since PK is now specialized towards signatures, we could remove the `usage` argument from `mbedtls_pk_get_psa_attributes()`, and make the function work only for a sign/verify usage. However, I don't think this would be right, especially because PK only handles signature: after parsing a key, to use it for something other than signature, you need to use PSA, which means you need to call `mbedtls_pk_get_psa_attributes()` then `mbedtls_pk_import_into_psa()` to create a PSA key with your desired non-signature algorithm. Also, the usage parameter allows for extracting the public part of a key when you don't know whether you have a public key or a key pair, which is very convenient in some cases such as managing a key store.

#### Copy between PK and PSA

Keep the following functions, which create a PK context from a PSA key and vice versa:
```
mbedtls_pk_import_into_psa()
mbedtls_pk_copy_from_psa()
mbedtls_pk_copy_public_from_psa()
```

#### Wrap a PSA key in PK

There is already a function to wrap a PSA private key in a PK context: `mbedtls_pk_setup_opaque()`. The function's name no longer makes sense, since there is no longer a concept of “opaque” PK contexts, and no longer a ”setup“ operation on PK contexts.

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/204): rename `mbedtls_pk_setup_opaque()` to `mbedtls_pk_wrap_psa()` and adjust the documentation accordingly. (Updating internal references to “opaque” is out of scope and will be done later: [Update terminology from “opaque” to “wrapped”](#update-terminology-from-opaque-to-wrapped).)

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/204): remove mentions of operations other than sign and verify from the documentation.

The current function has some limitations. We should lift them soon (“[Remove limitations of `mbedtls_pk_wrap_psa()`](#remove-limitations-of-mbedtls_pk_wrap_psa)”), but it isn't a deal breaker for TF-PSA-Crypto 1.0.

### Key parsing and writing

Keep:
```
mbedtls_pk_parse_key()
mbedtls_pk_parse_public_key()
mbedtls_pk_write_key_der()
mbedtls_pk_write_pubkey_der()
mbedtls_pk_write_pubkey_pem()
mbedtls_pk_write_key_pem()
```

Keep:
```
mbedtls_pk_parse_keyfile()
mbedtls_pk_parse_public_keyfile()
```

### Signature conveniences

#### Basic signature functionality

Keep the following:
```
MBEDTLS_PK_SIGNATURE_MAX_SIZE
mbedtls_pk_verify()
mbedtls_pk_sign()
```

ACTION (https://github.com/Mbed-TLS/mbedtls/issues/5544): remove `MBEDTLS_ERR_PK_SIG_LEN_MISMATCH`. It's mostly useless for RSA, and it doesn't even work for ECDSA.

#### Restartable signature functionality

It's more convenient to keep using PK for restartable signature in X.509, for the same reason as non-restartable signature. So restartable PK should keep existing, so we might as well keep it public.

Keep:
```
mbedtls_pk_restart_ctx
mbedtls_pk_restart_init()
mbedtls_pk_restart_free()
mbedtls_pk_verify_restartable()
mbedtls_pk_sign_restartable()
```

No changes to the function's implementation: restartable behavior is only available for built-in ECDSA when built-in restartable ECC is enabled, but the function always works (in a non-restartable way if restartable is not possible).

There is a risk that the current API will be suboptimal when we port its implementation. However, I think this risk is low, since this is basically the interface that X.509 likes, and the primary goal of PK is to support X.509. If X.509 needs more adaptation than expected to migrate to PSA, PK is the natural place for the adaptation code.

### Removals

#### Privatization

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/204): Move all private API elements to an private header:

```
mbedtls_pk_type_t
mbedtls_pk_rsassa_pss_options
mbedtls_pk_debug_type
mbedtls_pk_debug_item
MBEDTLS_PK_DEBUG_MAX_ITEMS
mbedtls_pk_info_from_type()
mbedtls_pk_setup()
mbedtls_pk_get_len()
mbedtls_pk_can_do()
mbedtls_pk_verify_ext()
mbedtls_pk_sign_ext()
mbedtls_pk_decrypt()
mbedtls_pk_encrypt()
mbedtls_pk_debug()
mbedtls_pk_get_name()
mbedtls_pk_get_type()
mbedtls_pk_rsa()
mbedtls_pk_ec()
mbedtls_pk_parse_subpubkey()
mbedtls_pk_write_pubkey()
```

Follow-up: [Make private API elements internal](#make-private-api-elements-internal)

#### Documentation update after privatization

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/205): remove all mentions of private API elements from the public documentation.

This includes both direct mentions (where a type name, constant name or function name is mentioned), and indirect mentions (e.g. “verify\_ext”, “context has been set up”).

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/207): update unit tests to validate the new interfaces.

#### Remove RSA-ALT

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/208): Remove the option `MBEDTLS_PK_RSA_ALT_SUPPORT` and all code guarded by it, as well as `MBEDTLS_PK_RSA_ALT`.

### Documentation updates

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/209): update the PSA transition guide.

ACTION (https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/209): write changelog entries.

## Open questions

### Parsing and writing

#### Remove file parsing functions?

Should we remove the file parsing functions `mbedtls_pk_parse_keyfile()` and `mbedtls_pk_parse_public_keyfile()`? They look misplaced in a library that generally doesn't access files. But it isn't really difficult to keep them.

These functions are used in test code and sample programs.

### Resource management

#### Access the underlying PSA key of a PK context

Should we provide a function to access the underlying PSA key of a PSA context, if there is one?

This would be new work, and does not seem to be needed at the moment. If the PK context was created from a PSA key, the application might as well use the original PSA key. If the PK context was created by parsing, `mbedtls_pk_import_into_psa()` works, and does not require a special case if the PK context does not have an underlying PSA key.

If we add this in the future, it will be considerably easier if all PK contexts have an underlying PSA key, or at least all PK contexts containing a private key have an underlying PSA key.

## Later tasks

The tasks described in this section do not need to be done before the 1.0/4.0 release. This section is incomplete.

### Missing functionality

#### Remove limitations of `mbedtls_pk_wrap_psa()`

Remove the limitations of wrapped keys:

* Implement verify for wrapped RSA keys.
* Implement check-pair for wrapped RSA keys.

### Migrate library and test code

#### Update terminology from “opaque” to “wrapped”

Update the library code to change the obsolete terminology “opaque” (as in e.g. `MBEDTLS_PK_OPAQUE`) to “wrapped”.

Originally, PK contexts could wrap a PSA key in order to support non-exportable keys kept in a secure partition, using a PSA implementation with client-server isolation. Thus the useful purpose of wrapping a PSA key was to make the key opaque, hence the name. In TF-PSA-Crypto, we plan to evolve to making PK keys contain a PSA key in more situations. What will matter is whether the underlying PSA key is owned by the PK context (and destroyed when the context is freed), or not (thus surviving when the context is freed). A key owned by the PK context could still potentially be opaque. Hence the distinction should be between _wrapped_ and _owned_ PSA keys.

#### Retire `MBEDTLS_PK_ECDSA`

It is no longer possible to construct a PK object with the legacy type `MBEDTLS_PK_ECDSA`. So get rid of the code that handles it, and remove `MBEDTLS_PK_ECDSA`.

#### Replace all uses of `mbedtls_pk_type_t`, `mbedtls_pk_get_type()` and `mbedtls_pk_can_do()` in X.509 library and test code

#### Replace all uses of `mbedtls_pk_type_t`, `mbedtls_pk_get_type()` and `mbedtls_pk_can_do()` in TLS library and test code

#### Get rid of `mbedtls_pk_can_do()`

#### Get rid of `mbedtls_pk_info`

Dispatch based on an enum rather than a method table. This simplifies the code.

#### Make `mbedtls_pk_type_t` internal

Goal: `mbedtls_pk_type_t` is only used inside `pk*.c` and in PK unit tests. It may still be exposed in the `mbedtls_pk_context` type.

### Migrate sample programs

#### Use new APIs to distinguish between RSA and ECC in sample programs

### Removals

#### Make private API elements internal

As much as possible, make private API elements internal. That is, instead of being declared in a public header, declare them in `pk_internal.h` which should not be included by anything except `pk*.c` and PK unit tests.

This should ideally be done little by little, when we eliminate the uses of these elements in Mbed TLS.

#### Remove deprecated former API elements once they are no longer used
