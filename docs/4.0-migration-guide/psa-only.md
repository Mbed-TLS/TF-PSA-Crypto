## PSA as the only cryptography API

The PSA Crypto API is now the only API for cryptographic primitives.

For general guidance on migrating to the PSA Crypto API, consult the
[PSA transition guide](../psa-transition.md). Note that most of the suggested migrations also work in the Mbed TLS 3.6 long-time support branch, provided that the library is configured suitably (`MBEDTLS_USE_PSA_CRYPTO` and `MBEDTLS_PSA_CRYPTO_CONFIG` enabled).

### Impact on application code

The PK module uses PSA for cryptographic operations. This corresponds to the behavior of Mbed TLS 3.x when `MBEDTLS_USE_PSA_CRYPTO` is enabled. In effect, `MBEDTLS_USE_PSA_CRYPTO` is now always enabled.

`psa_crypto_init()` must be called before performing any cryptographic operation.

A few functions take different parameters to migrate them to the PSA API. See “[Function prototype changes](#function-prototype-changes)”.

### Impact on the library configuration

The choice of supported cryptographic mechanisms is now based on `PSA_WANT_xxx` macros instead of legacy configuration macros such as `MBEDTLS_RSA_C`, `MBEDTLS_PKCS1_V15`, etc. This corresponds to the behavior of Mbed TLS 3.x when `MBEDTLS_PSA_CRYPTO_CONFIG` is enabled. In effect, `MBEDTLS_PSA_CRYPTO_CONFIG` is now always enabled.

For information on which configuration macros are affected and their new PSA equivalent, consult the [PSA transition guide](../psa-transition.md).

### Low-level crypto functions are no longer part of the public API

Low-level crypto functions, that is, all non-PSA crypto functions except a few
that don't have a proper PSA replacement yet, have been removed from the public
API.

The following header files, and their former content, are no longer available.

```
everest/Hacl_Curve25519.h
everest/everest.h
everest/kremlib.h
everest/kremlib/*.h
everest/kremlin/*.h
everest/kremlin/internal/*.h
everest/vs2013/*.h
everest/x25519.h
mbedtls/aes.h
mbedtls/aria.h
mbedtls/bignum.h
mbedtls/block_cipher.h
mbedtls/camellia.h
mbedtls/ccm.h
mbedtls/chacha20.h
mbedtls/chachapoly.h
mbedtls/cipher.h
mbedtls/cmac.h
mbedtls/ctr_drbg.h
mbedtls/des.h
mbedtls/ecdh.h
mbedtls/ecdsa.h
mbedtls/ecjpake.h
mbedtls/ecp.h
mbedtls/entropy.h
mbedtls/gcm.h
mbedtls/hmac_drbg.h
mbedtls/md5.h
mbedtls/pkcs12.h
mbedtls/pkcs5.h
mbedtls/poly1305.h
mbedtls/ripemd160.h
mbedtls/rsa.h
mbedtls/sha1.h
mbedtls/sha256.h
mbedtls/sha3.h
mbedtls/sha512.h
```

If your application was using functions from these headers, please see
[`docs/psa-transition.md`](../psa-transition.md) for ways to migrate to
the PSA API instead.

Some of the associated types still need to be visible to the compiler. For example, `mbedtls_aes_context` is used to define `psa_cipher_operation_t`. These types are still available when building application code, but we recommend that you no longer use them directly. The structure, the semantics and even the existence of these types may change without notice.

### Removal of alternative cryptographic module implementations

TF-PSA-Crypto no longer supports replacing a whole cryptographic module or an individual cryptographic function by defining a macro `MBEDTLS_xxx_ALT` and providing a custom implementation of the same interface. Instead, use PSA accelerator drivers.

The PK module no longer supports `MBEDTLS_PK_RSA_ALT`. Instead, for opaque keys (RSA or otherwise), use PSA secure element drivers.
