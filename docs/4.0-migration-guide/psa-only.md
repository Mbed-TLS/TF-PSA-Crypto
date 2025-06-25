## PSA as the only cryptography API

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
