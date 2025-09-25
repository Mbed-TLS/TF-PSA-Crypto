## Feature removals

### Removal of self-test interfaces

TF-PSA-Crypto 1.0 does not provide a ready-made self-test interface; one may be added in a future version of the library.

If you need self-tests for compliance, you may perform them by invoking normal API functions with sample data.

As a consequence, the compilation option `MBEDTLS_SELF_TEST` does not provide direct benefits in TF-PSA-Crypto 1.0. However, it allows the sample program `programs/test/selftest.c` in Mbed TLS to run self tests of cryptographic mechanisms.

### Removed hardware support

Acceleration for VIA Padlock (`MBEDTLS_PADLOCK_C`) is no longer provided.

The deprecated and incomplete support for dynamic registration of secure element drivers (`MBEDTLS_PSA_CRYPTO_SE_C`) has been removed. Use compile-time secure element drivers instead.

See also [the removal of ALT interfaces](#removal-of-alternative-cryptographic-module-implementations).

### Removed obsolete cryptographic mechanisms

Some obsolescent cryptographic mechanisms have been removed:

* The library no longer supports DES (including 3DES). All supported block ciphers now have 128-bit blocks.
* The library no longer supports elliptic curves whose size is 224 bits or less. The following curves are no longer supported: secp192r1, secp192k1, secp224k1, secp224r1. Use larger curves such as secp256r1.
