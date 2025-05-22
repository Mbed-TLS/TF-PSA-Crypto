## Removed support for RSA encryption/decryption in PK

The two functions `mbedtls_pk_decrypt()` and `mbedtls_pk_encrypt()` have been
removed. Instead the functions `psa_asymmetric_encrypt()` and
`psa_asymmetric_decrypt()` should be used.

If you have your key material as a PK context, you can convert it to a PSA key
using `mbedtls_pk_import_into_psa()`, see `psa-transition.md` for details.


