### Changes to MD and PK

### TODO: restricted md

### TODO: changed pk

### Removed support for RSA encryption/decryption in PK

The two functions `mbedtls_pk_decrypt()` and `mbedtls_pk_encrypt()` have been
removed. Instead the functions `psa_asymmetric_encrypt()` and
`psa_asymmetric_decrypt()` should be used.

If you have your key material as a PK context, you can convert it to a PSA key
using `mbedtls_pk_import_into_psa()`, see `psa-transition.md` for details.

### Create new type `mbedtls_pk_sigalg_t` to replace `mbedtls_pk_type_t`

A new type `mbedtls_pk_sigalg_t` has been created to replace `mbedtls_pk_type_t` and `mbedtls_pk_type_t` is now private and should not be used. Most of the legacy parameters have an equivilent in the new enum, these corespond to the same value to maintain compatibility. The only exceptions are `MBEDTLS_PK_ECKEY`, `MBEDTLS_PK_ECKEY_DH`  and `MBEDTLS_PK_OPAQUE`, which are now private values and should not be used.

As part of this change `mbedtls_pk_sign_ext()` has been updated to use the new mbedtls_pk_sigalg_t type.

### Privatisation of PK symbols

The following PK synbols are now private and should no longer be used:

'mbedtls_pk_rsassa_pss_options'
'mbedtls_pk_debug_type'
'mbedtls_pk_debug_item'
'MBEDTLS_PK_DEBUG_MAX_ITEMS'
'mbedtls_pk_info_from_type()'
'mbedtls_pk_setup()'
'mbedtls_pk_get_len()'
'mbedtls_pk_can_do()'
'mbedtls_pk_can_do_ext()'
'mbedtls_pk_debug()'
'mbedtls_pk_get_name()'
'mbedtls_pk_get_type()'
'mbedtls_pk_rsa()'
'mbedtls_pk_ec()'
'mbedtls_pk_parse_subpubkey()'
'mbedtls_pk_write_pubkey()'

### Modifications to `mbedtls_pk_context`

The field `ec_bits` has been replaced by bits in the `mbedtls_pk_context`, all future uses of this struct should now use bits instead of `ec_bits`. Two additional fields have been added to the `mbedtls_pk_context`, `rsa_padding' and `rsa_hash_alg`. `rsa_padding' needs to be set to one of the two values in the enum 'mbedtls_pk_rsa_padding_t', either `MBEDTLS_PK_RSA_PKCS_V15` or `MBEDTLS_PK_RSA_PKCS_V21`. rsa_hash_alg needs to be set to a valid psa_algorithm_t.
//bjwt TODO: check this with Valerio when he gets back.

### Changes to wrapping of PSA keys

The function `mbedtls_pk_setup_opaque()` has been removed and replaced by `mbedtls_pk_wrap_psa()`, all current uses of can be directly converted to the new function.

### Changes to `mbedtls_pk_verify_ext()`

The options parameter has been removed from the `mbedtls_pk_verify_ext()`, the options was already ignored and is no longer required with the new PSA API.

### Removals of `mbedtls_pk_decrypt()` and `mbedtls_pk_encrypt()`

`mbedtls_pk_decrypt()` and `mbedtls_pk_encrypt()` have been removed from the public API. Previous uses of these functions should be converted to the PSA API functions `psa_asymmetric_decrypt()` and `psa_asymmetric_encrypt()`.
