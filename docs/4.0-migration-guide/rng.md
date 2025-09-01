## Random number generation configuration
TF-PSA-Crypto does not expose a random number generation interface to applications. The entropy, CTR_DRBG, and HMAC_DRBG modules from Mbed TLS 3.6 are now for internal use only. As a result, their configuration has been updated, both to simplify them and to prepare for PSA entropy and random number generation drivers, which will be introduced in a future minor release.

The overall structure of the random number generator in TF-PSA-Crypto remains the same as in Mbed TLS 3.x. It consists of either:
* an external random number generator (when `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` is enabled), or
* a deterministic random number generator (CTR_DRBG or HMAC_DRBG) seeded with entropy by the entropy module.

If you have access to a fast, cryptographic-quality source of random data, enable `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` and provide the corresponding access function (see the `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` documentation).

Otherwise, select at least one entropy source (see the "Entropy configuration" section) and at least one DRBG module by enabling `MBEDTLS_CTR_DRBG_C` or `MBEDTLS_HMAC_DRBG_C`. Note that the entropy module is now automatically enabled when `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` is disabled.

The built-in random number generator is now configured through three options:
* `MBEDTLS_PSA_CRYPTO_RNG_HASH`: Selects the hash algorithm used by the entropy and HMAC_DRBG modules. This option replaces both `MBEDTLS_PSA_HMAC_DRBG_MD_TYPE` and `MBEDTLS_ENTROPY_FORCE_SHA256`.
* `MBEDTLS_PSA_RNG_RESEED_INTERVAL`: Sets the reseed interval for both CTR_DRBG and HMAC_DRBG. It replaces `MBEDTLS_CTR_DRBG_RESEED_INTERVAL` and `MBEDTLS_HMAC_DRBG_RESEED_INTERVAL`.
* `MBEDTLS_PSA_CRYPTO_RNG_STRENGTH`: Specifies the security strength in bits. The default is 256 bits. If you previously enabled `MBEDTLS_CTR_DRBG_USE_128_BIT_KEY` in Mbed TLS 3.6, you should now set `MBEDTLS_PSA_CRYPTO_RNG_STRENGTH` to 128, although this is not recommended.

The following Mbed TLS 3.6 options do not have any direct equivalent in TF-PSA-Crypto, see 0e-plans.md for more information:
`MBEDTLS_ENTROPY_C`, `MBEDTLS_ENTROPY_MAX_GATHER`, `MBEDTLS_ENTROPY_MAX_SOURCES`, `MBEDTLS_CTR_DRBG_ENTROPY_LEN`, `MBEDTLS_CTR_DRBG_MAX_INPUT`, `MBEDTLS_CTR_DRBG_MAX_REQUEST`, `MBEDTLS_CTR_DRBG_MAX_SEED_INPUT`, `MBEDTLS_HMAC_DRBG_MAX_INPUT`, `MBEDTLS_HMAC_DRBG_MAX_REQUEST` and `MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT`.
