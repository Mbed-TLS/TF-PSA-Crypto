#ifndef MBEDTLS_PSA_CRYPTO_ASYNC_CURVES_H
#define MBEDTLS_PSA_CRYPTO_ASYNC_CURVES_H

#include "mbedtls/psa_crypto_async_hardware.h"

#include <psa/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Resolve standardized prime-curve parameters for an async hardware request. */
const mbedtls_psa_async_crypto_prime_curve_t *
mbedtls_psa_async_crypto_resolve_prime_curve(psa_key_type_t key_type, size_t key_bits);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PSA_CRYPTO_ASYNC_CURVES_H */
