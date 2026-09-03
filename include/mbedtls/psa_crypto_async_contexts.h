#ifndef MBEDTLS_PSA_CRYPTO_ASYNC_CONTEXTS_H
#define MBEDTLS_PSA_CRYPTO_ASYNC_CONTEXTS_H

#include "mbedtls/psa_crypto_async_provider.h"

#include <stdint.h>

typedef struct mbedtls_psa_async_crypto_driver_operation_s {
    mbedtls_psa_async_crypto_operation_t provider_operation;
} mbedtls_psa_async_crypto_driver_operation_t;

typedef enum mbedtls_psa_async_crypto_signature_stage_e {
    MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE_INACTIVE = 0,
    MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE_RANDOM = 1,
    MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE = 2,
} mbedtls_psa_async_crypto_signature_stage_t;

typedef struct mbedtls_psa_async_crypto_signature_operation_s {
    mbedtls_psa_async_crypto_provider_t *provider;
    mbedtls_psa_async_crypto_operation_t provider_operation;
    mbedtls_psa_async_crypto_request_t request;
    const mbedtls_psa_async_crypto_prime_curve_t *curve;
    size_t key_size;
    size_t hash_size;
    psa_key_type_t key_type;
    psa_algorithm_t algorithm;
    uint32_t num_ops;
    uint8_t random_attempts;
    mbedtls_psa_async_crypto_signature_stage_t stage;
    uint8_t key[133];
    uint8_t hash[64];
    uint8_t nonce[66];
    uint8_t signature[132];
} mbedtls_psa_async_crypto_signature_operation_t;

typedef struct mbedtls_psa_async_crypto_key_agreement_operation_s {
    mbedtls_psa_async_crypto_provider_t *provider;
    mbedtls_psa_async_crypto_operation_t provider_operation;
    mbedtls_psa_async_crypto_request_t request;
    const mbedtls_psa_async_crypto_prime_curve_t *curve;
    uint32_t num_ops;
    uint8_t shared_secret[66];
} mbedtls_psa_async_crypto_key_agreement_operation_t;

typedef struct mbedtls_psa_async_crypto_export_public_key_operation_s {
    mbedtls_psa_async_crypto_provider_t *provider;
    mbedtls_psa_async_crypto_operation_t provider_operation;
    mbedtls_psa_async_crypto_request_t request;
    const mbedtls_psa_async_crypto_prime_curve_t *curve;
    uint32_t num_ops;
    uint8_t public_key[133];
} mbedtls_psa_async_crypto_export_public_key_operation_t;

typedef struct mbedtls_psa_async_crypto_random_operation_s {
    mbedtls_psa_async_crypto_provider_t *provider;
    mbedtls_psa_async_crypto_operation_t provider_operation;
    mbedtls_psa_async_crypto_request_t request;
    uint32_t num_ops;
} mbedtls_psa_async_crypto_random_operation_t;

typedef struct mbedtls_psa_async_crypto_aead_operation_s {
    mbedtls_psa_async_crypto_provider_t *provider;
    mbedtls_psa_async_crypto_operation_t provider_operation;
    mbedtls_psa_async_crypto_request_t request;
    size_t output_length;
    uint32_t num_ops;
} mbedtls_psa_async_crypto_aead_operation_t;

#endif /* MBEDTLS_PSA_CRYPTO_ASYNC_CONTEXTS_H */
