/* PSA driver for ML-DSA using mldsa-native */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

#include <psa/crypto.h>
#include "psa_crypto_mldsa.h"
#include "wrap_mldsa_native.h"
#include <mbedtls/platform_util.h>

/* For now, hard-coded values for MLDSA-87 */
#define TF_PSA_CRYPTO_MLDSA_EXPANDED_SECRET_MAX_SIZE MLDSA87_SECRETKEYBYTES
#define TF_PSA_CRYPTO_MLDSA_PUBLIC_KEY_MAX_SIZE MLDSA87_PUBLICKEYBYTES
#define TF_PSA_CRYPTO_MLDSA_SIGNATURE_MAX_SIZE MLDSA87_BYTES

static psa_status_t seed_to_public_key(
    size_t bits,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    if (key_buffer_size != 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (bits != 87) {
        /* Other parameter sets are not supported yet. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t public_key_length = MLDSA87_PUBLICKEYBYTES;
    if (data_size < public_key_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Beyond this point, we must go through the cleanup code. */
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    uint8_t secret[TF_PSA_CRYPTO_MLDSA_EXPANDED_SECRET_MAX_SIZE];

    int ret = tf_psa_crypto_pqcp_mldsa87_keypair_internal(data,
                                                          secret,
                                                          key_buffer);
    if (ret != 0) {
        /* The only documented error is an internal error which is not
         * supposed to ever happen (failure of a self-test). */
        goto cleanup;
    }
    status = PSA_SUCCESS;
    *data_length = public_key_length;

cleanup:
    mbedtls_platform_zeroize(secret, sizeof(secret));
    return status;
}

psa_status_t tf_psa_crypto_mldsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    *data_length = 0;           /* Safe default */

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return seed_to_public_key(psa_get_key_bits(attributes),
                              key_buffer, key_buffer_size,
                              data, data_size, data_length);
}

psa_status_t tf_psa_crypto_mldsa_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    *signature_length = 0;      /* Safe default */

    if (alg != PSA_ALG_DETERMINISTIC_ML_DSA) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (psa_get_key_bits(attributes) != 87) {
        /* Other parameter sets are not supported yet. */
        return PSA_ERROR_NOT_SUPPORTED;
    }
    size_t actual_signature_length = MLDSA87_BYTES;

    if (key_buffer_size != 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (signature_size < actual_signature_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Beyond this point, we must go through the cleanup code. */
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    uint8_t secret[TF_PSA_CRYPTO_MLDSA_EXPANDED_SECRET_MAX_SIZE];
    uint8_t public[TF_PSA_CRYPTO_MLDSA_PUBLIC_KEY_MAX_SIZE];

    int ret = tf_psa_crypto_pqcp_mldsa87_keypair_internal(public,
                                                          secret,
                                                          key_buffer);
    if (ret != 0) {
        /* The only documented error is an internal error which is not
         * supposed to ever happen (failure of a self-test). */
        goto cleanup;
    }

    const uint8_t prefix[2] = { 0, 0 }; // pure ML-DSA with empty context
    const size_t prefix_length = sizeof(prefix);
    const uint8_t rnd[MLDSA_RNDBYTES] = { 0 };

    ret = tf_psa_crypto_pqcp_mldsa87_signature_internal(signature,
                                                        signature_length,
                                                        message, message_length,
                                                        prefix, prefix_length,
                                                        rnd,
                                                        secret,
                                                        0);
    status = PSA_SUCCESS;

cleanup:
    mbedtls_platform_zeroize(secret, sizeof(secret));
    return status;
}

psa_status_t tf_psa_crypto_mldsa_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length)
{
    if (!PSA_ALG_IS_ML_DSA(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (psa_get_key_bits(attributes) != 87) {
        /* Other parameter sets are not supported yet. */
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (key_buffer_size != MLDSA87_PUBLICKEYBYTES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (signature_length != MLDSA87_BYTES) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    int ret = tf_psa_crypto_pqcp_mldsa87_verify(signature, signature_length,
                                                message, message_length,
                                                NULL, 0,
                                                key_buffer);
    if (ret == 0) {
        return PSA_SUCCESS;
    } else {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
}

#endif /* MBEDTLS_PSA_CRYPTO_C && TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */
