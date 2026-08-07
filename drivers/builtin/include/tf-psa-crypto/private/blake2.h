/**
 * \file blake2.h
 *
 * \brief This file contains context types for Blake2.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_BLAKE2_H
#define TF_PSA_CRYPTO_PRIVATE_BLAKE2_H
#include "mbedtls/private_access.h"

#include "tf-psa-crypto/build_info.h"

#include <stddef.h>
#include <stdint.h>

#include "psa/crypto_values.h"

#define TF_PSA_CRYPTO_ERR_BAD_INPUT_DATA    PSA_ERROR_INVALID_ARGUMENT
#define TF_PSA_CRYPTO_ERR_BUFFER_TOO_SMALL  PSA_ERROR_BUFFER_TOO_SMALL

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tf_psa_crypto_blake2s_context {
    uint8_t MBEDTLS_PRIVATE(buf[64]);
    uint32_t MBEDTLS_PRIVATE(state[8]);
    uint32_t MBEDTLS_PRIVATE(processed_bytes)[2];
    size_t MBEDTLS_PRIVATE(buf_idx);
    size_t MBEDTLS_PRIVATE(outlen);
} tf_psa_crypto_blake2s_context;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_BLAKE2S_HASH256)

int tf_psa_crypto_blake2s_init(tf_psa_crypto_blake2s_context *ctx, size_t outlen,
                               const void *key, size_t keylen);

void tf_psa_crypto_blake2s_free(tf_psa_crypto_blake2s_context *ctx);

void tf_psa_crypto_blake2s_clone(tf_psa_crypto_blake2s_context *dst,
                                 const tf_psa_crypto_blake2s_context *src);

void tf_psa_crypto_blake2s_update(tf_psa_crypto_blake2s_context *ctx,
                                  const uint8_t *in, size_t inlen);

int tf_psa_crypto_blake2s_finish(tf_psa_crypto_blake2s_context *ctx,
                                 uint8_t *out, size_t outlen);

int tf_psa_crypto_blake2s(const uint8_t *in, size_t inlen,
                          const void *key, size_t keylen,
                          uint8_t *out, size_t outlen);

#endif /* MBEDTLS_PSA_BUILTIN_ALG_BLAKE2S_HASH256 */

typedef struct tf_psa_crypto_blake2b_context {
    uint8_t MBEDTLS_PRIVATE(buf[128]);
    uint64_t MBEDTLS_PRIVATE(state[8]);
    uint64_t MBEDTLS_PRIVATE(processed_bytes[2]);
    size_t MBEDTLS_PRIVATE(buf_idx);
    size_t MBEDTLS_PRIVATE(outlen);
} tf_psa_crypto_blake2b_context;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512)

int tf_psa_crypto_blake2b_init(tf_psa_crypto_blake2b_context *ctx, size_t outlen,
                               const void *key, size_t keylen);

void tf_psa_crypto_blake2b_free(tf_psa_crypto_blake2b_context *ctx);

void tf_psa_crypto_blake2b_clone(tf_psa_crypto_blake2b_context *dst,
                                 const tf_psa_crypto_blake2b_context *src);

void tf_psa_crypto_blake2b_update(tf_psa_crypto_blake2b_context *ctx,
                                  const uint8_t *in, size_t inlen);

int tf_psa_crypto_blake2b_finish(tf_psa_crypto_blake2b_context *ctx,
                                 uint8_t *out, size_t outlen);

int tf_psa_crypto_blake2b(const uint8_t *in, size_t inlen,
                          const void *key, size_t keylen,
                          uint8_t *out, size_t outlen);

#endif /* MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512 */

#ifdef __cplusplus
}
#endif

#endif /* TF_PSA_CRYPTO_PRIVATE_BLAKE2_H */
