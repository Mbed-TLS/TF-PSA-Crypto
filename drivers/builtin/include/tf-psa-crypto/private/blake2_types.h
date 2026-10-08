/**
 * \file blake2_types.h
 *
 * \brief This file contains context types for the BLAKE2 cryptographic hash
 *        and keyed-hash (MAC) algorithms.
 *
 *        BLAKE2 is described in RFC 7693.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_BLAKE2_TYPES_H
#define TF_PSA_CRYPTO_PRIVATE_BLAKE2_TYPES_H
#include "mbedtls/private_access.h"

#include "tf-psa-crypto/build_info.h"

#include <stddef.h>
#include <stdint.h>

#include "psa/crypto_values.h"

/** Invalid input data, such as an invalid output length or key length. */
#define TF_PSA_CRYPTO_ERR_BAD_INPUT_DATA    PSA_ERROR_INVALID_ARGUMENT
/** The output buffer is too small to hold the requested digest. */
#define TF_PSA_CRYPTO_ERR_BUFFER_TOO_SMALL  PSA_ERROR_BUFFER_TOO_SMALL

/**
 * \brief          The BLAKE2s context structure.
 */
typedef struct tf_psa_crypto_blake2s_context {
    uint8_t MBEDTLS_PRIVATE(buf[64]);              /*!< The data block being processed. */
    uint32_t MBEDTLS_PRIVATE(state[8]);            /*!< The intermediate digest state. */
    uint32_t MBEDTLS_PRIVATE(processed_bytes)[2];  /*!< The number of bytes processed, as a
                                                      64-bit little-endian counter split
                                                      into two 32-bit words. */
    size_t MBEDTLS_PRIVATE(buf_idx);               /*!< The number of bytes currently held in
                                                      \c buf. */
    size_t MBEDTLS_PRIVATE(outlen);                /*!< The configured digest length, in bytes. */
} tf_psa_crypto_blake2s_context;

/**
 * \brief          The BLAKE2b context structure.
 */
typedef struct tf_psa_crypto_blake2b_context {
    uint8_t MBEDTLS_PRIVATE(buf[128]);              /*!< The data block being processed. */
    uint64_t MBEDTLS_PRIVATE(state[8]);             /*!< The intermediate digest state. */
    uint64_t MBEDTLS_PRIVATE(processed_bytes[2]);   /*!< The number of Bytes processed, as a
                                                       128-bit little-endian counter split
                                                       into two 64-bit words. */
    size_t MBEDTLS_PRIVATE(buf_idx);                /*!< The number of bytes currently held
                                                       in \c buf. */
    size_t MBEDTLS_PRIVATE(outlen);                 /*!< The configured digest length, in
                                                       bytes. */
} tf_psa_crypto_blake2b_context;

#endif /* TF_PSA_CRYPTO_PRIVATE_BLAKE2_TYPES_H */
