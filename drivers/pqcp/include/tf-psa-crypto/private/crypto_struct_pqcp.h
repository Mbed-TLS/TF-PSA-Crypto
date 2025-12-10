/**
 * \file crypto_struct_pqcp.h
 *
 * \brief Context structure declarations of the PSA driver that wraps around
 *        mldsa-native.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_CRYPTO_STRUCT_PQCP_H
#define TF_PSA_CRYPTO_PRIVATE_CRYPTO_STRUCT_PQCP_H

#include "mbedtls/private_access.h"

#include <psa/crypto_driver_common.h>

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED)
#define TF_PSA_CRYPTO_PQCP_MLDSA_PUBLIC_KEY_MAX_SIZE 2592
#define TF_PSA_CRYPTO_PQCP_MLDSA_PRIVATE_KEY_MAX_SIZE 4896
#else
#error "TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED defined but no parameter set enabled"
#endif

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_MULTIPART) && \
    !defined(MBEDTLS_PSA_BUILTIN_ALG_SHAKE256)
#error "The multipart MLDSA interface currently only works with the built-in SHAKE implementation."
#endif
#include <mbedtls/private/sha3.h>

typedef struct {
    uint8_t parameter_set;       /* 44, 65 or 87 */
    mbedtls_sha3_context shake;
    uint8_t private_key[TF_PSA_CRYPTO_PQCP_MLDSA_PRIVATE_KEY_MAX_SIZE];
} tf_psa_crypto_mldsa_sign_operation_t;

#define TF_PSA_CRYPTO_MLDSA_SIGN_OPERATION_INIT { 0, { { 0 }, 0, 0, 0, 0 }, { 0 } };

typedef struct {
    uint8_t parameter_set;       /* 44, 65 or 87 */
    mbedtls_sha3_context shake;
    uint8_t public_key[TF_PSA_CRYPTO_PQCP_MLDSA_PUBLIC_KEY_MAX_SIZE];
} tf_psa_crypto_mldsa_verify_operation_t;

#define TF_PSA_CRYPTO_MLDSA_VERIFY_OPERATION_INIT { 0, { { 0 }, 0, 0, 0, 0 }, { 0 } };

#endif /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

#endif /* TF_PSA_CRYPTO_PRIVATE_CRYPTO_STRUCT_PQCP_H */
