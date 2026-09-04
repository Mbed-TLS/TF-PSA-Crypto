/**
 * \file sm3_types.h
 *
 * \brief This file contains context types for SM3.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_SM3_TYPES_H
#define TF_PSA_CRYPTO_PRIVATE_SM3_TYPES_H
#include "mbedtls/private_access.h"

#include "tf-psa-crypto/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The state of an SM3 hash operation. */
typedef struct {
    uint64_t total;             /*!< The number of Bytes processed. */
    uint32_t state[8];          /*!< The intermediate digest state. */
    uint8_t buffer[64];         /*!< The data block being processed. */
} tf_psa_crypto_sm3_operation_t;

#ifdef __cplusplus
}
#endif

#endif /* TF_PSA_CRYPTO_PRIVATE_SM3_TYPES_H */
