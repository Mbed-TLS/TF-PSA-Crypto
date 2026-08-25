/**
 * \file sm3_internal.h
 *
 * \brief This file contains internal function definitions for SM3.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_SM3_INTERNAL_H
#define TF_PSA_CRYPTO_SM3_INTERNAL_H
#include "mbedtls/private_access.h"

#include "tf-psa-crypto/build_info.h"
#include "tf-psa-crypto/private/sm3_types.h"

#include "psa/crypto_types.h"
#include "psa/crypto_values.h"


/** Set up an SM3 operation. */
void tf_psa_crypto_sm3_setup(tf_psa_crypto_sm3_operation_t *operation);

/** Add input to an SM3 operation. */
psa_status_t tf_psa_crypto_sm3_update(
    tf_psa_crypto_sm3_operation_t *operation,
    const uint8_t *input,
    size_t input_length);

/** Finish an SM3 operation. */
void tf_psa_crypto_sm3_finish(
    tf_psa_crypto_sm3_operation_t *operation,
    uint8_t output[32]);

#if defined(MBEDTLS_SELF_TEST)
/** Run the SM3 checkup routine. */
int tf_psa_crypto_sm3_self_test(int verbose);
#endif /* MBEDTLS_SELF_TEST */

#endif /* TF_PSA_CRYPTO_SM3_INTERNAL_H */
