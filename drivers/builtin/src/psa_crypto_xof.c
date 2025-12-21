/*
 *  PSA XOF (extendable-output function) layer on top of software crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_xof.h"

#if defined(MBEDTLS_PSA_BUILTIN_XOF)

#include <string.h>

psa_status_t mbedtls_psa_xof_abort(
    mbedtls_psa_xof_operation_t *operation)
{
    switch (operation->alg) {
        case 0:
            /* The object has (apparently) been initialized but it is not
             * in use. It's ok to call abort on such an object, and there's
             * nothing to do. */
            break;
        default:
            return PSA_ERROR_BAD_STATE;
    }
    operation->alg = 0;
    return PSA_SUCCESS;
}

psa_status_t mbedtls_psa_xof_setup(
    mbedtls_psa_xof_operation_t *operation,
    psa_algorithm_t alg)
{
    /* A context must be freshly initialized before it can be set up. */
    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    switch (alg) {
        default:
            return PSA_ALG_IS_XOF(alg) ?
                   PSA_ERROR_NOT_SUPPORTED :
                   PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->alg = alg;
    return PSA_SUCCESS;
}

psa_status_t mbedtls_psa_xof_set_context(
    mbedtls_psa_xof_operation_t *operation,
    const uint8_t *context, size_t context_length)
{
    switch (operation->alg) {
        case 0:
            return PSA_ERROR_BAD_STATE;
        default:
            (void) context;
            (void) context_length;
            return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t mbedtls_psa_xof_update(
    mbedtls_psa_xof_operation_t *operation,
    const uint8_t *input, size_t input_length)
{
    switch (operation->alg) {
        default:
            (void) input;
            (void) input_length;
            return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t mbedtls_psa_xof_output(
    mbedtls_psa_xof_operation_t *operation,
    uint8_t *output, size_t output_size)
{
    /* TODO: fill output with something "safe" in case of error.
     * What would be safe here? */

    switch (operation->alg) {
        default:
            (void) output;
            (void) output_size;
            return PSA_ERROR_BAD_STATE;
    }
}

#endif /* MBEDTLS_PSA_BUILTIN_XOF */

#endif /* MBEDTLS_PSA_CRYPTO_C */
