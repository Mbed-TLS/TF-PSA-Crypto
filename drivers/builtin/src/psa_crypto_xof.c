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

#include "ascon_internal.h"

psa_status_t mbedtls_psa_xof_abort(
    mbedtls_psa_xof_operation_t *operation)
{
    switch (operation->alg) {
        case 0:
            /* The object has (apparently) been initialized but it is not
             * in use. It's ok to call abort on such an object, and there's
             * nothing to do. */
            break;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128)
        case PSA_ALG_ASCON_XOF128:
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128)
        case PSA_ALG_ASCON_CXOF128:
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128) || defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128)
            tf_psa_crypto_ascon_xof128_reset(&operation->ctx.ascon);
            break;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128 */

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
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128)
        case PSA_ALG_ASCON_XOF128:
            tf_psa_crypto_ascon_xof128_setup(&operation->ctx.ascon);
            break;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128)
        case PSA_ALG_ASCON_CXOF128:
            /* Do nothing: setup happens in set_context */
            break;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128 */

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

#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128)
        case PSA_ALG_ASCON_CXOF128:
#if SIZE_MAX > 0xffffffffffffffffu
            if (context_length > 0xffffffffffffffffu) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
#endif
            tf_psa_crypto_ascon_cxof128_setup(&operation->ctx.ascon,
                                              context, context_length);
            return PSA_SUCCESS;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128 */

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
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128)
        case PSA_ALG_ASCON_XOF128:
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128)
        case PSA_ALG_ASCON_CXOF128:
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128) || defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128)
            tf_psa_crypto_ascon_xof128_update(&operation->ctx.ascon,
                                              input, input_length);
            return PSA_SUCCESS;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128 */

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
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128)
        case PSA_ALG_ASCON_XOF128:
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128)
        case PSA_ALG_ASCON_CXOF128:
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128) || defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_CXOF128)
            if (!operation->have_output) {
                tf_psa_crypto_ascon_xof128_finish(&operation->ctx.ascon);
                operation->have_output = 1;
            }
            tf_psa_crypto_ascon_xof128_output(&operation->ctx.ascon,
                                              output, output_size);
            return PSA_SUCCESS;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128 */

        default:
            (void) output;
            (void) output_size;
            return PSA_ERROR_BAD_STATE;
    }
}

#endif /* MBEDTLS_PSA_BUILTIN_XOF */

#endif /* MBEDTLS_PSA_CRYPTO_C */
