/* A simple bump allocator for mldsa-native, allocating from a global buffer */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC_H
#define TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC_H

#include "tf_psa_crypto_common.h"

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED) && defined(TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC)
#include <psa/crypto_values.h>

#if defined(MBEDTLS_THREADING_C)
#include "threading_internal.h"
#endif

// Sufficient for signing with TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED
#define TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE 123200

extern uint8_t tf_psa_crypto_pqcp_alloc_buffer[TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE];

struct tf_psa_crypto_pqcp_context {
    int alloc_offset; // Negative values indicate allocator errors
};

#if defined(MBEDTLS_THREADING_C)
#define TF_PSA_CRYPTO_PQCP_ALLOC_LOCK() \
    mbedtls_mutex_lock(&mbedtls_threading_pqcp_buffer_alloc_mutex)
#else
#define TF_PSA_CRYPTO_PQCP_ALLOC_LOCK() 0
#endif

#define TF_PSA_CRYPTO_PQCP_CUSTOM_ALLOC(v, T, N, context) \
    T *(v) = NULL; \
    do { \
        /* Verify that the allocation would fit in the buffer by itself, avoiding overflows \
           This should be optimized away at compile-time */ \
        if ((N) > 0 && (N) <= TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE / sizeof(T)) { \
            if ((context).alloc_offset == 0) { \
                (context).alloc_offset = TF_PSA_CRYPTO_PQCP_ALLOC_LOCK(); \
            } \
            if ((context).alloc_offset >= 0) { \
                if ((size_t) (context).alloc_offset <= \
                    TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE - MLD_ALIGN_UP(sizeof(T) * (N))) { \
                    (v) = (T *) (tf_psa_crypto_pqcp_alloc_buffer + (context).alloc_offset); \
                    (context).alloc_offset += MLD_ALIGN_UP(sizeof(T) * (N)); \
                } else { \
                    /* Fail all further allocations in this function -> goto cleanup \
                     * If we ended up here, that implies (alloc_offset != 0) \
                     * thus we don't need to call mutex_unlock() */ \
                    (context).alloc_offset = PSA_ERROR_INSUFFICIENT_MEMORY; \
                } \
            } \
        } \
    } while (0)

#if defined(MBEDTLS_THREADING_C)
// mldsa-native only calls this macro if v != NULL
#define TF_PSA_CRYPTO_PQCP_CUSTOM_FREE(v, T, N, context) \
    do { \
        /* Unlock only after freeing the last allocation */ \
        if ((uint8_t *) (v) == tf_psa_crypto_pqcp_alloc_buffer) { \
            mbedtls_mutex_unlock(&mbedtls_threading_pqcp_buffer_alloc_mutex); \
        } \
    } while (0)
#else
#define TF_PSA_CRYPTO_PQCP_CUSTOM_FREE(v, T, N, context)
#endif

#endif /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED && TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC */

#endif /* TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC_H */
