/* A simple bump allocator for mldsa-native, allocating from a global buffer */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC_H
#define TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC_H

#include "tf_psa_crypto_common.h"

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

#if defined(TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC)
#include <psa/crypto_values.h>

#if defined(MBEDTLS_THREADING_C)
#include "threading_internal.h"
#endif

// Sufficient for signing with TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED
#define TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE 123200

#if defined(MBEDTLS_THREADING_C)
#define TF_PSA_CRYPTO_PQCP_ALLOC_LOCK()                                 \
    do {                                                                \
        if (mbedtls_mutex_lock(&mbedtls_threading_pqcp_buffer_alloc_mutex)) { \
            return PSA_ERROR_BAD_STATE;                                 \
        }                                                               \
    } while (0)
#define TF_PSA_CRYPTO_PQCP_ALLOC_UNLOCK()                                 \
    mbedtls_mutex_unlock(&mbedtls_threading_pqcp_buffer_alloc_mutex)
#else
#define TF_PSA_CRYPTO_PQCP_ALLOC_LOCK() ((void) 0)
#define TF_PSA_CRYPTO_PQCP_ALLOC_UNLOCK() ((void) 0)
#endif

void *tf_psa_crypto_pqcp_alloc_push(size_t size);
void tf_psa_crypto_pqcp_alloc_pop(size_t size);

#define TF_PSA_CRYPTO_PQCP_CUSTOM_ALLOC(v, T, N)                \
    T *(v) = tf_psa_crypto_pqcp_alloc_push((N) * sizeof(T))
#define TF_PSA_CRYPTO_PQCP_CUSTOM_FREE(v, T, N)                \
    tf_psa_crypto_pqcp_alloc_pop((N) * sizeof(T))

static inline psa_status_t tf_psa_crypto_pqcp_alloc_start()
{
    TF_PSA_CRYPTO_PQCP_ALLOC_LOCK();
    return PSA_SUCCESS;
}
psa_status_t tf_psa_crypto_pqcp_alloc_done(void);

#else /* TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC */

static inline psa_status_t tf_psa_crypto_pqcp_alloc_start()
{
    return PSA_SUCCESS;
}

static inline psa_status_t tf_psa_crypto_pqcp_alloc_done() {
    return PSA_SUCCESS;
}

#endif /* TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC */

#endif /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

#endif /* TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC_H */
