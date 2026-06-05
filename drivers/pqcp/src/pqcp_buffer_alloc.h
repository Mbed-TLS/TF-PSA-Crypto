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

#if defined(MBEDTLS_THREADING_C)
#include "threading_internal.h"
#endif

// Call stack: mldsa87_signature_internal -> attempt_signature_generation87
#define TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE_DETERMINISTIC_KL(K, L) ( \
        /* mldsa87_signature_internal */ ( \
            /* seedbuf      */ (2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2 * MLDSA_CRHBYTES) + \
            /* mld_polymat  */ (1024*(K) *(L)) + \
            /* mld_polyvecl */ (1024*(L)) + \
            /* mld_polyveck */ 2*(1024*(K)) \
            ) + \
        /* attempt_signature_generation87 */ ( \
            /* MLDSA_CTILDEBYTES */ MLD_ALIGN_UP(8*(K)) + \
            /* mld_polyvecl      */ 2*(1024*(L)) + \
            /* mld_polyveck      */ 3*(1024*(K)) + \
            /* mld_poly          */ 3*(1024) \
            ) \
        )

#define TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE_DETERMINISTIC(param_set) \
    TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE_DETERMINISTIC_KL((param_set)/10, (param_set)%10)

// Sufficient for deterministic signatures with TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED
#define TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE \
    TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE_DETERMINISTIC(87) /* == 123200 */

#if defined(MBEDTLS_THREADING_C)
#define TF_PSA_CRYPTO_PQCP_ALLOC_LOCK()                                 \
    do {                                                                \
        if (mbedtls_mutex_lock(&mbedtls_threading_pqcp_buffer_alloc_mutex)) { \
            return MLD_ERR_FAIL;                                 \
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

#define TF_PSA_CRYPTO_PQCP_CUSTOM_ALLOC(v, T, N) \
    T *(v) = NULL; \
    do { \
        /* Verify that the allocation would fit in the buffer by itself, avoiding overflows \
           This should be optimized away at compile-time */ \
        if ((N) > 0 && (N) <= TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE / sizeof(T)) { \
            (v) = tf_psa_crypto_pqcp_alloc_push(MLD_ALIGN_UP(sizeof(T) * (N))); \
        } \
    } while (0)

#define TF_PSA_CRYPTO_PQCP_CUSTOM_FREE(v, T, N)                \
    tf_psa_crypto_pqcp_alloc_pop(MLD_ALIGN_UP(sizeof(T) * (N)))

static inline int tf_psa_crypto_pqcp_alloc_start(void)
{
    TF_PSA_CRYPTO_PQCP_ALLOC_LOCK();
    return 0;
}
int tf_psa_crypto_pqcp_alloc_done(void);

#endif /* TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC */

#endif /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

#endif /* TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC_H */
