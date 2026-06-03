/* A simple bump allocator for mldsa-native, allocating from a global buffer */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED) && \
    defined(TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC)

#include "wrap_mldsa_native.h"
#include "src/common.h"

static MLD_ALIGN uint8_t tf_psa_crypto_pqcp_alloc_buffer[TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE];
static size_t tf_psa_crypto_pqcp_alloc_used;
static int tf_psa_crypto_pqcp_alloc_status;

int tf_psa_crypto_pqcp_alloc_done(void)
{
    int status = tf_psa_crypto_pqcp_alloc_status;
    tf_psa_crypto_pqcp_alloc_status = 0;
    if (tf_psa_crypto_pqcp_alloc_used != 0) {
        status = MLD_ERR_FAIL;
        tf_psa_crypto_pqcp_alloc_used = 0;
    }
    TF_PSA_CRYPTO_PQCP_ALLOC_UNLOCK();
    return status;
}

/* The base address and every allocation are aligned to a multiple
 * of MLD_ALIGN. */
void *tf_psa_crypto_pqcp_alloc_push(size_t size)
{
    /* If something's already gone wrong, avoid doing anything that could
     * make things worse. */
    if (tf_psa_crypto_pqcp_alloc_status != 0) {
        return NULL;
    }

    /* Check that there is room. This shouldn't happen if the buffer size
     * was configured correctly. */
    if (tf_psa_crypto_pqcp_alloc_used + size > sizeof(tf_psa_crypto_pqcp_alloc_buffer)) {
        tf_psa_crypto_pqcp_alloc_status = MLD_ERR_OUT_OF_MEMORY;
        return NULL;
    }

    void *p = tf_psa_crypto_pqcp_alloc_buffer + tf_psa_crypto_pqcp_alloc_used;
    tf_psa_crypto_pqcp_alloc_used += size;
    return p;
}

/* The base address and every allocation are aligned to a multiple
 * of MLD_ALIGN. */
void tf_psa_crypto_pqcp_alloc_pop(size_t size)
{
    /* This shouldn't happen, but make sure we don't underflow the buffer. */
    if (tf_psa_crypto_pqcp_alloc_used < size) {
        tf_psa_crypto_pqcp_alloc_status = MLD_ERR_FAIL;
        return;
    }

    tf_psa_crypto_pqcp_alloc_used -= size;
}

#endif
