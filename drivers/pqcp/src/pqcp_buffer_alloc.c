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

MLD_ALIGN uint8_t tf_psa_crypto_pqcp_alloc_buffer[TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE];

#endif
