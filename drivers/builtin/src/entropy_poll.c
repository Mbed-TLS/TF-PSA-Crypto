/*
 *  Platform-specific and custom entropy polling functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include <string.h>

#if defined(MBEDTLS_ENTROPY_C)

#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "entropy_poll.h"
#include "mbedtls/error_common.h"

int mbedtls_entropy_poll_platform(void *data, unsigned char *output, size_t len, size_t *olen)
{
    int ret;
    size_t entropy_content = 0;
    (void) data;

    ret = mbedtls_platform_get_entropy(output, len, olen, &entropy_content);
    if (ret != 0) {
        return ret;
    }

    if (entropy_content < (8 * (*olen))) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    return 0;
}

#if defined(MBEDTLS_ENTROPY_NV_SEED)
int mbedtls_nv_seed_poll(void *data,
                         unsigned char *output, size_t len, size_t *olen)
{
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];
    size_t use_len = MBEDTLS_ENTROPY_BLOCK_SIZE;
    ((void) data);

    memset(buf, 0, MBEDTLS_ENTROPY_BLOCK_SIZE);

    if (mbedtls_nv_seed_read(buf, MBEDTLS_ENTROPY_BLOCK_SIZE) < 0) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    if (len < use_len) {
        use_len = len;
    }

    memcpy(output, buf, use_len);
    *olen = use_len;

    return 0;
}
#endif /* MBEDTLS_ENTROPY_NV_SEED */

#endif /* MBEDTLS_ENTROPY_C */
