/**
 * \file entropy_poll.h
 *
 * \brief Platform-specific and custom entropy polling functions
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ENTROPY_POLL_H
#define MBEDTLS_ENTROPY_POLL_H

#include "tf-psa-crypto/build_info.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Default thresholds for built-in sources, in bytes
 */
#define MBEDTLS_ENTROPY_MIN_PLATFORM     32     /**< Minimum for platform source    */

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
/**
 * \brief           Platform-specific entropy poll callback
 */
int mbedtls_platform_entropy_poll(void *data,
                                  unsigned char *output, size_t len, size_t *olen);
#endif

#if defined(MBEDTLS_ENTROPY_NV_SEED)
/**
 * \brief           Entropy poll callback for a non-volatile seed file
 *
 * \note            This must accept NULL as its first argument.
 */
int mbedtls_nv_seed_poll(void *data,
                         unsigned char *output, size_t len, size_t *olen);
#endif

/* Wrapper to allow mbedtls_platform_get_entropy_alt() to be used from entropy
 * module as other entropy polling functions (i.e. mbedtls_platform_entropy_poll
 * and mbedtls_nv_seed_poll). */
#if defined(MBEDTLS_PLATFORM_GET_ENTROPY_ALT)

#include <mbedtls/platform.h>

#define MBEDTLS_ENTROPY_MIN_HARDWARE            32

static inline int mbedtls_hardware_poll(void *data, unsigned char *output,
                                        size_t len, size_t *olen)
{
    int ret;
    size_t entropy_content = 0;
    (void) data;

    ret = mbedtls_platform_get_entropy_alt(output, len, olen, &entropy_content);
    if (ret != 0) {
        return ret;
    }

    if (entropy_content < (8 * (*olen))) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    return 0;
}
#endif /* MBEDTLS_PLATFORM_GET_ENTROPY_ALT */

#ifdef __cplusplus
}
#endif

#endif /* entropy_poll.h */
