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

#define MBEDTLS_ENTROPY_POLL_PLATFORM_MIN        32

/**
 * This function get called from the entropy module when it's gathering entropy
 * data. Backends are:
 * - On Windows, Linux or BSD systems there's no need to define
 *   MBEDTLS_PLATFORM_GET_ENTROPY_ALT. In this case Mbed TLS uses platform-specific
 *   sources such as getrandom(), /dev/urandom or BCryptGenRandom() to gather
 *   entropy data.
 * - on baremetal plaform instead define MBEDTLS_PLATFORM_GET_ENTROPY_ALT and
 *   provide the custom implementation of mbedtls_platform_get_entropy().
 *   See mbedtls/platform.h for the documentation of the function.
 *
 * \note The function must accept \p data == NULL.
 */
int mbedtls_entropy_poll_platform(void *data, unsigned char *output, size_t len, size_t *olen);

#if defined(MBEDTLS_ENTROPY_NV_SEED)
/**
 * \brief           Entropy poll callback for a non-volatile seed file
 *
 * \note            This must accept NULL as its first argument.
 */
int mbedtls_nv_seed_poll(void *data,
                         unsigned char *output, size_t len, size_t *olen);
#endif

#ifdef __cplusplus
}
#endif

#endif /* entropy_poll.h */
