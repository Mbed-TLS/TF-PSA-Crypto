/**
 * \file threading_internal.h
 *
 * \brief Threading interfaces used by the test framework
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_THREADING_INTERNAL_H
#define MBEDTLS_THREADING_INTERNAL_H

#include "tf_psa_crypto_common.h"

#include <mbedtls/threading.h>

/* A version number for the internal threading interface.
 * This is meant to allow the framework to remain compatible with
 * multiple versions, to facilitate transitions.
 *
 * Conventionally, this is the Mbed TLS version number when the
 * threading interface was last changed in a way that may impact the
 * test framework, with the lower byte incremented as necessary
 * if multiple changes happened between releases. */
#define MBEDTLS_THREADING_INTERNAL_VERSION 0x04000000

#if defined(MBEDTLS_THREADING_C)

/*
 * The function pointers for mutex_init, mutex_free, mutex_ and mutex_unlock
 *
 * They are exposed for the sake of the mutex usage verification framework
 * (see framework/tests/src/threading_helpers.c).
 */
extern void (*mbedtls_mutex_init_ptr)(mbedtls_platform_mutex_t *mutex);
extern void (*mbedtls_mutex_free_ptr)(mbedtls_platform_mutex_t *mutex);
extern int (*mbedtls_mutex_lock_ptr)(mbedtls_platform_mutex_t *mutex);
extern int (*mbedtls_mutex_unlock_ptr)(mbedtls_platform_mutex_t *mutex);


#endif /* MBEDTLS_THREADING_C */

#endif /* MBEDTLS_THREADING_INTERNAL_H */
