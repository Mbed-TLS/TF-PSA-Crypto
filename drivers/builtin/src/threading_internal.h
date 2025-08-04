/**
 * \file threading_internal.h
 *
 * \brief Internal declarations related to threading
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef TF_PSA_CRYPTO_THREADING_INTERNAL_H
#define TF_PSA_CRYPTO_THREADING_INTERNAL_H

#include <mbedtls/private_access.h>
#include <tf-psa-crypto/build_info.h>

#include <mbedtls/threading.h>

#if defined(MBEDTLS_TEST_HOOKS)
/* See threading_helpers.c */
extern void (*mbedtls_test_hook_mutex_init_post)(mbedtls_threading_mutex_t *mutex);
extern void (*mbedtls_test_hook_mutex_free_pre)(mbedtls_threading_mutex_t *mutex);
extern void (*mbedtls_test_hook_mutex_lock_post)(mbedtls_threading_mutex_t *mutex,
                                                 int ret);
extern void (*mbedtls_test_hook_mutex_unlock_pre)(mbedtls_threading_mutex_t *mutex);
#endif

#endif /* TF_PSA_CRYPTO_THREADING_INTERNAL_H */
