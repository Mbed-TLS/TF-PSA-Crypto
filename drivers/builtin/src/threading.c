/*
 *  Threading abstraction layer
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * Ensure gmtime_r is available even with -std=c99; must be defined before
 * mbedtls_config.h, which pulls in glibc's features.h. Harmless on other platforms.
 */
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_THREADING_C)

#include "mbedtls/threading.h"

#include "threading_internal.h"

#include <psa/crypto_values.h>

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)

#if !defined(_WIN32) && (defined(unix) || \
    defined(__unix) || defined(__unix__) || (defined(__APPLE__) && \
    defined(__MACH__)))
#include <unistd.h>
#endif /* !_WIN32 && (unix || __unix || __unix__ ||
        * (__APPLE__ && __MACH__)) */

#if !((defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L) ||     \
    (defined(_POSIX_THREAD_SAFE_FUNCTIONS) &&                     \
    _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L))
/*
 * This is a convenience shorthand macro to avoid checking the long
 * preprocessor conditions above. Ideally, we could expose this macro in
 * platform_util.h and simply use it in platform_util.c, threading.c and
 * threading.h. However, this macro is not part of the Mbed TLS public API, so
 * we keep it private by only defining it in this file
 */

#if !(defined(_WIN32) && !defined(EFIX64) && !defined(EFI32))
#define THREADING_USE_GMTIME
#endif /* ! ( defined(_WIN32) && !defined(EFIX64) && !defined(EFI32) ) */

#endif /* !( ( defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L ) || \
             ( defined(_POSIX_THREAD_SAFE_FUNCTIONS ) && \
                _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L ) ) */

#endif /* MBEDTLS_HAVE_TIME_DATE && !MBEDTLS_PLATFORM_GMTIME_R_ALT */

#if defined(MBEDTLS_THREADING_C11)
static int wrap_error(int threads_ret)
{
    switch (threads_ret) {
        case thrd_success:
            return 0;
        case thrd_nomem:
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        default:
            return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
}

int mbedtls_platform_mutex_setup(mbedtls_platform_mutex_t *mutex)
{
    return wrap_error(mtx_init(mutex, mtx_plain));
}
MBEDTLS_STATIC_TESTABLE
void mbedtls_platform_mutex_destroy(mbedtls_platform_mutex_t *mutex)
{
    mtx_destroy(mutex);
}

int mbedtls_platform_mutex_lock(mbedtls_platform_mutex_t *mutex)
{
    return wrap_error(mtx_lock(mutex));
}

int mbedtls_platform_mutex_unlock(mbedtls_platform_mutex_t *mutex)
{
    return wrap_error(mtx_unlock(mutex));
}

#endif /* MBEDTLS_THREADING_C11 */

#if defined(MBEDTLS_THREADING_PTHREAD)
#include <errno.h>

int mbedtls_platform_mutex_setup(mbedtls_platform_mutex_t *mutex)
{
    switch (pthread_mutex_init(mutex, NULL)) {
        case 0:
            return 0;
        case ENOMEM:
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        default:
            return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
}

void mbedtls_platform_mutex_destroy(mbedtls_platform_mutex_t *mutex)
{
    (void) pthread_mutex_destroy(mutex);
}

int mbedtls_platform_mutex_lock(mbedtls_platform_mutex_t *mutex)
{
    if (pthread_mutex_lock(mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
    return 0;
}

int mbedtls_platform_mutex_unlock(mbedtls_platform_mutex_t *mutex)
{
    if (pthread_mutex_unlock(mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
    return 0;
}

/*
 * With pthreads we can statically initialize mutexes
 */
#if defined(MBEDTLS_TEST_HOOKS)
#define MUTEX_INIT  = { PTHREAD_MUTEX_INITIALIZER, 1 }
#else
#define MUTEX_INIT  = { PTHREAD_MUTEX_INITIALIZER }
#endif

#endif /* MBEDTLS_THREADING_PTHREAD */

#if defined(MBEDTLS_TEST_HOOKS)
/* See threading_helpers.c */
void (*mbedtls_test_hook_mutex_init_post)(mbedtls_threading_mutex_t *mutex);
void (*mbedtls_test_hook_mutex_free_pre)(mbedtls_threading_mutex_t *mutex);
void (*mbedtls_test_hook_mutex_lock_post)(mbedtls_threading_mutex_t *mutex,
                                          int ret);
void (*mbedtls_test_hook_mutex_unlock_pre)(mbedtls_threading_mutex_t *mutex);
#endif

void mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    /* One problem here is that calling lock on a pthread mutex without first
     * having initialised it is undefined behaviour. Obviously we cannot check
     * this here in a thread safe manner without a significant performance
     * hit, so state transitions are checked in tests only via the state
     * variable. Please make sure any new mutex that gets added is exercised in
     * tests; see framework/tests/src/threading_helpers.c for more details. */
    /* We don't have a way to return an error code yet, so we just leave
     * the mutex in a bad state. This should be improved. */
    (void) mbedtls_platform_mutex_setup(&mutex->mutex);

#if defined(MBEDTLS_TEST_HOOKS)
    if (mbedtls_test_hook_mutex_init_post != NULL) {
        mbedtls_test_hook_mutex_init_post(mutex);
    }
#endif
}

void mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

#if defined(MBEDTLS_TEST_HOOKS)
    if (mbedtls_test_hook_mutex_free_pre != NULL) {
        mbedtls_test_hook_mutex_free_pre(mutex);
    }
#endif

    mbedtls_platform_mutex_destroy(&mutex->mutex);
}

int mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

    int ret = mbedtls_platform_mutex_lock(&mutex->mutex);

#if defined(MBEDTLS_TEST_HOOKS)
    if (mbedtls_test_hook_mutex_lock_post != NULL) {
        mbedtls_test_hook_mutex_lock_post(mutex, ret);
    }
#endif

    return ret;
}

int mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_TEST_HOOKS)
    if (mbedtls_test_hook_mutex_unlock_pre != NULL) {
        mbedtls_test_hook_mutex_unlock_pre(mutex);
    }
#endif

    return mbedtls_platform_mutex_unlock(&mutex->mutex);
}


/*
 * Set functions pointers and initialize global mutexes
 */
void mbedtls_threading_setup(void)
{
#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_init(&mbedtls_threading_readdir_mutex);
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_init(&mbedtls_threading_gmtime_mutex);
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_mutex_init(&mbedtls_threading_key_slot_mutex);
    mbedtls_mutex_init(&mbedtls_threading_psa_globaldata_mutex);
    mbedtls_mutex_init(&mbedtls_threading_psa_rngdata_mutex);
#endif
}

/*
 * Free global mutexes
 */
void mbedtls_threading_teardown(void)
{
#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_free(&mbedtls_threading_readdir_mutex);
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_free(&mbedtls_threading_gmtime_mutex);
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_mutex_free(&mbedtls_threading_key_slot_mutex);
    mbedtls_mutex_free(&mbedtls_threading_psa_globaldata_mutex);
    mbedtls_mutex_free(&mbedtls_threading_psa_rngdata_mutex);
#endif
}

/*
 * Define global mutexes
 */
#ifndef MUTEX_INIT
#define MUTEX_INIT
#endif
#if defined(MBEDTLS_FS_IO)
mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex MUTEX_INIT;
#endif
#if defined(THREADING_USE_GMTIME)
mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex MUTEX_INIT;
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
mbedtls_threading_mutex_t mbedtls_threading_key_slot_mutex MUTEX_INIT;
mbedtls_threading_mutex_t mbedtls_threading_psa_globaldata_mutex MUTEX_INIT;
mbedtls_threading_mutex_t mbedtls_threading_psa_rngdata_mutex MUTEX_INIT;
#endif

#endif /* MBEDTLS_THREADING_C */
