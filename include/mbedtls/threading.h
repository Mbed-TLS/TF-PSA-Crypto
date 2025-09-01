/**
 * \file threading.h
 *
 * \brief Threading abstraction layer
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_THREADING_H
#define MBEDTLS_THREADING_H
#include "mbedtls/private_access.h"

#include "tf-psa-crypto/build_info.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Detected error in mutex or condition variable usage.
 *
 * Note that depending on the platform, many usage errors of
 * synchronization primitives have undefined behavior. But where
 * it is practical to detect usage errors at runtime, mutex and
 * condition primitives can return this error code.
 */
#define MBEDTLS_ERR_THREADING_USAGE_ERROR                 -0x001E

/** A historical alias for #MBEDTLS_ERR_THREADING_USAGE_ERROR. */
#define MBEDTLS_ERR_THREADING_MUTEX_ERROR MBEDTLS_ERR_THREADING_USAGE_ERROR

#if defined(MBEDTLS_THREADING_C)

#if defined(MBEDTLS_THREADING_PTHREAD)
#include <pthread.h>
typedef pthread_mutex_t mbedtls_platform_mutex_t;
typedef pthread_cond_t mbedtls_platform_condition_variable_t;
#endif

#if defined(MBEDTLS_THREADING_ALT)
/* You should define the types mbedtls_platform_mutex_t and
 * mbedtls_platform_condition_variable_t in your header. */
#include "threading_alt.h"

/**
 * \brief           Set your alternate threading implementation function
 *                  pointers and initialize global mutexes. If used, this
 *                  function must be called once in the main thread before any
 *                  other Mbed TLS function is called, and
 *                  mbedtls_threading_free_alt() must be called once in the main
 *                  thread after all other Mbed TLS functions.
 *
 * \note            Functions should return #MBEDTLS_ERR_THREADING_USAGE_ERROR
 *                  if a mutex usage error is detected. However, it is
 *                  acceptable for usage errors to result in undefined behavior
 *                  (including deadlocks and crashes) if detecting usage errors
 *                  is not practical on your platform.
 *
 * \note            mutex_init() and mutex_free() don't return a status code.
 *                  If mutex_init() fails, it should leave its argument (the
 *                  mutex) in a state such that mutex_lock() will fail when
 *                  called with this argument.
 *
 * \note            The library will always unlock a mutex from the same
 *                  thread that locked it, and will never lock a mutex
 *                  in a thread that has already locked it.
 *
 * \param mutex_init    the init function implementation
 * \param mutex_free    the free function implementation
 * \param mutex_lock    the lock function implementation
 * \param mutex_unlock  the unlock function implementation
 * \param cond_init     The condition variable initialization implementation.
 * \param cond_destroy  The condition variable destroy implementation.
 * \param cond_signal   The condition variable signal implementation.
 * \param cond_broadcast The condition variable broadcast implementation.
 * \param cond_wait     The condition variable wait implementation.
 */
void mbedtls_threading_set_alt(
    void (*mutex_init)(mbedtls_platform_mutex_t *),
    void (*mutex_free)(mbedtls_platform_mutex_t *),
    int (*mutex_lock)(mbedtls_platform_mutex_t *),
    int (*mutex_unlock)(mbedtls_platform_mutex_t *),
    int (*cond_init)(mbedtls_platform_condition_variable_t *),
    void (*cond_destroy)(mbedtls_platform_condition_variable_t *),
    int (*cond_signal)(mbedtls_platform_condition_variable_t *),
    int (*cond_broadcast)(mbedtls_platform_condition_variable_t *),
    int (*cond_wait)(mbedtls_platform_condition_variable_t *,
                     mbedtls_platform_mutex_t *));

/**
 * \brief               Free global mutexes.
 */
void mbedtls_threading_free_alt(void);
#endif /* MBEDTLS_THREADING_ALT */

typedef struct mbedtls_threading_mutex_t {
    mbedtls_platform_mutex_t MBEDTLS_PRIVATE(mutex);

    /* WARNING - state should only be accessed when holding the mutex lock in
     * framework/tests/src/threading_helpers.c, otherwise corruption can occur.
     * state will be 0 after a failed init or a free, and nonzero after a
     * successful init. This field is for testing only and thus not considered
     * part of the public API of Mbed TLS and may change without notice.*/
    char MBEDTLS_PRIVATE(state);

} mbedtls_threading_mutex_t;

typedef struct mbedtls_threading_condition_variable_t {
    mbedtls_platform_condition_variable_t MBEDTLS_PRIVATE(cond);
} mbedtls_threading_condition_variable_t;

/** Initialize a mutex (mutual exclusion lock).
 *
 * \note            This function may fail internally, but for historical
 *                  reasons, it does not return a value. If the mutex
 *                  initialization fails internally, mbedtls_mutex_free()
 *                  will still work normally, and all other mutex functions
 *                  will fail safely with a nonzero return code.
 *
 * \note            The behavior is undefined if
 *                  \p mutex is already initialized, or
 *                  if this function is called concurrently on the same
 *                  object from multiple threads.
 *
 * \param mutex     The mutex to initialize.
 */
void mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex);

/** Destroy a mutex.
 *
 * After this function returns, you may call mbedtls_mutex_init()
 * again on \p mutex.
 *
 * \note            The behavior is undefined if:
 *                  - \p mutex has not been initialized with
 *                    mbedtls_mutex_init();
 *                  - this function is called concurrently on the same
 *                    object from multiple threads;
 *                  - \p mutex is locked.
 *
 * \param mutex     The mutex to destroy.
 */
void mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex);

/** Lock a mutex.
 *
 * It must not be already locked by the calling thread
 * (mutexes are not recursive).
 *
 * \note            The behavior is undefined if:
 *                  - \p mutex has not been initialized with
 *                    mbedtls_mutex_init(), or has already been freed
 *                    with mbedtls_mutex_free();
 *                  - \p mutex is already locked by the same thread.
 *
 * \param mutex     The mutex to lock.
 *
 * \retval 0
 *                  Success.
 * \retval #MBEDTLS_ERR_THREADING_USAGE_ERROR
 *                  mbedtls_mutex_init() failed,
 *                  or a mutex usage error was detected.
 *                  Note that depending on the platform, a mutex usage
 *                  error may result in a deadlock, a crash or other
 *                  undesirable behavior instead of returning an error.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *                  There were insufficient resources to initialize or
 *                  lock the mutex.
 * \retval #PSA_ERROR_BAD_STATE
 *                  The compilation option #MBEDTLS_THREADING_ALT is
 *                  enabled, and mbedtls_threading_set_alt() has not
 *                  been called.
 */
int mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex);

/** Unlock a mutex.
 *
 * It must be currently locked by the calling thread.
 *
 * \note            The behavior is undefined if:
 *                  - \p mutex has not been initialized with
 *                    mbedtls_mutex_init(), or has already been freed
 *                    with mbedtls_mutex_free();
 *                  - \p mutex is not locked;
 *                  - \p mutex was locked by a different thread.
 *
 * \param mutex     The mutex to unlock.
 *
 * \retval 0
 *                  Success.
 * \retval #MBEDTLS_ERR_THREADING_USAGE_ERROR
 *                  mbedtls_mutex_init() failed,
 *                  or a mutex usage error was detected.
 *                  Note that depending on the platform, a mutex usage
 *                  error may result in a deadlock, a crash or other
 *                  undesirable behavior instead of returning an error.
 * \retval #PSA_ERROR_BAD_STATE
 *                  The compilation option #MBEDTLS_THREADING_ALT is
 *                  enabled, and mbedtls_threading_set_alt() has not
 *                  been called.
 */
int mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex);

/** Initialize a condition variable.
 *
 * \note            The behavior is undefined if
 *                  \p cond is already initialized, or
 *                  if this function is called concurrently on the same
 *                  object from multiple threads.
 *
 * \param cond      The condition variable to initialize.
 *
 * \retval 0
 *                  Success.
 * \retval #MBEDTLS_ERR_THREADING_USAGE_ERROR
 *                  The condition variable is already initialized
 *                  (on platforms where this can be detected),
 *                  or an unpecified error occurred.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *                  There were insufficient resources to initialize the object.
 * \retval #PSA_ERROR_BAD_STATE
 *                  The compilation option #MBEDTLS_THREADING_ALT is
 *                  enabled, and mbedtls_threading_set_alt() has not
 *                  been called.
 */
int mbedtls_condition_variable_init(
    mbedtls_threading_condition_variable_t *cond);


/** Destroy a condition variable.
 *
 * After this function returns, you may call mbedtls_condition_variable_init()
 * again on \p cond.
 *
 * \note            The behavior is undefined if:
 *                  - \p cond has not been initialized with
 *                    mbedtls_condition_variable_init();
 *                  - any function is called concurrently on the same
 *                    object from another thread.
 *
 * \param cond      The condition variable to destroy.
 */
void mbedtls_condition_variable_free(
    mbedtls_threading_condition_variable_t *cond);

/** Raise a signal a condition variable to wake up one thread.
 *
 * Do nothing, successfully, if no thread is waiting.
 *
 * \note            The behavior is undefined if:
 *                  - \p cond has not been initialized with
 *                    mbedtls_condition_variable_init(), or has already been
 *                    freed with mbedtls_condition_variable_free().
 *
 * \param cond      The condition variable to signal.
 *
 * \retval 0
 *                  Success.
 * \retval #MBEDTLS_ERR_THREADING_USAGE_ERROR
 *                  A usage error was detected.
 *                  Note that depending on the platform, a condition variable
 *                  usage error may result in a deadlock, a crash or other
 *                  undesirable behavior instead of returning an error.
 * \retval #PSA_ERROR_BAD_STATE
 *                  The compilation option #MBEDTLS_THREADING_ALT is
 *                  enabled, and mbedtls_threading_set_alt() has not
 *                  been called.
 */
int mbedtls_condition_variable_signal(
    mbedtls_threading_condition_variable_t *cond);

/** Raise a signal a condition variable to wake up all waiting threads.
 *
 * \note            The behavior is undefined if:
 *                  - \p cond has not been initialized with
 *                    mbedtls_condition_variable_init(), or has already been
 *                    freed with mbedtls_condition_variable_free().
 *
 * \param cond      The condition variable to signal.
 *
 * \retval 0
 *                  Success.
 * \retval #MBEDTLS_ERR_THREADING_USAGE_ERROR
 *                  A usage error was detected.
 *                  Note that depending on the platform, a condition variable
 *                  usage error may result in a deadlock, a crash or other
 *                  undesirable behavior instead of returning an error.
 * \retval #PSA_ERROR_BAD_STATE
 *                  The compilation option #MBEDTLS_THREADING_ALT is
 *                  enabled, and mbedtls_threading_set_alt() has not
 *                  been called.
 */
int mbedtls_condition_variable_broadcast(
    mbedtls_threading_condition_variable_t *cond);

/** Wait for a signal on a condition variable.
 *
 * When this function is called, it atomically unlocks \p mutex.
 * On waking up, it atomically locks \p mutex.
 *
 * \note            The behavior is undefined if:
 *                  - \p mutex has not been initialized with
 *                    mbedtls_mutex_init(), or has already been
 *                    freed with mbedtls_mutex_free();
 *                  - \p cond has not been initialized with
 *                    mbedtls_condition_variable_init(), or has already been
 *                    freed with mbedtls_condition_variable_free();
 *                   - \p mutex is not currently locked by the calling thread.
 *
 * \param cond      The condition variable to wait on.
 * \param mutex     The mutex to unlock and re-lock.
 *                  It must currently be locked by the calling thread.
 *
 * \retval 0
 *                  Success.
 * \retval #MBEDTLS_ERR_THREADING_USAGE_ERROR
 *                  A usage error was detected.
 *                  Note that depending on the platform, a condition variable
 *                  usage error may result in a deadlock, a crash or other
 *                  undesirable behavior instead of returning an error.
 * \retval #PSA_ERROR_BAD_STATE
 *                  The compilation option #MBEDTLS_THREADING_ALT is
 *                  enabled, and mbedtls_threading_set_alt() has not
 *                  been called.
 */
int mbedtls_condition_variable_wait(
    mbedtls_threading_condition_variable_t *cond,
    mbedtls_threading_mutex_t *mutex);

/*
 * Global mutexes
 */
#if defined(MBEDTLS_FS_IO)
extern mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex;
#endif

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)
/* This mutex may or may not be used in the default definition of
 * mbedtls_platform_gmtime_r(), but in order to determine that,
 * we need to check POSIX features, hence modify _POSIX_C_SOURCE.
 * With the current approach, this declaration is orphaned, lacking
 * an accompanying definition, in case mbedtls_platform_gmtime_r()
 * doesn't need it, but that's not a problem. */
extern mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex;
#endif /* MBEDTLS_HAVE_TIME_DATE && !MBEDTLS_PLATFORM_GMTIME_R_ALT */

#endif /* MBEDTLS_THREADING_C */

#ifdef __cplusplus
}
#endif

#endif /* threading.h */
