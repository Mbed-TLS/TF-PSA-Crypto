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

/** Bad input parameters to function. */
#define MBEDTLS_ERR_THREADING_BAD_INPUT_DATA              -0x001C
/** Locking / unlocking / free failed with error code. */
#define MBEDTLS_ERR_THREADING_MUTEX_ERROR                 -0x001E

#if defined(MBEDTLS_THREADING_C)

#include "mbedtls/platform_threading.h"

typedef struct mbedtls_threading_mutex_t {
    mbedtls_platform_mutex_t MBEDTLS_PRIVATE(mutex);

#if defined(MBEDTLS_TEST_HOOKS)
    /* WARNING - state should only be accessed when holding the mutex lock in
     * framework/tests/src/threading_helpers.c, otherwise corruption can occur.
     * state will be 0 after a failed init or a free, and nonzero after a
     * successful init. This field is for testing only and thus not considered
     * part of the public API of Mbed TLS and may change without notice.*/
    char MBEDTLS_PRIVATE(state);
#endif
} mbedtls_threading_mutex_t;

/* For test purposes only. See <test/threading_helpers.h>. */
#define MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE 0x01000001

/* For test purposes only. See <test/threading_helpers.h>. */
#define MBEDTLS_PLATFORM_THREADING_THREAD 0x01000001


/**
 * \brief   Initialize global mutexes.
 *
 * If your application calls TF-PSA-Crypto or Mbed TLS functions from more
 * than one thred, you must call this function exactly once before calling
 * any other library function.
 *
 * \note    Calling this function is optional on threading implementations
 *          where a mutex can be initialized statically.
 */
void mbedtls_threading_setup(void);

/**
 * \brief   Destroy global mutexes.
 *
 * If you have called mbedtls_threading_setup(), you may call this
 * function to destroy resources consumed by global mutexes.
 *
 * Do not call this function while any TF-PSA-Crypto or Mbed TLS function
 * call is in progress in any thread, or while the PSA subsystem is active.
 */
void mbedtls_threading_teardown(void);

/** Initialize and set up a mutex.
 *
 * \note    The mutex may not be used until one thread has completed a call
 *          to mbedtls_mutex_init().
 *
 * \note    This function may allocate resources. Call mbedtls_mutex_free()
 *          to free these resources.
 *
 * \note    mbedtls_mutex_init() does not return a status code.
 *          If it fails, it should leave its argument (the mutex)
 *          in a state such that mbedtls_mutex_lock() will fail when
 *          called with this argument.
 *
 * \param[out] mutex    The mutex to initialize.
 */
void mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex);

/** Destroy a mutex.
 *
 * A destroyed mutex does not hold any resources.
 *
 * \note    As soon as one thread has started a call to this function,
 *          no other thread may access the mutex in any way, including
 *          concurrent calls to this function. Once the call returns,
 *          you may call mbedtls_mutex_init() again on the mutex.
 *
 * \param[in,out] mutex The mutex to destroy.
 */
void mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex);

/** Lock a mutex.
 *
 * \note    The mutex must have been initialized and must not be
 *          already locked by the same state (no recursive locking).
 *          Otherwise the behavior is undefined.
 *
 * \param[in,out] mutex The mutex to lock.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_MUTEX_ERROR
 *                      The mutex could not be locked.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      The mutex is in an invalid state.
 */
int mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex);

/** Unlock a mutex.
 *
 * \note    The mutex must have been locked by the same thread.
 *          Otherwise the behavior is undefined.
 *
 * \param[in,out] mutex The mutex to unlock.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_MUTEX_ERROR
 *                      The mutex could not be unlocked.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      The mutex is in an invalid state.
 */
int mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex);
/** The type of condition variables.
 */
typedef mbedtls_platform_condition_variable_t mbedtls_threading_condition_t;

/** Set up a condition variable.
 *
 * \param[in,out] cond  The condition variable to set up.
 *                      The behavior is undefined if \p cond is
 *                      already set up.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      The condition variable is in an invalid state.
 *                      Note that such an error condition have undefined
 *                      behavior.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *                      Insufficient memory or other resource.
 */
int mbedtls_condition_variable_setup(mbedtls_threading_condition_t *cond);

/** Destroy a condition variable.
 *
 * \param[in,out] cond  The condition variable to destroy.
 *                      The behavior is undefined if \p cond is
 *                      already not set up or if there are threads
 *                      waiting on \p cond.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      The condition variable is in an invalid state.
 *                      Note that such an error condition have undefined
 *                      behavior.
 */
int mbedtls_condition_variable_destroy(mbedtls_threading_condition_t *cond);

/** Signal one consumer on a condition variable.
 *
 * Wake up a thread that is currently waiting on \p cond. Do nothing if
 * no thread is waiting on \p cond.
 *
 * \param[in,out] cond  The condition variable to signal.
 *                      The behavior is undefined if \p cond is
 *                      not set up.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      The condition variable is in an invalid state.
 *                      Note that such an error condition have undefined
 *                      behavior.
 */
int mbedtls_condition_variable_signal(mbedtls_threading_condition_t *cond);

/** Signal all consumers on a condition variable.
 *
 * Wake up all threads that are currently waiting on \p cond.
 *
 * \param[in,out] cond  The condition variable to signal.
 *                      The behavior is undefined if \p cond is
 *                      not set up.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      The condition variable is in an invalid state.
 *                      Note that such an error condition have undefined
 *                      behavior.
 */
int mbedtls_condition_variable_broadcast(mbedtls_threading_condition_t *cond);

/** Wait on a condition variable.
 *
 * On entry to this function, atomically unlock \p mutex and block until
 * another thread sends a signal on \p cond. When this happens, atomically
 * lock \p mutex and return.
 *
 * \note    On some platforms, mbedtls_condition_variable_wait() may
 *          return even if the condition variable has not been signalled
 *          (spurious wakeup). The mutex is unlocked normally even in
 *          that case.
 *
 * \param[in,out] cond  The condition variable to wait on.
 *                      The behavior is undefined if \p cond is
 *                      not set up.
 * \param[in,out] mutex The mutex to lock while not waiting.
 *                      The behavior is undefined if \p mutex is
 *                      not locked by the calling thread.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      The condition variable is in an invalid state.
 *                      Note that such an error condition have undefined
 *                      behavior.
 */
int mbedtls_condition_variable_wait(mbedtls_threading_condition_t *cond,
                                    mbedtls_threading_mutex_t *mutex);

/* Internal definition, kept in a public header until Mbed TLS stops
 * using it. */
#if defined(MBEDTLS_FS_IO)
extern mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex;
#endif
#endif /* MBEDTLS_THREADING_C */

#ifdef __cplusplus
}
#endif

#endif /* threading.h */
