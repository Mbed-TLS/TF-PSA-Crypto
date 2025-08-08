/**
 * \file platform_threading.h
 *
 * \brief Platform interface for threading.
 *
 * Alternative implementations of the threading abstraction need to
 * implement the header, types and functions documented in this file:
 *
 * - Provide a header file `"threading_alt.h"` that defines the following:
 *     - The type ::mbedtls_platform_mutex_t` of mutex objects.
 *     - The types ::mbedtls_platform_thread_object_t and
 *       ::mbedtls_platform_thread_return_t, and the macro
 *       ::MBEDTLS_PLATFORM_THREAD_RETURN_0. See the documentation
 *       of mbedtls_platform_thread_create().
 *
 * - Either define inline versions of the functions listed in this file
 *   in `"threading_alt.h"`, or provide linkable versions of the functions
 *   at link time.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PLATFORM_THREADING_H
#define MBEDTLS_PLATFORM_THREADING_H
#include "mbedtls/private_access.h"

#include "tf-psa-crypto/build_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_THREADING_C11)
#include <threads.h>
typedef mtx_t mbedtls_platform_mutex_t;
typedef thrd_t mbedtls_platform_thread_object_t;
typedef int mbedtls_platform_thread_return_t;
#define MBEDTLS_PLATFORM_THREAD_RETURN_0 0
#endif /* MBEDTLS_THREADING_C11 */

#if defined(MBEDTLS_THREADING_PTHREAD)
#include <pthread.h>
/** Type of a mutex object.
 *
 * Used by mbedtls_platform_mutex_init(), mbedtls_platform_mutex_free(),
 * mbedtls_platform_mutex_lock() and mbedtls_platform_mutex_unlock().
 */
typedef pthread_mutex_t mbedtls_platform_mutex_t;

/** Type of an active thread.
 *
 * Used by mbedtls_platform_thread_create() and
 * mbedtls_platform_thread_join().
 */
typedef pthread_t mbedtls_platform_thread_object_t;

/** Type returned by the function that implements a thread.
 *
 * This can be `void` if thread functions do not return a value on
 * your platform.
 *
 * See mbedtls_platform_thread_create().
 */
typedef void *mbedtls_platform_thread_return_t;

/** A value of type ::mbedtls_test_thread_return_t, to return from
 * a test thread function.
 *
 * This can be a macro with an empty expansion if
 * ::mbedtls_test_thread_return_t is `void`.
 */
#define MBEDTLS_PLATFORM_THREAD_RETURN_0 NULL
#endif /* MBEDTLS_THREADING_PTHREAD */

#if defined(MBEDTLS_THREADING_ALT)
#include "threading_alt.h"
#endif /* MBEDTLS_THREADING_ALT */

#if defined(MBEDTLS_THREADING_C)

/** Platform callback to initialize and set up a mutex.
 *
 * The mutex may not be used until one thread has completed a call to
 * this function.
 *
 * This function may allocate resources. mbedtls_platform_mutex_free()
 * should free these resources.
 *
 * \param[out] mutex    The mutex to initialize.
 *
 * \retval 0            Success.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *                      Insufficient memory. You may use this error code
 *                      to indicate that some other resource is exhausted
 *                      if no other error code is more suitable.
 * \retval #MBEDTLS_ERR_THREADING_MUTEX_ERROR
 *                      The mutex could not be set up.
 */
int mbedtls_platform_mutex_setup(mbedtls_platform_mutex_t *mutex);

/** Platform callback to destroy a mutex.
 *
 * This function frees any resource allocated by
 * mbedtls_platform_mutex_setup().
 *
 * As soon as one thread has started a call to this function,
 * no other thread may access the mutex in any way, including
 * concurrent calls to this function. Once the call returns,
 * you may call mbedtls_mutex_init() again on the mutex.
 *
 * \param[in,out] mutex The mutex to destroy.
 *                      It is guaranteed to have been set up and not
 *                      destroyed yet. Otherwise the behavior is undefined.
 */
void mbedtls_platform_mutex_destroy(mbedtls_platform_mutex_t *mutex);

/** Platform callback to lock a mutex.
 *
 * The mutex does not need to be recursive: the behavior of this function
 * is undefined if the mutex is already locked by the same thread.
 *
 * \param[in,out] mutex The mutex to lock.
 *                      It is guaranteed to have been initialized by
 *                      mbedtls_platform_mutex_init().
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_MUTEX_ERROR
 *                      The mutex could not be locked.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      The mutex is in an invalid state.
 */
int mbedtls_platform_mutex_lock(mbedtls_platform_mutex_t *mutex);

/** Platform callback to unlock a mutex.
 *
 * The behavior is undefined if the mutex is not currently locked or
 * if the mutex was locked by a different thread.
 *
 * \param[in,out] mutex The mutex to unlock.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_MUTEX_ERROR
 *                      The mutex could not be unlocked.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      The mutex is in an invalid state.
 */
int mbedtls_platform_mutex_unlock(mbedtls_platform_mutex_t *mutex);

/** The type of a function that implements a thread.
 *
 * \param[in,out] param A pointer to arbitrary data passed to the thread.
 *
 * \return #MBEDTLS_PLATFORM_THREAD_RETURN_0
 *
 * See mbedtls_platform_thread_create().
 */
typedef mbedtls_platform_thread_return_t (mbedtls_platform_thread_function_t)(void *param);

/** Platform callback to start a thread.
 *
 * \note    As of TF-PSA-Crypto 1.0 and Mbed TLS 4.0, there is no plan to
 *          ever call this function from the library. It is only meant to
 *          be used in sample programs and tests. If your platform does
 *          not provide a way to create threads at runtime, you can omit
 *          mbedtls_platform_thread_create() and mbedtls_platform_thread_join()
 *          or make them stub functions that always return an error.
 *          If you do this, you will be able to compile and use the library
 *          normally, but you will not be able to run some of the tests
 *          and sample programs.
 *
 * \param[out] thread   The object that will represent the active
 *                      or terminated thread.
 * \param[in] func      The code of the thread. This function is called
 *                      with one parameter which is \p param. If this
 *                      function returns a value other than
 *                      #MBEDTLS_PLATFORM_THREAD_RETURN_0, the behavior
 *                      is undefined.
 * \param[in,out] param A pointer to arbitrary data passed to the thread.
 *
 * \retval 0            Success.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *                      Insufficient memory. You may use this error code
 *                      to indicate that some other resource is exhausted
 *                      if no other error code is more suitable.
 * \retval ret          Any other negative value to indicate other errors.
 */
int mbedtls_platform_thread_create(mbedtls_platform_thread_object_t *thread,
                                   mbedtls_platform_thread_function_t *func,
                                   void *param);

/** Wait for a thread to exit.
 *
 * A thread exits by returning from its function.
 *
 * This abstraction does not provide a way to return a value from the thread
 * function. (Functions can store output in an object accessible via the
 * thread parameter.)
 *
 *
 *
 * \param[in,out] thread    The object that represents a thread.
 *                          The thread may be active or may already have
 *                          exited.
 *                          This is guaranteed to be an object populated
 *                          by mbedtls_platform_thread_create(), and on
 *                          which mbedtls_platform_thread_join() has not
 *                          been called yet. Otherwise the behavior is
 *                          undefined.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
 *                      Suggested error code if \p thread is invalid and
 *                      the implementation was able to detect it.
 */
int mbedtls_platform_thread_join(mbedtls_platform_thread_object_t *thread);

#endif /* MBEDTLS_THREADING_C */

#ifdef __cplusplus
}
#endif

#endif /* platform_threading.h */
