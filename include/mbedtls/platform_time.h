/**
 * \file platform_time.h
 *
 * \brief Mbed TLS Platform time abstraction
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PLATFORM_TIME_H
#define MBEDTLS_PLATFORM_TIME_H

#include "tf-psa-crypto/build_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief   The type used for representing time values in Mbed TLS.
 *
 * By default this is time_t as defined in <time.h>. This type may be
 * overridden by defining #MBEDTLS_PLATFORM_TIME_TYPE_MACRO to a suitable
 * scalar arithmetic type (for example int64_t or uint32_t).
 *
 * Mbed TLS uses values of this type in the following ways:
 * - Subtraction and comparison of two mbedtls_time_t values, to measure
 *   elapsed time (for example for TLS session ticket lifetime, session
 *   cache timeout, and DTLS cookie timeout).
 * - Conversion to unsigned integer types when encoding protocol fields
 *   (for example, the gmt_unix_time field of a TLS 1.2 ClientHello or
 *   ServerHello, encoded as uint32_t, and the session start time in
 *   serialized session data, encoded as uint64_t).
 * - Passing by pointer to mbedtls_platform_gmtime_r() as
 *   const mbedtls_time_t *, to convert a time value to calendar date
 *   and time, when #MBEDTLS_HAVE_TIME_DATE is enabled.
 *
 * Time values of this type represent seconds since the Unix epoch
 * (1970-01-01 00:00:00 UTC).
 */
#if defined(MBEDTLS_PLATFORM_TIME_TYPE_MACRO)
typedef MBEDTLS_PLATFORM_TIME_TYPE_MACRO mbedtls_time_t;
#else
/* For time_t */
#include <time.h>
typedef time_t mbedtls_time_t;
#endif /* MBEDTLS_PLATFORM_TIME_TYPE_MACRO */

#if defined(MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO)
typedef MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO mbedtls_ms_time_t;
#else
#include <stdint.h>
#include <inttypes.h>
typedef int64_t mbedtls_ms_time_t;
#endif /* MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO */

/**
 * \brief   Get time in milliseconds.
 *
 * \return Monotonically-increasing current time in milliseconds.
 *
 * \note Define MBEDTLS_PLATFORM_MS_TIME_ALT to be able to provide an
 *       alternative implementation
 *
 * \warning This function returns a monotonically-increasing time value from a
 *          start time that will differ from platform to platform, and possibly
 *          from run to run of the process.
 *
 */
mbedtls_ms_time_t mbedtls_ms_time(void);

/*
 * The function pointers for time
 */
#if defined(MBEDTLS_PLATFORM_TIME_ALT)
extern mbedtls_time_t (*mbedtls_time)(mbedtls_time_t *time);

/**
 * \brief   Set your own time function pointer
 *
 * \param   time_func   the time function implementation
 *
 * \return              0
 */
int mbedtls_platform_set_time(mbedtls_time_t (*time_func)(mbedtls_time_t *time));
#else
#if defined(MBEDTLS_PLATFORM_TIME_MACRO)
#define mbedtls_time    MBEDTLS_PLATFORM_TIME_MACRO
#else
#define mbedtls_time   time
#endif /* MBEDTLS_PLATFORM_TIME_MACRO */
#endif /* MBEDTLS_PLATFORM_TIME_ALT */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PLATFORM_TIME_H */
