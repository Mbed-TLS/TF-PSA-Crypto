/**
 * \file psa/error.h
 *
 * \brief Standard error codes from PSA Certified status code API.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef __PSA_ERROR_H__
#define __PSA_ERROR_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* If #PSA_SUCCESS is already defined, it means that #psa_status_t
 * is also defined in an external header, so prevent its multiple
 * definition.
 */
#ifndef PSA_SUCCESS
typedef int32_t psa_status_t;
#endif

/* >= 1 is reserved for Success error codes which are API-specific (RoT services) */
#define PSA_SUCCESS                     ((psa_status_t)0)
/* -1 to -128 is reserved for API-specific (RoT services) error codes */

/** A status code that indicates a PROGRAMMER ERROR in the client
 * 
 * This error indicates that the function has detected an abnormal call, which
 * typically indicates a programming error in the caller, or an abuse of the
 * API. */
#define PSA_ERROR_PROGRAMMER_ERROR      ((psa_status_t)-129)

/** A status code that indicates that the caller is not permitted to connect to
 * a Service. */
#define PSA_ERROR_CONNECTION_REFUSED    ((psa_status_t)-130)

/** A status code that indicates that the caller cannot connect to a service.
 */
#define PSA_ERROR_CONNECTION_BUSY       ((psa_status_t)-131)

/** An error occurred that does not correspond to any defined
 * failure cause.
 *
 * Implementations may use this error code if none of the other standard
 * error codes are applicable. */
#define PSA_ERROR_GENERIC_ERROR         ((psa_status_t)-132)

/** The requested action is denied by a policy.
 *
 * Implementations should return this error code when the parameters
 * are recognized as valid and supported, and a policy explicitly
 * denies the requested operation.
 *
 * If a subset of the parameters of a function call identify a
 * forbidden operation, and another subset of the parameters are
 * not valid or not supported, it is unspecified whether the function
 * returns #PSA_ERROR_NOT_PERMITTED, #PSA_ERROR_NOT_SUPPORTED or
 * #PSA_ERROR_INVALID_ARGUMENT. */
#define PSA_ERROR_NOT_PERMITTED         ((psa_status_t)-133)

/** The requested operation or a parameter is not supported
 * by this implementation.
 *
 * Implementations should return this error code when an enumeration
 * parameter such as a key type, algorithm, etc. is not recognized.
 * If a combination of parameters is recognized and identified as
 * not valid, return #PSA_ERROR_INVALID_ARGUMENT instead. */
#define PSA_ERROR_NOT_SUPPORTED         ((psa_status_t)-134)

/** The parameters passed to the function are invalid.
 *
 * Implementations may return this error any time a parameter or
 * combination of parameters are recognized as invalid.
 *
 * Implementations shall not return this error code to indicate that a
 * key identifier is invalid, but shall return #PSA_ERROR_INVALID_HANDLE
 * instead.
 */
#define PSA_ERROR_INVALID_ARGUMENT      ((psa_status_t)-135)

/** The key identifier is not valid. See also :ref:\`key-handles\`.
 */
#define PSA_ERROR_INVALID_HANDLE        ((psa_status_t)-136)

/** The requested action cannot be performed in the current state.
 *
 * Multipart operations return this error when one of the
 * functions is called out of sequence. Refer to the function
 * descriptions for permitted sequencing of functions.
 *
 * Implementations shall not return this error code to indicate
 * that a key either exists or not,
 * but shall instead return #PSA_ERROR_ALREADY_EXISTS or
 * #PSA_ERROR_DOES_NOT_EXIST as applicable.
 *
 * Implementations shall not return this error code to indicate that a
 * key identifier is invalid, but shall return #PSA_ERROR_INVALID_HANDLE
 * instead. */
#define PSA_ERROR_BAD_STATE             ((psa_status_t)-137)

/** An output buffer is too small.
 *
 * Applications can call the \c PSA_xxx_SIZE macro listed in the function
 * description to determine a sufficient buffer size.
 *
 * Implementations should preferably return this error code only
 * in cases when performing the operation with a larger output
 * buffer would succeed. However implementations may return this
 * error if a function has invalid or unsupported parameters in addition
 * to the parameters that determine the necessary output buffer size. */
#define PSA_ERROR_BUFFER_TOO_SMALL      ((psa_status_t)-138)

/** Asking for an item that already exists
 *
 * Implementations should return this error, when attempting
 * to write an item (like a key) that already exists. */
#define PSA_ERROR_ALREADY_EXISTS        ((psa_status_t)-139)

/** Asking for an item that doesn't exist
 *
 * Implementations should return this error, if a requested item (like
 * a key) does not exist. */
#define PSA_ERROR_DOES_NOT_EXIST        ((psa_status_t)-140)

/** There is not enough runtime memory.
 *
 * If the action is carried out across multiple security realms, this
 * error can refer to available memory in any of the security realms. */
#define PSA_ERROR_INSUFFICIENT_MEMORY   ((psa_status_t)-141)

/** There is not enough persistent storage.
 *
 * Functions that modify the key storage return this error code if
 * there is insufficient storage space on the host media. In addition,
 * many functions that do not otherwise access storage may return this
 * error code if the implementation requires a mandatory log entry for
 * the requested action and the log storage space is full. */
#define PSA_ERROR_INSUFFICIENT_STORAGE  ((psa_status_t)-142)

/** Return this error when there's insufficient data when attempting
 * to read from a resource. */
#define PSA_ERROR_INSUFFICIENT_DATA     ((psa_status_t)-143)

/** This can be returned if a function can no longer operate correctly.
 * For example, if an essential initialization operation failed or
 * a mutex operation failed. */
#define PSA_ERROR_SERVICE_FAILURE       ((psa_status_t)-144)

/** There was a communication failure inside the implementation.
 *
 * This can indicate a communication failure between the application
 * and an external cryptoprocessor or between the cryptoprocessor and
 * an external volatile or persistent memory. A communication failure
 * may be transient or permanent depending on the cause.
 *
 * \warning If a function returns this error, it is undetermined
 * whether the requested action has completed or not. Implementations
 * should return #PSA_SUCCESS on successful completion whenever
 * possible, however functions may return #PSA_ERROR_COMMUNICATION_FAILURE
 * if the requested action was completed successfully in an external
 * cryptoprocessor but there was a breakdown of communication before
 * the cryptoprocessor could report the status to the application.
 */
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t)-145)

/** There was a storage failure that may have led to data loss.
 *
 * This error indicates that some persistent storage is corrupted.
 * It should not be used for a corruption of volatile memory
 * (use #PSA_ERROR_CORRUPTION_DETECTED), for a communication error
 * between the cryptoprocessor and its external storage (use
 * #PSA_ERROR_COMMUNICATION_FAILURE), or when the storage is
 * in a valid state but is full (use #PSA_ERROR_INSUFFICIENT_STORAGE).
 *
 * Note that a storage failure does not indicate that any data that was
 * previously read is invalid. However this previously read data may no
 * longer be readable from storage.
 *
 * When a storage failure occurs, it is no longer possible to ensure
 * the global integrity of the keystore. Depending on the global
 * integrity guarantees offered by the implementation, access to other
 * data may or may not fail even if the data is still readable but
 * its integrity cannot be guaranteed.
 *
 * Implementations should only use this error code to report a
 * permanent storage corruption. However application writers should
 * keep in mind that transient errors while reading the storage may be
 * reported using this error code. */
#define PSA_ERROR_STORAGE_FAILURE       ((psa_status_t)-146)

/** A hardware failure was detected.
 *
 * A hardware failure may be transient or permanent depending on the
 * cause. */
#define PSA_ERROR_HARDWARE_FAILURE      ((psa_status_t)-147)

/* -148 is reserved for PSA Certified APIs */

/** The signature, MAC or hash is incorrect.
 *
 * Verification functions return this error if the verification
 * calculations completed successfully, and the value to be verified
 * was determined to be incorrect.
 *
 * If the value to verify has an invalid size, implementations may return
 * either #PSA_ERROR_INVALID_ARGUMENT or #PSA_ERROR_INVALID_SIGNATURE. */
#define PSA_ERROR_INVALID_SIGNATURE     ((psa_status_t)-149)
/* -150 is reserved for PSA Certified APIs */

/** A tampering attempt was detected.
 *
 * If an application receives this error code, there is no guarantee
 * that previously accessed or computed data was correct and remains
 * confidential. Applications should not perform any security function
 * and should enter a safe failure state.
 *
 * Implementations may return this error code if they detect an invalid
 * state that cannot happen during normal operation and that indicates
 * that the implementation's security guarantees no longer hold. Depending
 * on the implementation architecture and on its security and safety goals,
 * the implementation may forcibly terminate the application.
 *
 * This error code is intended as a last resort when a security breach
 * is detected and it is unsure whether the keystore data is still
 * protected. Implementations shall only return this error code
 * to report an alarm from a tampering detector, to indicate that
 * the confidentiality of stored data can no longer be guaranteed,
 * or to indicate that the integrity of previously returned data is now
 * considered compromised. Implementations shall not use this error code
 * to indicate a hardware failure that merely makes it impossible to
 * perform the requested operation (use #PSA_ERROR_COMMUNICATION_FAILURE,
 * #PSA_ERROR_STORAGE_FAILURE, #PSA_ERROR_HARDWARE_FAILURE,
 * #PSA_ERROR_INSUFFICIENT_ENTROPY or other applicable error code
 * instead).
 *
 * This error indicates an attack against the application. Implementations
 * shall not return this error code as a consequence of the behavior of
 * the application itself. */
#define PSA_ERROR_CORRUPTION_DETECTED   ((psa_status_t)-151)

/** Stored data has been corrupted.
 *
 * This error indicates that some persistent storage has suffered corruption.
 * It does not indicate the following situations, which have specific error
 * codes:
 *
 * - A corruption of volatile memory - use #PSA_ERROR_CORRUPTION_DETECTED.
 * - A communication error between the cryptoprocessor and its external
 *   storage - use #PSA_ERROR_COMMUNICATION_FAILURE.
 * - When the storage is in a valid state but is full - use
 *   #PSA_ERROR_INSUFFICIENT_STORAGE.
 * - When the storage fails for other reasons - use
 *   #PSA_ERROR_STORAGE_FAILURE.
 * - When the stored data is not valid - use #PSA_ERROR_DATA_INVALID.
 *
 * \note A storage corruption does not indicate that any data that was
 * previously read is invalid. However this previously read data might no
 * longer be readable from storage.
 *
 * When a storage failure occurs, it is no longer possible to ensure the
 * global integrity of the keystore.
 */
#define PSA_ERROR_DATA_CORRUPT          ((psa_status_t)-152)

/** Data read from storage is not valid for the implementation.
 *
 * This error indicates that some data read from storage does not have a valid
 * format. It does not indicate the following situations, which have specific
 * error codes:
 *
 * - When the storage or stored data is corrupted - use #PSA_ERROR_DATA_CORRUPT
 * - When the storage fails for other reasons - use #PSA_ERROR_STORAGE_FAILURE
 * - An invalid argument to the API - use #PSA_ERROR_INVALID_ARGUMENT
 *
 * This error is typically a result of either storage corruption on a
 * cleartext storage backend, or an attempt to read data that was
 * written by an incompatible version of the library.
 */
#define PSA_ERROR_DATA_INVALID          ((psa_status_t)-153)

/* -154 to -247 is reserved for PSA Certified APIs */

/** The function that returns this status is defined as interruptible and
 *  still has work to do, thus the user should call the function again with the
 *  same operation context until it either returns #PSA_SUCCESS or any other
 *  error. This is not an error per se, more a notification of status.
 */
#define PSA_OPERATION_INCOMPLETE        ((psa_status_t) - 248)
/* -249 to -256 is reserved for the SPM implementation */
/* <= -257 is reserved for API-specific (RoT services) error codes */

#ifdef __cplusplus
}
#endif

#endif /* __PSA_ERROR_H__ */
