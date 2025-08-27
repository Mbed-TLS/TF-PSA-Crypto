/**
 * \file crypto_unified_errors.h
 *
 * \brief Contains definitions of unified error codes for public modules.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_PRIVATE_CRYPTO_UNIFIED_ERRORS_H
#define MBEDTLS_PRIVATE_CRYPTO_UNIFIED_ERRORS_H

/** Output buffer too small. */
#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL               PSA_ERROR_BUFFER_TOO_SMALL
/** Buffer too small when writing ASN.1 data structure. */
#define MBEDTLS_ERR_ASN1_BUF_TOO_SMALL                    PSA_ERROR_BUFFER_TOO_SMALL
/** Input/output buffer is too small to contain requited data */
#define MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL                  PSA_ERROR_BUFFER_TOO_SMALL
/** The output buffer is too small. */
#define MBEDTLS_ERR_PK_BUFFER_TOO_SMALL                   PSA_ERROR_BUFFER_TOO_SMALL
/** Buffer is too small to hold the data. */
#define MBEDTLS_ERR_NET_BUFFER_TOO_SMALL                  PSA_ERROR_BUFFER_TOO_SMALL
/** A buffer is too small to receive or write a message */
#define MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL                  PSA_ERROR_BUFFER_TOO_SMALL
/** Destination buffer is too small. */
#define MBEDTLS_ERR_X509_BUFFER_TOO_SMALL                 PSA_ERROR_BUFFER_TOO_SMALL

/** Memory allocation failed. */
#define MBEDTLS_ERR_PK_ALLOC_FAILED                       PSA_ERROR_INSUFFICIENT_MEMORY
/** Failed to allocate memory. */
#define MBEDTLS_ERR_PEM_ALLOC_FAILED                      PSA_ERROR_INSUFFICIENT_MEMORY
/** Memory allocation failed */
#define MBEDTLS_ERR_ASN1_ALLOC_FAILED                     PSA_ERROR_INSUFFICIENT_MEMORY
/** LMS failed to allocate space for a private key */
#define MBEDTLS_ERR_LMS_ALLOC_FAILED                      PSA_ERROR_INSUFFICIENT_MEMORY
/** Allocation of memory failed. */
#define MBEDTLS_ERR_PKCS7_ALLOC_FAILED                    PSA_ERROR_INSUFFICIENT_MEMORY
/** Memory allocation failed */
#define MBEDTLS_ERR_SSL_ALLOC_FAILED                      PSA_ERROR_INSUFFICIENT_MEMORY
/** Allocation of memory failed. */
#define MBEDTLS_ERR_X509_ALLOC_FAILED                     PSA_ERROR_INSUFFICIENT_MEMORY

/** Bad input parameters to function. */
#define MBEDTLS_ERR_PK_BAD_INPUT_DATA                     PSA_ERROR_INVALID_ARGUMENT
/** Bad input parameters to function. */
#define MBEDTLS_ERR_PEM_BAD_INPUT_DATA                    PSA_ERROR_INVALID_ARGUMENT
/** Bad input parameters to function. */
#define MBEDTLS_ERR_THREADING_BAD_INPUT_DATA              PSA_ERROR_INVALID_ARGUMENT
/** Bad data has been input to an LMS function */
#define MBEDTLS_ERR_LMS_BAD_INPUT_DATA                    PSA_ERROR_INVALID_ARGUMENT
/** Input invalid. */
#define MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA                  PSA_ERROR_INVALID_ARGUMENT
/** Bad input parameters to function. */
#define MBEDTLS_ERR_SSL_BAD_INPUT_DATA                    PSA_ERROR_INVALID_ARGUMENT
/** Input invalid. */
#define MBEDTLS_ERR_X509_BAD_INPUT_DATA                   PSA_ERROR_INVALID_ARGUMENT

/** Error parsing the signature */
#define MBEDTLS_ERR_PKCS7_INVALID_SIGNATURE               PSA_ERROR_INVALID_SIGNATURE
/** Verification Failed */
#define MBEDTLS_ERR_PKCS7_VERIFY_FAIL                     PSA_ERROR_INVALID_SIGNATURE
/** The signature tag or value invalid. */
#define MBEDTLS_ERR_X509_INVALID_SIGNATURE                PSA_ERROR_INVALID_SIGNATURE
/** Certificate verification failed, e.g. CRL, CA or signature check failed. */
#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED               PSA_ERROR_INVALID_SIGNATURE

#endif /* MBEDTLS_PRIVATE_CRYPTO_UNIFIED_ERRORS_H */
