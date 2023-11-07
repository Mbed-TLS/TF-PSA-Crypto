/**
 * \file mbedtls_config.h
 *
 * \brief Configuration options (set of defines) for PSA cryptography
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CONFIG
#define MBEDTLS_CIPHER_C /* Prerequisite of MBEDTLS_PSA_CRYPTO_C */
#define MBEDTLS_USE_PSA_CRYPTO

/*
 * Note: The below config options are used internally for testing only.
 *       They are not meant to be used for configuring TF-PSA-Crypto.
 */

//#define MBEDTLS_BASE64_C
//#define MBEDTLS_DHM_C
//#define MBEDTLS_ECP_WITH_MPI_UINT
//#define MBEDTLS_NIST_KW_C
//#define MBEDTLS_PEM_PARSE_C
//#define MBEDTLS_PEM_WRITE_C
//#define MBEDTLS_PKCS5_C
//#define MBEDTLS_PKCS12_C
