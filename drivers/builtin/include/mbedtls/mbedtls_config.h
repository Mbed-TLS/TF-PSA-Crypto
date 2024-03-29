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
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
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
