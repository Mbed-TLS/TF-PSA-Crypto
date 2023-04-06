/**
 * \file configs/ccm-aes-sha256.h
 *
 * \brief PSA crypto configuration with only symmetric cryptography: CCM-AES,
 *        SHA-256, HMAC and key derivation
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

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

/**
 * \name SECTION: General configuration options
 *
 * \{
 */

//#define PSA_CRYPTO_SPM
//#define PSA_CRYPTO_STD_FUNCTIONS
#define PSA_CRYPTO_FS_IO
#define PSA_CRYPTO_MEMORY_BUFFER_ALLOC
//#define PSA_CRYPTO_PLATFORM_ZEROIZE

/** \} name SECTION: General configuration options */

/**
 * \name SECTION: PSA cryptography interface configuration
 *
 * This section allows for configuring the PSA cryptography interface as
 * specified in psa-conditional-inclusion-c.md.
 *
 * \{
 */

#define PSA_WANT_ALG_CCM 1
#define PSA_WANT_ALG_HMAC 1
#define PSA_WANT_ALG_SHA_256 1
#define PSA_WANT_ALG_TLS12_PRF 1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS 1
#define PSA_WANT_KEY_TYPE_DERIVE 1
#define PSA_WANT_KEY_TYPE_HMAC 1
#define PSA_WANT_KEY_TYPE_AES 1
#define PSA_WANT_KEY_TYPE_RAW_DATA 1

/** \} name SECTION: PSA cryptography interface configuration */

/**
 * \name SECTION: PSA cryptography core configuration options
 *
 * This section allows for the configuration of the PSA cryptography core
 * which provides the key management, the generation of random numbers and
 * the dispatch to drivers.
 * \{
 */

#define PSA_CRYPTO_KEY_ID_ENCODES_OWNER
//#define PSA_CRYPTO_BUILTIN_KEYS
//#define PSA_CRYPTO_EXTERNAL_RNG
#define PSA_CRYPTO_STORAGE_C
#define PSA_CRYPTO_ITS_FILE_C
//#define PSA_CRYPTO_HMAC_DRBG_HASH PSA_ALG_SHA_256
//#define PSA_CRYPTO_KEY_SLOT_COUNT 32
//#define PSA_CRYPTO_PLATFORM_ENTROPY
#define PSA_CRYPTO_ENTROPY_NV_SEED
//#define PSA_CRYPTO_ENTROPY_NV_SEED_FILE "seedfile"

/** \} name SECTION: PSA cryptography core configuration options */

/**
 * \name SECTION: PSA driver interface implementation configuration options
 *
 * This section allows for the configuration of the PSA cryptography driver
 * interface implementation which implements the PSA cryptographic mechanisms.
 * \{
 */

#define PSA_CRYPTO_HAVE_ASM
//#define PSA_CRYPTO_NO_UDBL_DIVISION
#define PSA_CRYPTO_NO_64BIT_MULTIPLICATION
#define PSA_CRYPTO_AES_ROM_TABLES
#define PSA_CRYPTO_AES_FEWER_TABLES
//#define PSA_CRYPTO_CAMELLIA_SMALL_MEMORY
//#define PSA_CRYPTO_ECC_NIST_OPTIM
#define PSA_CRYPTO_SHA256_SMALLER
//#define PSA_CRYPTO_SHA512_SMALLER

/** \} name SECTION: PSA driver interface implementation configuration options */

#endif /* PSA_CRYPTO_CONFIG_H */
