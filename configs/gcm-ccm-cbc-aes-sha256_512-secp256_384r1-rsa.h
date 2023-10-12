/**
 * \file psa/gcm-ccm-cbc-aes-sha256_512-secp256_384r1-rsa
 *
 * \brief TF-PSA-Crypto configuration with symmetric cryptography and
 *        asymmetric cryptography based on the secp256r1 or secp384r1 elliptic
 *        curves or RSA: GCM/CCM/CBC-AES, SHA-256, SHA-512, HMAC, ECDSA, ECDH,
 *        RSA-PKCS#1 v1.5, RSA-OAEP, RSA-PSS and key derivation.
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

#ifndef TF_PSA_CRYPTO_GCM_CCM_CBC_AES_SHA256_512_SECP256_384R1_RSA_H
#define TF_PSA_CRYPTO_GCM_CCM_CBC_AES_SHA256_512_SECP256_384R1_RSA_H

/**
 * \name SECTION: General configuration options
 *
 * \{
 */

//#define TF_PSA_CRYPTO_SPM
//#define TF_PSA_CRYPTO_STD_FUNCTIONS
#define TF_PSA_CRYPTO_FS_IO
#define TF_PSA_CRYPTO_MEMORY_BUFFER_ALLOC
//#define TF_PSA_CRYPTO_PLATFORM_ZEROIZE

/** \} name SECTION: General configuration options */

/**
 * \name SECTION: PSA cryptography interface configuration
 *
 * This section allows for configuring the PSA cryptography interface as
 * specified in psa-conditional-inclusion-c.md.
 *
 * \{
 */

#define PSA_WANT_ALG_CBC_NO_PADDING 1
#define PSA_WANT_ALG_CBC_PKCS7 1
#define PSA_WANT_ALG_CCM 1
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA 1
#define PSA_WANT_ALG_ECDH 1
#define PSA_WANT_ALG_ECDSA 1
#define PSA_WANT_ALG_GCM 1
#define PSA_WANT_ALG_HKDF 1
#define PSA_WANT_ALG_HMAC 1
#define PSA_WANT_ALG_RSA_OAEP 1
#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT 1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN 1
#define PSA_WANT_ALG_RSA_PSS 1
#define PSA_WANT_ALG_SHA_256 1
#define PSA_WANT_ALG_SHA_512 1
#define PSA_WANT_ALG_TLS12_PRF 1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS 1
#define PSA_WANT_ECC_SECP_R1_256 1
#define PSA_WANT_ECC_SECP_R1_384 1
#define PSA_WANT_KEY_TYPE_DERIVE 1
#define PSA_WANT_KEY_TYPE_HMAC 1
#define PSA_WANT_KEY_TYPE_AES 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR 1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY 1
#define PSA_WANT_KEY_TYPE_RAW_DATA 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR 1
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY 1

/** \} name SECTION: PSA cryptography interface configuration */

/**
 * \name SECTION: PSA cryptography core configuration options
 *
 * This section allows for the configuration of the PSA cryptography core
 * which provides the key management, the generation of random numbers and
 * the dispatch to drivers.
 * \{
 */

#define TF_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
//#define TF_PSA_CRYPTO_BUILTIN_KEYS
//#define TF_PSA_CRYPTO_EXTERNAL_RNG
#define TF_PSA_CRYPTO_STORAGE_C
#define TF_PSA_CRYPTO_ITS_FILE_C
//#define TF_PSA_CRYPTO_HMAC_DRBG_HASH PSA_ALG_SHA_256
//#define TF_PSA_CRYPTO_KEY_SLOT_COUNT 32
//#define TF_PSA_CRYPTO_PLATFORM_ENTROPY
//#define TF_PSA_CRYPTO_HARDWARE_ENTROPY
#define TF_PSA_CRYPTO_ENTROPY_NV_SEED
#define TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE "seedfile"

/** \} name SECTION: PSA cryptography core configuration options */

/**
 * \name SECTION: PSA driver interface implementation configuration options
 *
 * This section allows for the configuration of the PSA cryptography driver
 * interface implementation which implements the PSA cryptographic mechanisms.
 * \{
 */

#define TF_PSA_CRYPTO_HAVE_ASM
//#define TF_PSA_CRYPTO_NO_UDBL_DIVISION
#define TF_PSA_CRYPTO_NO_64BIT_MULTIPLICATION
#define TF_PSA_CRYPTO_AES_ROM_TABLES
#define TF_PSA_CRYPTO_AES_FEWER_TABLES
//#define TF_PSA_CRYPTO_CAMELLIA_SMALL_MEMORY
#define TF_PSA_CRYPTO_ECP_NIST_OPTIM
#define TF_PSA_CRYPTO_SHA256_SMALLER
//#define TF_PSA_CRYPTO_SHA512_SMALLER

/** \} name SECTION: PSA driver interface implementation configuration options */

#endif /* TF_PSA_CRYPTO_GCM_CCM_CBC_AES_SHA256_512_SECP256_384R1_RSA_H */
