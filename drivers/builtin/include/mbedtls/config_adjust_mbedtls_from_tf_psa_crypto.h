/**
 * \file config_adjust_mbedtls_from_tf_psa_crypto.h
 * \brief Adjust the configuration of the Mbed TLS builtin driver code from the
 *        TF-PSA-Crypto configuration.
 *
 * The TF-PSA-Crypto repository defines configuration options beyond the
 * PSA_WANT_ macros. This file enables the Mbed TLS configuration options as
 * needed to fulfill the needs of the TF-PSA-Crypto repository configuration.
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

#ifndef MBEDTLS_CONFIG_ADJUST_MBEDTLS_FROM_TF_PSA_CRYPTO_H
#define MBEDTLS_CONFIG_ADJUST_MBEDTLS_FROM_TF_PSA_CRYPTO_H

#if defined(TF_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
#define MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
#endif

#if defined(TF_PSA_CRYPTO_SPM)
#define MBEDTLS_PSA_CRYPTO_SPM
#endif

#if !defined(TF_PSA_CRYPTO_STD_FUNCTIONS)
#include <tf_psa_crypto/platform.h>
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_PRINTF_MACRO  tf_psa_crypto_printf
#define MBEDTLS_PLATFORM_FPRINTF_MACRO  tf_psa_crypto_fprintf
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO  tf_psa_crypto_snprintf
#define MBEDTLS_PLATFORM_SETBUF_MACRO  tf_psa_crypto_setbuf
#if defined(TF_PSA_CRYPTO_MEMORY_BUFFER_ALLOC)
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_MEMORY_ALIGN_MULTIPLE 8
#else
#define MBEDTLS_PLATFORM_CALLOC_MACRO  tf_psa_crypto_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO  tf_psa_crypto_free
#endif
#endif /* !TF_PSA_CRYPTO_STD_FUNCTIONS */

#if defined(TF_PSA_CRYPTO_FS_IO)
#define MBEDTLS_FS_IO
#endif

#if defined(TF_PSA_CRYPTO_PLATFORM_ZEROIZE)
#define MBEDTLS_PLATFORM_ZEROIZE_ALT
#define mbedtls_platform_zeroize tf_psa_crypto_platform_zeroize
#endif

#if defined(TF_PSA_CRYPTO_BUILTIN_KEYS)
#define MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
#endif

#if defined(TF_PSA_CRYPTO_STORAGE_C)
#define MBEDTLS_PSA_CRYPTO_STORAGE_C
#endif

#if defined(TF_PSA_CRYPTO_ITS_FILE_C)
#define MBEDTLS_PSA_ITS_FILE_C
#endif

#if defined(TF_PSA_CRYPTO_EXTERNAL_RNG)
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#else /* TF_PSA_CRYPTO_EXTERNAL_RNG */
#define MBEDTLS_ENTROPY_C

#if defined(TF_PSA_CRYPTO_HMAC_DRBG_HASH)
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C

/*
 * The macro TF_PSA_CRYPTO_HMAC_DRBG_HASH defines the hash algorithm (SHA-256 or
 * SHA-512) to be used for HMAC for the PSA DRBG. It defines it using the PSA
 * macro identifying the hash algorithm. Those macros are not part of the
 * configuration macros thus they may not be defined at that point. As we need
 * to use the value of TF_PSA_CRYPTO_HMAC_DRBG_HASH, which is equal to
 * PSA_ALG_SHA_256 or PSA_ALG_SHA_512 we need those macros to be defined. Their
 * specific values are not important here, they just have to be different.
 */
#if !defined(PSA_ALG_SHA_256)
#define PSA_ALG_SHA_256 1
#define PSA_ALG_SHA_512 2
#define UNDEFINE_PSA_ALG_SHA_256_512
#endif

#if (TF_PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_256)
#define MBEDTLS_PSA_HMAC_DRBG_MD_TYPE MBEDTLS_MD_SHA256
#if !defined(MBEDTLS_SHA256_C)
#define MBEDTLS_SHA256_C
#endif
#endif /* TF_PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_256 */

#if (TF_PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_512)
#if !defined(MBEDTLS_SHA512_C)
#define MBEDTLS_SHA512_C
#endif
#define MBEDTLS_PSA_HMAC_DRBG_MD_TYPE MBEDTLS_MD_SHA512
#endif /* TF_PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_512 */

/* Clean-up of the dummy values for PSA_ALG_SHA_256 and PSA_ALG_SHA_512 */
#if defined(UNDEFINE_PSA_ALG_SHA_256_512)
#undef PSA_ALG_SHA_256
#undef PSA_ALG_SHA_512
#undef UNDEFINE_PSA_ALG_SHA_256_512
#endif

#else  /* TF_PSA_CRYPTO_HMAC_DRBG_HASH */

#define MBEDTLS_CTR_DRBG_C
#if !defined(MBEDTLS_AES_C)
#define MBEDTLS_AES_C
#endif

#endif /* !TF_PSA_CRYPTO_HMAC_DRBG_HASH */

#if !defined(TF_PSA_CRYPTO_PLATFORM_ENTROPY)
#define MBEDTLS_NO_PLATFORM_ENTROPY
#endif

#if defined(TF_PSA_CRYPTO_HARDWARE_ENTROPY)
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define mbedtls_hardware_poll tf_psa_crypto_hardware_entropy
#endif

#if defined(TF_PSA_CRYPTO_ENTROPY_NV_SEED)
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_ENTROPY_NV_SEED
#if !defined(TF_PSA_CRYPTO_STD_FUNCTIONS) || !defined(TF_PSA_CRYPTO_FS_IO)
#include <tf_psa_crypto/platform.h>
#define MBEDTLS_PLATFORM_NV_SEED_READ_MACRO  tf_psa_crypto_platform_entropy_nv_seed_read
#define MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO  tf_psa_crypto_platform_entropy_nv_seed_write
#endif
#endif /* TF_PSA_CRYPTO_ENTROPY_NV_SEED */

#endif /* !TF_PSA_CRYPTO_EXTERNAL_RNG */

#if defined(TF_PSA_CRYPTO_KEY_SLOT_COUNT)
#define MBEDTLS_PSA_KEY_SLOT_COUNT TF_PSA_CRYPTO_KEY_SLOT_COUNT
#endif

#if defined(TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE)
#define MBEDTLS_PLATFORM_STD_NV_SEED_FILE TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE
#endif

/* PSA driver interface implementation configuration options */

#if defined(TF_PSA_CRYPTO_HAVE_ASM)
#define MBEDTLS_HAVE_ASM
#endif

#if defined(TF_PSA_CRYPTO_AESNI_C)
#define MBEDTLS_AESNI_C
#endif

#if defined(TF_PSA_CRYPTO_AESCE_C)
#define MBEDTLS_AESCE_C
#endif

#if defined(TF_PSA_CRYPTO_NO_UDBL_DIVISION)
#define MBEDTLS_NO_UDBL_DIVISION
#endif

#if defined(TF_PSA_CRYPTO_NO_64BIT_MULTIPLICATION)
#define MBEDTLS_NO_64BIT_MULTIPLICATION
#endif

#if defined(TF_PSA_CRYPTO_AES_ROM_TABLES)
#define MBEDTLS_AES_ROM_TABLES
#endif

#if defined(TF_PSA_CRYPTO_AES_FEWER_TABLES)
#define MBEDTLS_AES_FEWER_TABLES
#endif

#if defined(TF_PSA_CRYPTO_CAMELLIA_SMALL_MEMORY)
#define MBEDTLS_CAMELLIA_SMALL_MEMORY
#endif

#if defined(TF_PSA_CRYPTO_ECP_NIST_OPTIM)
#define MBEDTLS_ECP_NIST_OPTIM
#endif

#if defined(TF_PSA_CRYPTO_SHA256_SMALLER)
#define MBEDTLS_SHA256_SMALLER
#endif

#if defined(TF_PSA_CRYPTO_SHA512_SMALLER)
#define MBEDTLS_SHA512_SMALLER
#endif

#if defined(TF_PSA_CRYPTO_WANT_LMS)
#define MBEDTLS_LMS_C
#endif

#endif /* MBEDTLS_CONFIG_ADJUST_MBEDTLS_FROM_TF_PSA_CRYPTO_H */
