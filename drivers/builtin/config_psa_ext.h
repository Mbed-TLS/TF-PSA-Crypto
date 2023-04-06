/**
 * \file config_psa_ext.h
 * \brief PSA crypto configurations to Mbed TLS configurations extension
 *
 *  Extension of the translation of the PSA crypto configurations to the Mbed
 *  TLS ones handling the PSA-Crypto specific configuration options.
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

#if defined(PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
#define MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
#endif

#if defined(PSA_CRYPTO_SPM)
#define MBEDTLS_PSA_CRYPTO_SPM
#endif

#if !defined(PSA_CRYPTO_STD_FUNCTIONS)
#include <psa/platform.h>
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_PRINTF_MACRO  psa_crypto_printf
#define MBEDTLS_PLATFORM_FPRINTF_MACRO  psa_crypto_fprintf
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO  psa_crypto_snprintf
#define MBEDTLS_PLATFORM_SETBUF_MACRO  psa_crypto_setbuf
#if defined(PSA_CRYPTO_MEMORY_BUFFER_ALLOC)
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_MEMORY_ALIGN_MULTIPLE 8
#else
#define MBEDTLS_PLATFORM_CALLOC_MACRO  psa_crypto_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO  psa_crypto_free
#endif
#endif /* !PSA_CRYPTO_STD_FUNCTIONS */

#if defined(PSA_CRYPTO_FS_IO)
#define MBEDTLS_FS_IO
#endif

#if defined(PSA_CRYPTO_PLATFORM_ZEROIZE)
#define MBEDTLS_PLATFORM_ZEROIZE_ALT
#define mbedtls_platform_zeroize psa_crypto_platform_zeroize
#endif

#if defined(PSA_CRYPTO_BUILTIN_KEYS)
#define MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
#endif

#if defined(PSA_CRYPTO_STORAGE_C)
#define MBEDTLS_PSA_CRYPTO_STORAGE_C
#endif

#if defined(PSA_CRYPTO_ITS_FILE_C)
#define MBEDTLS_PSA_ITS_FILE_C
#endif

#if defined(PSA_CRYPTO_EXTERNAL_RNG)
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#else /* PSA_CRYPTO_EXTERNAL_RNG */
#define MBEDTLS_ENTROPY_C

#if defined(PSA_CRYPTO_HMAC_DRBG_HASH)
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C

/*
 * The macro PSA_CRYPTO_HMAC_DRBG_HASH defines the hash algorithm (SHA-256 or
 * SHA-512) to be used for HMAC for the PSA DRBG. It defines it using the PSA
 * macro identifying the hash algorithm. Those macros are not part of the
 * configuration macros thus they may not be defined at that point. As we need
 * to use the value of PSA_CRYPTO_HMAC_DRBG_HASH, which is equal to
 * PSA_ALG_SHA_256 or PSA_ALG_SHA_512 we need those macros to be defined. Their
 * specific values are not important here, they just have to be different.
 */
#if !defined(PSA_ALG_SHA_256)
#define PSA_ALG_SHA_256 1
#define PSA_ALG_SHA_512 2
#define UNDEFINE_PSA_ALG_SHA_256_512
#endif

#if (PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_256)
#define MBEDTLS_PSA_HMAC_DRBG_MD_TYPE MBEDTLS_MD_SHA256
#if !defined(MBEDTLS_SHA256_C)
#define MBEDTLS_SHA256_C
#endif
#endif /* PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_256 */

#if (PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_512)
#if !defined(MBEDTLS_SHA512_C)
#define MBEDTLS_SHA512_C
#endif
#define MBEDTLS_PSA_HMAC_DRBG_MD_TYPE MBEDTLS_MD_SHA512
#endif /* PSA_CRYPTO_HMAC_DRBG_HASH == PSA_ALG_SHA_512 */

/* Clean-up of the dummy values for PSA_ALG_SHA_256 and PSA_ALG_SHA_512 */
#if defined(UNDEFINE_PSA_ALG_SHA_256_512)
#undef PSA_ALG_SHA_256
#undef PSA_ALG_SHA_512
#undef UNDEFINE_PSA_ALG_SHA_256_512
#endif

#else  /* PSA_CRYPTO_HMAC_DRBG_HASH */

#define MBEDTLS_CTR_DRBG_C
#if !defined(MBEDTLS_AES_C)
#define MBEDTLS_AES_C
#endif

#endif /* !PSA_CRYPTO_HMAC_DRBG_HASH */

#if !defined(PSA_CRYPTO_PLATFORM_ENTROPY)
#define MBEDTLS_NO_PLATFORM_ENTROPY
#endif

#if defined(PSA_CRYPTO_ENTROPY_NV_SEED)
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_ENTROPY_NV_SEED
#if !defined(PSA_CRYPTO_STD_FUNCTIONS) || !defined(PSA_CRYPTO_FS_IO)
#include <psa/platform.h>
#define MBEDTLS_PLATFORM_NV_SEED_READ_MACRO  psa_crypto_platform_entropy_nv_seed_read
#define MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO  psa_crypto_platform_entropy_nv_seed_write
#endif
#endif /* PSA_CRYPTO_ENTROPY_NV_SEED */

#endif /* !PSA_CRYPTO_EXTERNAL_RNG */

#if defined(PSA_CRYPTO_KEY_SLOT_COUNT)
#define MBEDTLS_PSA_KEY_SLOT_COUNT PSA_CRYPTO_KEY_SLOT_COUNT
#endif

#if defined(PSA_CRYPTO_ENTROPY_NV_SEED_FILE)
#define MBEDTLS_PLATFORM_STD_NV_SEED_FILE PSA_CRYPTO_ENTROPY_NV_SEED_FILE
#endif
