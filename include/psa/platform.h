/**
 * \file platform.h
 *
 * \brief This file contains the definition of the PSA cryptography platform
 *        abstraction layer.
 *
 *        The platform abstraction layer removes the need for the library
 *        to directly link to some standard C library functions or operating
 *        system services, making the library easier to port and embed.
 *        Application developers and users of the library can provide their own
 *        implementations of these functions that may be specific to their
 *        platform.
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
#ifndef PSA_PLATFORM_H
#define PSA_PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>

/**
 * \def PSA_CRYPTO_PRINTF_ATTRIBUTE
 *
 * Mark a function as having printf attributes, and thus enable checking
 * via -wFormat and other flags. This does nothing on builds with compilers
 * that do not support the format attribute
 *
 * This macro is intended to be used to qualify the plaform specific
 * implementations of functions of the printf family.
 */
#if defined(__has_attribute)
#if __has_attribute(format)
#define PSA_CRYPTO_PRINTF_ATTRIBUTE(string_index, first_to_check)    \
    __attribute__((format(printf, string_index, first_to_check)))
#else /* __has_attribute(format) */
#define PSA_CRYPTO_PRINTF_ATTRIBUTE(string_index, first_to_check)
#endif /* __has_attribute(format) */
#else /* defined(__has_attribute) */
#define PSA_CRYPTO_PRINTF_ATTRIBUTE(string_index, first_to_check)
#endif

/*
 * If the configuration option PSA_CRYPTO_STD_FUNCTIONS is enabled (default),
 * the following platform abstraction functions are just aliases to the
 * corresponding standard C library functions. Otherwise, these functions have
 * to be provided as part of the integration of the PSA cryptography library.
 * They should behave as the corresponding standard C library functions as
 * defined in the C99 specification.
 *
 * If the configuration option PSA_CRYPTO_STD_FUNCTIONS is disabled and
 * PSA_CRYPTO_MEMORY_BUFFER_ALLOC is enabled the library buffer allocator
 * implementation is included in the build and the library uses it to allocate
 * and free memory. There is thus no need to provide the psa_crypto_alloc()
 * psa_crypto_free() functions as part of the integration.
 */
void *psa_crypto_calloc(size_t nmemb, size_t size);
void psa_crypto_free(void *ptr);
int psa_crypto_printf(const char *format, ...) PSA_CRYPTO_PRINTF_ATTRIBUTE(1, 2);
int psa_crypto_fprintf(FILE *stream, const char *format, ...) PSA_CRYPTO_PRINTF_ATTRIBUTE(2, 3);
int psa_crypto_snprintf(char *s, size_t n, const char *format, ...) PSA_CRYPTO_PRINTF_ATTRIBUTE(3, 4);
void psa_crypto_setbuf(FILE *stream, char *buf);

/**
 * \brief   Read an entropy seed from a Non-Volatile (NV) storage.
 *
 * \note This platform abstraction function is used by the psa-crypto library
 *       if and only if the PSA_CRYPTO_ENTROPY_NV_SEED configuration option
 *       is enabled. Furthermore, if both PSA_CRYPTO_STD_FUNCTIONS and
 *       PSA_CRYPTO_FS_IO configuration options are enabled then the psa-crypto
 *       library provides and uses its own implementation based on fopen() and
 *       a seed file (see PSA_CRYPTO_ENTROPY_NV_SEED_FILE configuration option)
 *       on the file system accessed through fopen(). Otherwise, if
 *       PSA_CRYPTO_STD_FUNCTIONS or PSA_CRYPTO_FS_IO is not enabled, the
 *       function has to be provided as part of the integration of psa-crypto
 *       library.
 *
 * \param[out]  buf  Buffer to write the entropy seed into.
 * \param       buf_size  Size of \p buf in bytes.
 *
 *
 * \return  \c 0 if \p buf_size bytes have been read and written into \p buf,
 *          a negative value otherwise.
 */
int psa_crypto_platform_entropy_nv_seed_read(unsigned char *buf, size_t buf_size);

/**
 * \brief Write an entropy seed to a Non-Volatile (NV) storage.
 *
 * \note This platform abstraction function is used by the psa-crypto library
 *       if and only if the PSA_CRYPTO_ENTROPY_NV_SEED configuration option
 *       is enabled. Furthermore, if both PSA_CRYPTO_STD_FUNCTIONS and
 *       PSA_CRYPTO_FS_IO configuration options are enabled then the psa-crypto
 *       library provides and uses its own implementation based on fopen() and
 *       a seed file (see PSA_CRYPTO_ENTROPY_NV_SEED_FILE configuration option)
 *       on the file system accessed through fopen(). Otherwise, if
 *       PSA_CRYPTO_STD_FUNCTIONS or PSA_CRYPTO_FS_IO is not enabled, the
 *       function has to be provided as part of the integration of psa-crypto
 *       library.
 *
 * \param[in]  buf  Buffer containing the data to write to the NV storage.
 * \param      buf_len  Length of the data to write in bytes.
 *
 * \return  \c 0 if \p buf_len bytes have been written to the NV storage, a
 *          negative value otherwise.
 */
int psa_crypto_platform_entropy_nv_seed_write(unsigned char *buf, size_t buf_len);

/**
 * \brief Securely zeroize a buffer
 *
 *        The function is meant to wipe the data contained in a buffer so that
 *        it can no longer be recovered even if the program memory is later
 *        compromised. It is called on sensitive data stored on the stack
 *        before returning from a function, and on sensitive data stored on the
 *        heap before freeing the heap object.
 *
 *        It is extremely difficult to guarantee that calls to
 *        mbedtls_platform_zeroize() are not removed by aggressive
 *        compiler optimizations in a portable way. By disabling the
 *        PSA_CRYPTO_STD_FUNCTIONS configuration option, users of the
 *        psa-crypto library can provide their own implementation suitable for
 *        their platform and needs.
 *
 * \param buf   Buffer to be zeroized
 * \param len   Length of the data in bytes
 *
 */
void psa_crypto_platform_zeroize(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PSA_PLATFORM_H */
