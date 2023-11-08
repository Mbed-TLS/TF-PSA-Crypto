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
 * \def TF_PSA_CRYPTO_PRINTF_ATTRIBUTE
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
#define TF_PSA_CRYPTO_PRINTF_ATTRIBUTE(string_index, first_to_check)    \
    __attribute__((format(printf, string_index, first_to_check)))
#else /* __has_attribute(format) */
#define TF_PSA_CRYPTO_PRINTF_ATTRIBUTE(string_index, first_to_check)
#endif /* __has_attribute(format) */
#else /* defined(__has_attribute) */
#define TF_PSA_CRYPTO_PRINTF_ATTRIBUTE(string_index, first_to_check)
#endif

/*
 * If the configuration option TF_PSA_CRYPTO_STD_FUNCTIONS is enabled (default),
 * the following platform abstraction functions are just aliases to the
 * corresponding standard C library functions. Otherwise, these functions have
 * to be provided as part of the integration of the PSA cryptography library.
 * They should behave as the corresponding standard C library functions as
 * defined in the C99 specification.
 *
 * If the configuration option TF_PSA_CRYPTO_STD_FUNCTIONS is disabled and
 * TF_PSA_CRYPTO_MEMORY_BUFFER_ALLOC is enabled the library buffer allocator
 * implementation is included in the build and the library uses it to allocate
 * and free memory. There is thus no need to provide the tf_psa_crypto_alloc()
 * tf_psa_crypto_free() functions as part of the integration.
 */
#if defined(TF_PSA_CRYPTO_STD_FUNCTIONS)
#define tf_psa_crypto_calloc calloc
#define tf_psa_crypto_free free
#define tf_psa_crypto_printf printf
#define tf_psa_crypto_fprintf fprintf
#define tf_psa_crypto_snprintf snprintf
#define tf_psa_crypto_setbuf setbuf
#else
void *tf_psa_crypto_calloc(size_t nmemb, size_t size);
void tf_psa_crypto_free(void *ptr);
int tf_psa_crypto_printf(const char *format, ...) TF_PSA_CRYPTO_PRINTF_ATTRIBUTE(1, 2);
int tf_psa_crypto_fprintf(FILE *stream, const char *format, ...) TF_PSA_CRYPTO_PRINTF_ATTRIBUTE(2, 3);
int tf_psa_crypto_snprintf(char *s, size_t n, const char *format, ...) TF_PSA_CRYPTO_PRINTF_ATTRIBUTE(3, 4);
void tf_psa_crypto_setbuf(FILE *stream, char *buf);
#endif

/**
 * \brief  Poll entropy from a hardware source
 *
 * \warning  This is not provided by TF-PSA-Crypto.
 *           See \c TF_PSA_CRYPTO_HARDWARE_ENTROPY in crypto_config.h.
 *
 * \param[in]  data    Pointer to function-specific data. NULL must be accepted.
 * \param[out] output  Buffer to write data in
 * \param      size    Size of \p output
 * \param[out] len     Number of bytes written in \p output. As far as possible,
 *                     should be \p size but may be as low as 0.
 * 
 * \return             0 if no critical failure occured, a negative value
 *                     otherwise.
 */
int tf_psa_crypto_hardware_entropy(void *data,
                                   unsigned char *output, size_t size,
                                   size_t *len);

/**
 * \brief   Read an entropy seed from a Non-Volatile (NV) storage.
 *
 * \note This platform abstraction function is used by the TF-PSA-Crypto library
 *       if and only if the TF_PSA_CRYPTO_ENTROPY_NV_SEED configuration option
 *       is enabled. Furthermore, if both TF_PSA_CRYPTO_STD_FUNCTIONS and
 *       TF_PSA_CRYPTO_FS_IO configuration options are enabled then the
 *       TF-PSA-Crypto library provides and uses its own implementation based
 *       on fopen() and a seed file (see TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE
 *       configuration option) on the file system accessed through fopen().
 *       Otherwise, if TF_PSA_CRYPTO_STD_FUNCTIONS or TF_PSA_CRYPTO_FS_IO is
 *       not enabled, the function has to be provided as part of the
 *       integration of TF-PSA-Crypto library.
 *
 * \param[out]  buf  Buffer to write the entropy seed into.
 * \param       buf_size  Size of \p buf in bytes.
 *
 *
 * \return  \c 0 if \p buf_size bytes have been read and written into \p buf,
 *          a negative value otherwise.
 */
int tf_psa_crypto_platform_entropy_nv_seed_read(unsigned char *buf,
                                                size_t buf_size);

/**
 * \brief Write an entropy seed to a Non-Volatile (NV) storage.
 *
 * \note This platform abstraction function is used by the TF-PSA-Crypto library
 *       if and only if the TF_PSA_CRYPTO_ENTROPY_NV_SEED configuration option
 *       is enabled. Furthermore, if both TF_PSA_CRYPTO_STD_FUNCTIONS and
 *       TF_PSA_CRYPTO_FS_IO configuration options are enabled then the
 *       TF-PSA-Crypto library provides and uses its own implementation based
 *       on fopen() and a seed file (see TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE
 *       configuration option) on the file system accessed through fopen().
 *       Otherwise, if TF_PSA_CRYPTO_STD_FUNCTIONS or TF_PSA_CRYPTO_FS_IO is
 *       not enabled, the function has to be provided as part of the
 *       integration of TF-PSA-Crypto library.
 *
 * \param[in]  buf  Buffer containing the data to write to the NV storage.
 * \param      buf_len  Length of the data to write in bytes.
 *
 * \return  \c 0 if \p buf_len bytes have been written to the NV storage, a
 *          negative value otherwise.
 */
int tf_psa_crypto_platform_entropy_nv_seed_write(unsigned char *buf,
                                                 size_t buf_len);

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
 *        tf_psa_crypto_platform_zeroize() are not removed by aggressive
 *        compiler optimizations in a portable way. By enabling the
 *        TF_PSA_CRYPTO_PLATFORM_ZEROIZE configuration option, users of the
 *        TF-PSA-Crypto library can provide their own implementation suitable
 *        for their platform and needs.
 *
 * \param buf   Buffer to be zeroized
 * \param len   Length of the data in bytes
 *
 */
void tf_psa_crypto_platform_zeroize(void *buf, size_t len);

/*
 * Platform exit macros
 */

#if defined(TF_PSA_CRYPTO_PLATFORM_EXIT)
#define tf_psa_crypto_exit TF_PSA_CRYPTO_PLATFORM_EXIT
#else
#define tf_psa_crypto_exit exit
#endif

#if defined(TF_PSA_CRYPTO_PLATFORM_EXIT_SUCCESS)
#define TF_PSA_CRYPTO_EXIT_SUCCESS TF_PSA_CRYPTO_PLATFORM_EXIT_SUCCESS
#else
#define TF_PSA_CRYPTO_EXIT_SUCCESS 0
#endif

#if defined(TF_PSA_CRYPTO_PLATFORM_EXIT_FAILURE)
#define TF_PSA_CRYPTO_EXIT_FAILURE TF_PSA_CRYPTO_PLATFORM_EXIT_FAILURE
#else
#define TF_PSA_CRYPTO_EXIT_FAILURE 1
#endif

#ifdef __cplusplus
}
#endif

#endif /* PSA_PLATFORM_H */
