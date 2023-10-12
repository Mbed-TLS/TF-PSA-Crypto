/** \file tf_psa_crypto_platform.c
 *
 * \brief Helper functions to test PSA crypto functionality.
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

#include <psa/build_info.h>
#include <tf_psa_crypto/platform.h>

#if !defined(TF_PSA_CRYPTO_STD_FUNCTIONS)
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(TF_PSA_CRYPTO_MEMORY_BUFFER_ALLOC)
void *tf_psa_crypto_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void tf_psa_crypto_free(void *ptr)
{
    free(ptr);
}
#endif

int tf_psa_crypto_printf(const char *format, ...)
{
    int ret;
    va_list argp;

    va_start(argp, format);
    ret = vprintf(format, argp);
    va_end(argp);

    return ret;
}

int tf_psa_crypto_fprintf(FILE *stream, const char *format, ...)
{
    int ret;
    va_list argp;

    va_start(argp, format);
    ret = vfprintf(stream, format, argp);
    va_end(argp);

    return ret;
}

int tf_psa_crypto_snprintf(char *s, size_t n, const char *format, ...)
{
    int ret;
    va_list argp;

    va_start(argp, format);
    ret = vsnprintf(s, n, format, argp);
    va_end(argp);

    return ret;
}

void tf_psa_crypto_setbuf(FILE *stream, char *buf)
{
    setbuf(stream, buf);
}
#endif /* !TF_PSA_CRYPTO_STD_FUNCTIONS */

#if defined(TF_PSA_CRYPTO_PLATFORM_ZEROIZE)
void tf_psa_crypto_platform_zeroize(void *buf, size_t len)
{
    if (buf != NULL && len != 0)
        memset(buf, 0, len);
}
#endif

#if defined(TF_PSA_CRYPTO_HARDWARE_ENTROPY)
int tf_psa_crypto_hardware_entropy(void *data,
                                   unsigned char *output, size_t size,
                                   size_t *len)
{
    (void) data;

    memset(output, 0, size);
    *len = size;
    
    return 0;
}
#endif

#if defined(TF_PSA_CRYPTO_ENTROPY_NV_SEED)
#if defined(TF_PSA_CRYPTO_FS_IO)
#if !defined(TF_PSA_CRYPTO_STD_FUNCTIONS)
#include <mbedtls/entropy.h>

int tf_psa_crypto_platform_entropy_nv_seed_read(unsigned char *buf,
                                                size_t buf_len)
{
    FILE *file;
    size_t n;

    if ((file = fopen(TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE, "rb")) == NULL) {
        return -1;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    tf_psa_crypto_setbuf(file, NULL);

    if ((n = fread(buf, 1, buf_len, file)) != buf_len) {
        fclose(file);
        memset(buf, 0, buf_len);
        return -1;
    }

    fclose(file);
    return (int) n;
}

int tf_psa_crypto_platform_entropy_nv_seed_write(unsigned char *buf,
                                                 size_t buf_len)
{
    FILE *file;
    size_t n;

    if ((file = fopen(TF_PSA_CRYPTO_ENTROPY_NV_SEED_FILE, "w")) == NULL) {
        return -1;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    tf_psa_crypto_setbuf(file, NULL);

    if ((n = fwrite(buf, 1, buf_len, file)) != buf_len) {
        fclose(file);
        return -1;
    }

    fclose(file);
    return (int) n;
}
#endif /* !TF_PSA_CRYPTO_STD_FUNCTIONS */

#else /* TF_PSA_CRYPTO_FS_IO */

#include <mbedtls/entropy.h>
size_t tf_psa_crypto_test_platform_entropy_nv_seed_len = MBEDTLS_ENTROPY_BLOCK_SIZE;

int tf_psa_crypto_platform_entropy_nv_seed_read(unsigned char *buf,
                                                size_t buf_size)
{
    if (buf_size > tf_psa_crypto_test_platform_entropy_nv_seed_len)
        return -1;

    memset(buf, 0, buf_size);

    return (int) buf_size;
}

int tf_psa_crypto_platform_entropy_nv_seed_write(unsigned char *buf,
                                                 size_t buf_len)
{
    (void)buf;

    tf_psa_crypto_test_platform_entropy_nv_seed_len = buf_len;

    return (int) buf_len;
}
#endif /* TF_PSA_CRYPTO_FS_IO */
#endif /* TF_PSA_CRYPTO_ENTROPY_NV_SEED */
