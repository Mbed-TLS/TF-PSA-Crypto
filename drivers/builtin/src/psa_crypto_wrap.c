/*
 *  PSA key wrapping driver entry points
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include "psa_crypto_wrap.h"
#include "psa_crypto_cipher.h"
#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/private/error_common.h"

#include <string.h>

#if defined(PSA_WANT_ALG_KW) || defined(PSA_WANT_ALG_KWP)

#define KW_SEMIBLOCK_LENGTH    8
#define MIN_SEMIBLOCKS_COUNT   3

#if defined(PSA_WANT_ALG_KW)
/*! The 64-bit default integrity check value (ICV) for KW mode. */
static const unsigned char PSA_KW_ICV1[] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};
#endif /* PSA_WANT_ALG_KW */

#if defined(PSA_WANT_ALG_KWP)
/*! The 32-bit default integrity check value (ICV) for KWP mode. */
static const unsigned char PSA_KW_ICV2[] = { 0xA6, 0x59, 0x59, 0xA6 };
#endif /* PSA_WANT_ALG_KWP */

/*
 * Helper function for Xoring the uint64_t "t" with the encrypted A.
 * Defined in NIST SP 800-38F section 6.1
 */
static void psa_kw_calc_a_xor_t(unsigned char A[KW_SEMIBLOCK_LENGTH], uint64_t t)
{
    size_t i;
    for (i = 0; i < sizeof(t); i++) {
        A[i] ^= (t >> ((sizeof(t) - 1 - i) * 8)) & 0xff;
    }
}

/*
 * Encrypt or decrypt a single 16-byte block with the wrapping key using
 * AES-ECB.
 */
static psa_status_t psa_kw_cipher_ecb(const psa_key_attributes_t *attributes,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      int encrypt,
                                      const unsigned char input[KW_SEMIBLOCK_LENGTH * 2],
                                      unsigned char output[KW_SEMIBLOCK_LENGTH * 2])
{
    psa_status_t status;
    size_t olen = 0;
    unsigned char iv[1] = { 0 };

    if (encrypt) {
        status = mbedtls_psa_cipher_encrypt(
            attributes, key_buffer, key_buffer_size,
            PSA_ALG_ECB_NO_PADDING, iv, 0,
            input, KW_SEMIBLOCK_LENGTH * 2,
            output, KW_SEMIBLOCK_LENGTH * 2, &olen);
    } else {
        status = mbedtls_psa_cipher_decrypt(
            attributes, key_buffer, key_buffer_size,
            PSA_ALG_ECB_NO_PADDING,
            input, KW_SEMIBLOCK_LENGTH * 2,
            output, KW_SEMIBLOCK_LENGTH * 2, &olen);
    }

    if (status == PSA_SUCCESS && olen != KW_SEMIBLOCK_LENGTH * 2) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }

    return status;
}

psa_status_t mbedtls_psa_key_wrap(const psa_key_attributes_t *wrapping_key_attributes,
                                  const uint8_t *wrapping_key_buffer,
                                  size_t wrapping_key_buffer_size,
                                  const psa_key_attributes_t *key_attributes,
                                  const uint8_t *key_buffer,
                                  size_t key_buffer_size,
                                  psa_algorithm_t alg,
                                  uint8_t *output,
                                  size_t output_size,
                                  size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t semiblocks = 0, s, padlen = 0;
    uint64_t t;
    unsigned char outbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char inbuff[KW_SEMIBLOCK_LENGTH * 2];
    uint8_t *key_data = NULL;
    size_t key_data_size = 0;
    size_t key_length = 0;

    *output_length = 0;

    if (psa_get_key_type(wrapping_key_attributes) != PSA_KEY_TYPE_AES) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Determine the size of the exported representation of the key to wrap. */
    key_data_size = PSA_EXPORT_KEY_OUTPUT_SIZE(psa_get_key_type(key_attributes),
                                               psa_get_key_bits(key_attributes));
    if (key_data_size == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    key_data = mbedtls_calloc(1, key_data_size);
    if (key_data == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    /* Export the key to wrap using driver wrapper. */
    status = psa_driver_wrapper_export_key(key_attributes,
                                           key_buffer,
                                           key_buffer_size,
                                           key_data,
                                           key_data_size,
                                           &key_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

#if defined(PSA_WANT_ALG_KW)
    if (alg == PSA_ALG_KW) {
        if (output_size < key_length + KW_SEMIBLOCK_LENGTH) {
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        /*
         * According to SP 800-38F Table 1, the plaintext length for KW
         * must be between 2 to 2^54-1 semiblocks inclusive.
         */
        if (key_length < 16 ||
#if SIZE_MAX > 0x1FFFFFFFFFFFFF8
            key_length > 0x1FFFFFFFFFFFFF8 ||
#endif
            key_length % KW_SEMIBLOCK_LENGTH != 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }

        memcpy(output, PSA_KW_ICV1, KW_SEMIBLOCK_LENGTH);
        memmove(output + KW_SEMIBLOCK_LENGTH, key_data, key_length);
    } else
#endif /* PSA_WANT_ALG_KW */
#if defined(PSA_WANT_ALG_KWP)
    if (alg == PSA_ALG_KWP) {
        if (key_length % 8 != 0) {
            padlen = (8 - (key_length % 8));
        }

        if (output_size < key_length + KW_SEMIBLOCK_LENGTH + padlen) {
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        /*
         * According to SP 800-38F Table 1, the plaintext length for KWP
         * must be between 1 and 2^32-1 octets inclusive.
         */
        if (key_length < 1
#if SIZE_MAX > 0xFFFFFFFF
            || key_length > 0xFFFFFFFF
#endif
            ) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }

        memcpy(output, PSA_KW_ICV2, KW_SEMIBLOCK_LENGTH / 2);
        MBEDTLS_PUT_UINT32_BE((key_length & 0xffffffff), output,
                              KW_SEMIBLOCK_LENGTH / 2);

        memcpy(output + KW_SEMIBLOCK_LENGTH, key_data, key_length);
        memset(output + KW_SEMIBLOCK_LENGTH + key_length, 0, padlen);
    } else
#endif /* PSA_WANT_ALG_KWP */
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto cleanup;
    }

    semiblocks = ((key_length + padlen) / KW_SEMIBLOCK_LENGTH) + 1;
    s = 6 * (semiblocks - 1);

#if defined(PSA_WANT_ALG_KWP)
    if (alg == PSA_ALG_KWP && key_length <= KW_SEMIBLOCK_LENGTH) {
        memcpy(inbuff, output, KW_SEMIBLOCK_LENGTH * 2);
        status = psa_kw_cipher_ecb(wrapping_key_attributes,
                                   wrapping_key_buffer,
                                   wrapping_key_buffer_size,
                                   1, inbuff, output);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }
    } else
#endif /* PSA_WANT_ALG_KWP */
    {
        unsigned char *R2 = output + KW_SEMIBLOCK_LENGTH;
        unsigned char *A = output;

        /*
         * Do the wrapping function W, as defined in RFC 3394 section 2.2.1
         */
        if (semiblocks < MIN_SEMIBLOCKS_COUNT) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }

        /* Calculate intermediate values */
        for (t = 1; t <= s; t++) {
            memcpy(inbuff, A, KW_SEMIBLOCK_LENGTH);
            memcpy(inbuff + KW_SEMIBLOCK_LENGTH, R2, KW_SEMIBLOCK_LENGTH);

            status = psa_kw_cipher_ecb(wrapping_key_attributes,
                                       wrapping_key_buffer,
                                       wrapping_key_buffer_size,
                                       1, inbuff, outbuff);
            if (status != PSA_SUCCESS) {
                goto cleanup;
            }

            memcpy(A, outbuff, KW_SEMIBLOCK_LENGTH);
            psa_kw_calc_a_xor_t(A, t);

            memcpy(R2, outbuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH);
            R2 += KW_SEMIBLOCK_LENGTH;
            if (R2 >= output + (semiblocks * KW_SEMIBLOCK_LENGTH)) {
                R2 = output + KW_SEMIBLOCK_LENGTH;
            }
        }
    }

    *output_length = semiblocks * KW_SEMIBLOCK_LENGTH;
    status = PSA_SUCCESS;

cleanup:
    if (key_data != NULL) {
        mbedtls_platform_zeroize(key_data, key_data_size);
        mbedtls_free(key_data);
    }

    if (status != PSA_SUCCESS) {
        memset(output, 0, output_size);
    }
    mbedtls_platform_zeroize(inbuff, sizeof(inbuff));
    mbedtls_platform_zeroize(outbuff, sizeof(outbuff));

    return status;
}

static psa_status_t psa_key_unwrap_w(const psa_key_attributes_t *attributes,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     const unsigned char *input,
                                     size_t semiblocks,
                                     unsigned char A[KW_SEMIBLOCK_LENGTH],
                                     unsigned char *output,
                                     size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    const size_t s = 6 * (semiblocks - 1);
    uint64_t t;
    unsigned char outbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char inbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char *R = NULL;

    *output_length = 0;

    if (semiblocks < MIN_SEMIBLOCKS_COUNT) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memcpy(A, input, KW_SEMIBLOCK_LENGTH);
    memmove(output, input + KW_SEMIBLOCK_LENGTH,
            (semiblocks - 1) * KW_SEMIBLOCK_LENGTH);
    R = output + (semiblocks - 2) * KW_SEMIBLOCK_LENGTH;

    /* Calculate intermediate values */
    for (t = s; t >= 1; t--) {
        psa_kw_calc_a_xor_t(A, t);

        memcpy(inbuff, A, KW_SEMIBLOCK_LENGTH);
        memcpy(inbuff + KW_SEMIBLOCK_LENGTH, R, KW_SEMIBLOCK_LENGTH);

        status = psa_kw_cipher_ecb(attributes, key_buffer, key_buffer_size,
                                   0, inbuff, outbuff);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }

        memcpy(A, outbuff, KW_SEMIBLOCK_LENGTH);

        /* Set R as LSB64 of outbuff */
        memcpy(R, outbuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH);

        if (R == output) {
            R = output + (semiblocks - 2) * KW_SEMIBLOCK_LENGTH;
        } else {
            R -= KW_SEMIBLOCK_LENGTH;
        }
    }

    *output_length = (semiblocks - 1) * KW_SEMIBLOCK_LENGTH;
    status = PSA_SUCCESS;

cleanup:
    if (status != PSA_SUCCESS) {
        memset(output, 0, (semiblocks - 1) * KW_SEMIBLOCK_LENGTH);
    }
    mbedtls_platform_zeroize(inbuff, sizeof(inbuff));
    mbedtls_platform_zeroize(outbuff, sizeof(outbuff));

    return status;
}

psa_status_t mbedtls_psa_key_unwrap(const psa_key_attributes_t *attributes,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    const unsigned char *input,
                                    size_t input_length,
                                    unsigned char *output,
                                    size_t output_size,
                                    size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    unsigned char A[KW_SEMIBLOCK_LENGTH];
    int diff;
#if defined(PSA_WANT_ALG_KWP)
    size_t padlen = 0, Plen;
#endif

    *output_length = 0;

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_AES) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (output_size < input_length - KW_SEMIBLOCK_LENGTH) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

#if defined(PSA_WANT_ALG_KW)
    if (alg == PSA_ALG_KW) {
        /*
         * According to SP 800-38F Table 1, the ciphertext length for KW
         * must be between 3 to 2^54 semiblocks inclusive.
         */
        if (input_length < 24 ||
#if SIZE_MAX > 0x200000000000000
            input_length > 0x200000000000000 ||
#endif
            input_length % KW_SEMIBLOCK_LENGTH != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        status = psa_key_unwrap_w(attributes, key_buffer, key_buffer_size,
                                  input, input_length / KW_SEMIBLOCK_LENGTH,
                                  A, output, output_length);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }

        /* Check ICV in "constant-time" */
        diff = mbedtls_ct_memcmp(PSA_KW_ICV1, A, KW_SEMIBLOCK_LENGTH);
        if (diff != 0) {
            status = PSA_ERROR_INVALID_SIGNATURE;
            goto cleanup;
        }
    } else
#endif /* PSA_WANT_ALG_KW */
#if defined(PSA_WANT_ALG_KWP)
    if (alg == PSA_ALG_KWP) {
        /*
         * According to SP 800-38F Table 1, the ciphertext length for KWP
         * must be between 2 to 2^29 semiblocks inclusive.
         */
        if (input_length < KW_SEMIBLOCK_LENGTH * 2 ||
#if SIZE_MAX > 0x100000000
            input_length > 0x100000000 ||
#endif
            input_length % KW_SEMIBLOCK_LENGTH != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (input_length == KW_SEMIBLOCK_LENGTH * 2) {
            unsigned char outbuff[KW_SEMIBLOCK_LENGTH * 2];
            status = psa_kw_cipher_ecb(attributes, key_buffer, key_buffer_size,
                                       0, input, outbuff);
            if (status != PSA_SUCCESS) {
                mbedtls_platform_zeroize(outbuff, sizeof(outbuff));
                goto cleanup;
            }

            memcpy(A, outbuff, KW_SEMIBLOCK_LENGTH);
            memcpy(output, outbuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH);
            mbedtls_platform_zeroize(outbuff, sizeof(outbuff));
            *output_length = KW_SEMIBLOCK_LENGTH;
        } else {
            /* input_length >= KW_SEMIBLOCK_LENGTH * 3 */
            status = psa_key_unwrap_w(attributes, key_buffer, key_buffer_size,
                                      input,
                                      input_length / KW_SEMIBLOCK_LENGTH,
                                      A, output, output_length);
            if (status != PSA_SUCCESS) {
                goto cleanup;
            }
        }

        /* Check ICV in "constant-time" */
        diff = mbedtls_ct_memcmp(PSA_KW_ICV2, A, KW_SEMIBLOCK_LENGTH / 2);
        if (diff != 0) {
            status = PSA_ERROR_INVALID_SIGNATURE;
        }

        Plen = MBEDTLS_GET_UINT32_BE(A, KW_SEMIBLOCK_LENGTH / 2);

        /*
         * Plen is the length of the plaintext, when the input is valid.
         * If Plen is larger than the plaintext and padding, padlen will be
         * larger than 8, because of the type wrap around.
         */
        padlen = input_length - KW_SEMIBLOCK_LENGTH - Plen;
        status = mbedtls_ct_error_if(mbedtls_ct_uint_gt(padlen, 7),
                                     PSA_ERROR_INVALID_SIGNATURE, status);
        padlen &= 7;

        /* Check padding in "constant-time" */
        const uint8_t zero[KW_SEMIBLOCK_LENGTH] = { 0 };
        diff = mbedtls_ct_memcmp_partial(
            &output[*output_length - KW_SEMIBLOCK_LENGTH], zero,
            KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH - padlen, 0);
        if (diff != 0) {
            status = PSA_ERROR_INVALID_SIGNATURE;
        }

        if (status != PSA_SUCCESS) {
            goto cleanup;
        }

        memset(output + Plen, 0, padlen);
        *output_length = Plen;
    } else
#endif /* PSA_WANT_ALG_KWP */
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = PSA_SUCCESS;

cleanup:
    if (status != PSA_SUCCESS) {
        memset(output, 0, output_size);
        *output_length = 0;
    }
    mbedtls_platform_zeroize(A, sizeof(A));

    return status;
}

#else /* PSA_WANT_ALG_KW || PSA_WANT_ALG_KWP */

psa_status_t mbedtls_psa_key_wrap(const psa_key_attributes_t *wrapping_key_attributes,
                                  const uint8_t *wrapping_key_buffer,
                                  size_t wrapping_key_buffer_size,
                                  const psa_key_attributes_t *key_attributes,
                                  const uint8_t *key_buffer,
                                  size_t key_buffer_size,
                                  psa_algorithm_t alg,
                                  uint8_t *output,
                                  size_t output_size,
                                  size_t *output_length)
{
    (void) wrapping_key_attributes;
    (void) wrapping_key_buffer;
    (void) wrapping_key_buffer_size;
    (void) key_attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t mbedtls_psa_key_unwrap(const psa_key_attributes_t *attributes,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    const unsigned char *input,
                                    size_t input_length,
                                    unsigned char *output,
                                    size_t output_size,
                                    size_t *output_length)
{
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

#endif /* PSA_WANT_ALG_KW || PSA_WANT_ALG_KWP */

#endif /* MBEDTLS_PSA_CRYPTO_C */
