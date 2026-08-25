/**
 * \file sm3.c
 *
 * \brief Implementation of SM3.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_BUILTIN_ALG_SM3)

#include "sm3_internal.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#include "mbedtls/platform.h"
#endif

#define EXTMSG_W1_LEN 68
#define EXTMSG_W2_LEN 64
#define EXTMSG_W_LEN (EXTMSG_W1_LEN + EXTMSG_W2_LEN)
#define SM3_BLOCK_SIZE 64

#define ROTL32(value, amount)                                           \
    (((uint32_t) (value) << ((amount) & 0x1f)) |                        \
     ((uint32_t) (value) >> ((32 - (amount)) & 0x1f)))

#define T(i) (((i) <= 15) ? 0x79cc4519u : 0x7a879d8au)
#define GG(j, x, y, z)                                                  \
    (((j) <= 15) ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | (~(x) & (z))))
#define FF(j, x, y, z)                                                  \
    (((j) <= 15) ? ((x) ^ (y) ^ (z)) :                                  \
     (((x) & (y)) | ((x) & (z)) | ((y) & (z))))
#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

/* SM3 message expansion. */
MBEDTLS_MAYBE_UNUSED static void sm3_msgext(uint32_t *w,
                                            const uint8_t *block)
{
    for (size_t j = 0; j < 16; j++) {
        w[j] = MBEDTLS_GET_UINT32_BE(block, j * 4);
    }

    for (size_t j = 16; j < EXTMSG_W1_LEN; j++) {
        w[j] = P1(w[j - 16] ^ w[j - 9] ^ ROTL32(w[j - 3], 15)) ^
               ROTL32(w[j - 13], 7) ^ w[j - 6];
    }

    uint32_t *w_ext = w + EXTMSG_W1_LEN;

    for (size_t j = 0; j < EXTMSG_W2_LEN; j++) {
        w_ext[j] = w[j] ^ w[j + 4];
    }
}

/* SM3 compression function. */
MBEDTLS_MAYBE_UNUSED static void sm3_process(
    tf_psa_crypto_sm3_operation_t *operation,
    const uint8_t block[64])
{
    struct {
        uint32_t ss1, ss2, tt1, tt2;
        uint32_t W[EXTMSG_W_LEN];
        uint32_t A[8];
    } local;

    for (size_t i = 0; i < 8; i++) {
        local.A[i] = operation->state[i];
    }

    sm3_msgext(local.W, block);

    for (size_t j = 0; j < 64; j++) {
        local.ss1 = ROTL32(ROTL32(local.A[0], 12) + local.A[4] +
                           ROTL32(T(j), j), 7);
        local.ss2 = local.ss1 ^ ROTL32(local.A[0], 12);
        local.tt1 = FF(j, local.A[0], local.A[1], local.A[2]) +
                    local.A[3] + local.ss2 + local.W[j + EXTMSG_W1_LEN];
        local.tt2 = GG(j, local.A[4], local.A[5], local.A[6]) +
                    local.A[7] + local.ss1 + local.W[j];
        local.A[3] = local.A[2];
        local.A[2] = ROTL32(local.A[1], 9);
        local.A[1] = local.A[0];
        local.A[0] = local.tt1;
        local.A[7] = local.A[6];
        local.A[6] = ROTL32(local.A[5], 19);
        local.A[5] = local.A[4];
        local.A[4] = P0(local.tt2);
    }

    for (size_t i = 0; i < 8; i++) {
        operation->state[i] ^= local.A[i];
    }

    mbedtls_platform_zeroize(&local, sizeof(local));
}

void tf_psa_crypto_sm3_setup(tf_psa_crypto_sm3_operation_t *operation)
{
    operation->total = 0;

    operation->state[0] = 0x7380166fu;
    operation->state[1] = 0x4914b2b9u;
    operation->state[2] = 0x172442d7u;
    operation->state[3] = 0xda8a0600u;
    operation->state[4] = 0xa96f30bcu;
    operation->state[5] = 0x163138aau;
    operation->state[6] = 0xe38dee4du;
    operation->state[7] = 0xb0fb0e4eu;
}

psa_status_t tf_psa_crypto_sm3_update(
    tf_psa_crypto_sm3_operation_t *operation,
    const uint8_t *input,
    size_t input_length)
{
    size_t left;
    size_t fill;

    if (input_length == 0) {
        return PSA_SUCCESS;
    }

    if (input == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if SIZE_MAX > (UINT64_MAX >> 3)
    if (input_length > (UINT64_MAX >> 3)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    if (operation->total > (UINT64_MAX >> 3) - (uint64_t) input_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    left = (size_t) (operation->total & 0x3f);
    fill = 64 - left;

    operation->total += input_length;

    if (left != 0 && input_length >= fill) {
        memcpy(operation->buffer + left, input, fill);
        sm3_process(operation, operation->buffer);

        input += fill;
        input_length -= fill;
        left = 0;
    }

    while (input_length >= 64) {
        sm3_process(operation, input);

        input += 64;
        input_length -= 64;
    }

    if (input_length > 0) {
        memcpy(operation->buffer + left, input, input_length);
    }

    return PSA_SUCCESS;
}

void tf_psa_crypto_sm3_finish(
    tf_psa_crypto_sm3_operation_t *operation,
    uint8_t output[32])
{
    uint32_t high;
    uint32_t low;
    size_t used;

    used = (size_t) (operation->total & 0x3f);

    operation->buffer[used++] = 0x80;

    if (used > SM3_BLOCK_SIZE - 8) {
        memset(operation->buffer + used, 0, SM3_BLOCK_SIZE - used);
        sm3_process(operation, operation->buffer);
        used = 0;
    }

    memset(operation->buffer + used, 0, SM3_BLOCK_SIZE - 8 - used);

    high = (uint32_t) (operation->total >> 29);
    low = (uint32_t) (operation->total << 3);

    MBEDTLS_PUT_UINT32_BE(high, operation->buffer, 56);
    MBEDTLS_PUT_UINT32_BE(low, operation->buffer, 60);
    sm3_process(operation, operation->buffer);

    for (size_t i = 0; i < 8; i++) {
        MBEDTLS_PUT_UINT32_BE(operation->state[i], output, i * 4);
    }
}

#if defined(MBEDTLS_SELF_TEST)
/* GB/T 32905-2016 test vectors. */
static const unsigned char sm3_test_buf[2][64] = {
    { "abc" },
    { "abcdabcdabcdabcdabcdabcdabcdabcd"
      "abcdabcdabcdabcdabcdabcdabcdabcd" },
};

static const size_t sm3_test_buflen[2] = { 3, 64 };

static const unsigned char sm3_test_sum[2][32] = {
    { 0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
      0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
      0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
      0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0 },
    { 0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
      0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
      0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
      0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32 },
};

int tf_psa_crypto_sm3_self_test(int verbose)
{
    tf_psa_crypto_sm3_operation_t operation;
    unsigned char output[32];
    int ret = 0;

    for (size_t i = 0; i < 2; i++) {
        if (verbose != 0) {
            mbedtls_printf("  SM3 test #%u: ", (unsigned int) i + 1);
        }

        tf_psa_crypto_sm3_setup(&operation);
        if (tf_psa_crypto_sm3_update(&operation,
                                     sm3_test_buf[i],
                                     sm3_test_buflen[i]) != PSA_SUCCESS) {
            ret = 1;
            goto fail;
        }
        tf_psa_crypto_sm3_finish(&operation, output);

        if (memcmp(output, sm3_test_sum[i], sizeof(output)) != 0) {
            ret = 1;
            goto fail;
        }

        if (verbose != 0) {
            mbedtls_printf("passed\n");
        }
    }

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    goto exit;

fail:
    if (verbose != 0) {
        mbedtls_printf("failed\n");
    }

exit:
    mbedtls_platform_zeroize(&operation, sizeof(operation));
    mbedtls_platform_zeroize(output, sizeof(output));
    return ret;
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_PSA_BUILTIN_ALG_SM3 */
