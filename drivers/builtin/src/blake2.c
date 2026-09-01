/**
 * \file blake2.c
 *
 * \brief Implementation of Blake2.
 *
 * The code is heavily inspired from RFC 7693.
 * Only sequential modes are implemented, not parallel ones.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#include "tf-psa-crypto/private/blake2.h"
#include "mbedtls/platform_util.h"
#include "alignment.h"

#if defined(MBEDTLS_PSA_BUILTIN_ALG_BLAKE2S_HASH256) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512)

static const uint8_t blake2_sigma[][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13, 0 },
#if defined(MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512)
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
#endif /* MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512 */
};
#endif /* MBEDTLS_PSA_BUILTIN_ALG_BLAKE2S_HASH256 || MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512 */

#if defined(MBEDTLS_PSA_BUILTIN_ALG_BLAKE2S_HASH256)

static const uint32_t blake2s_iv[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

#ifndef ROTR32
#define ROTR32(x, y)  (((x) >> (y)) ^ ((x) << (32 - (y))))
#endif

#define B2S_G(a, b, c, d, x, y) {   \
        v[a] = v[a] + v[b] + x;         \
        v[d] = ROTR32(v[d] ^ v[a], 16); \
        v[c] = v[c] + v[d];             \
        v[b] = ROTR32(v[b] ^ v[c], 12); \
        v[a] = v[a] + v[b] + y;         \
        v[d] = ROTR32(v[d] ^ v[a], 8);  \
        v[c] = v[c] + v[d];             \
        v[b] = ROTR32(v[b] ^ v[c], 7);  \
}

int tf_psa_crypto_blake2s_init(tf_psa_crypto_blake2s_context *ctx, size_t outlen,
                               const void *key, size_t keylen)
{
    size_t i;

    if (outlen == 0 || outlen > 32 || keylen > 32) {
        return TF_PSA_CRYPTO_ERR_BAD_INPUT_DATA;
    }

    memset(ctx, 0, sizeof(*ctx));

    for (i = 0; i < 8; i++) {
        ctx->state[i] = blake2s_iv[i];
    }

    ctx->state[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
    ctx->outlen = outlen;

    if (keylen > 0) {
        tf_psa_crypto_blake2s_update(ctx, key, keylen);
        ctx->buf_idx = 64;
    }

    return 0;
}

void tf_psa_crypto_blake2s_free(tf_psa_crypto_blake2s_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(*ctx));
}

void tf_psa_crypto_blake2s_clone(tf_psa_crypto_blake2s_context *dst,
                                 const tf_psa_crypto_blake2s_context *src)
{
    *dst = *src;
}

static void tf_psa_crypto_blake2s_compress(tf_psa_crypto_blake2s_context *ctx, int last)
{
    int i;
    uint32_t v[16], m[16];

    for (i = 0; i < 8; i++) {
        v[i] = ctx->state[i];
        v[i + 8] = blake2s_iv[i];
    }

    v[12] ^= ctx->processed_bytes[0];
    v[13] ^= ctx->processed_bytes[1];
    if (last) {
        v[14] = ~v[14];
    }

    for (i = 0; i < 16; i++) {
        m[i] = MBEDTLS_GET_UINT32_LE(&ctx->buf[4 * i], 0);
    }

    for (i = 0; i < 10; i++) {
        B2S_G(0, 4,  8, 12, m[blake2_sigma[i][0]], m[blake2_sigma[i][1]]);
        B2S_G(1, 5,  9, 13, m[blake2_sigma[i][2]], m[blake2_sigma[i][3]]);
        B2S_G(2, 6, 10, 14, m[blake2_sigma[i][4]], m[blake2_sigma[i][5]]);
        B2S_G(3, 7, 11, 15, m[blake2_sigma[i][6]], m[blake2_sigma[i][7]]);
        B2S_G(0, 5, 10, 15, m[blake2_sigma[i][8]], m[blake2_sigma[i][9]]);
        B2S_G(1, 6, 11, 12, m[blake2_sigma[i][10]], m[blake2_sigma[i][11]]);
        B2S_G(2, 7,  8, 13, m[blake2_sigma[i][12]], m[blake2_sigma[i][13]]);
        B2S_G(3, 4,  9, 14, m[blake2_sigma[i][14]], m[blake2_sigma[i][15]]);
    }

    for (i = 0; i < 8; ++i) {
        ctx->state[i] ^= v[i] ^ v[i + 8];
    }
}

void tf_psa_crypto_blake2s_update(tf_psa_crypto_blake2s_context *ctx,
                                  const uint8_t *in, size_t inlen)
{
    size_t space_left, to_copy;

    while (inlen > 0) {
        if (ctx->buf_idx == 64) {
            ctx->processed_bytes[0] += (uint32_t) ctx->buf_idx;
            // check overflow
            if (ctx->processed_bytes[0] < ctx->buf_idx) {
                ctx->processed_bytes[1]++;
            }
            tf_psa_crypto_blake2s_compress(ctx, 0);
            ctx->buf_idx = 0;
        }

        space_left = sizeof(ctx->buf) - ctx->buf_idx;
        to_copy = inlen > space_left ? space_left : inlen;
        memcpy(&ctx->buf[ctx->buf_idx], in, to_copy);
        inlen -= to_copy;
        in += to_copy;
        ctx->buf_idx += to_copy;
    }
}

int tf_psa_crypto_blake2s_finish(tf_psa_crypto_blake2s_context *ctx,
                                 uint8_t *out, size_t outlen)
{
    size_t i, pad_size;

    if (outlen < ctx->outlen) {
        return TF_PSA_CRYPTO_ERR_BUFFER_TOO_SMALL;
    }

    ctx->processed_bytes[0] += (uint32_t) ctx->buf_idx;
    // check overflow
    if (ctx->processed_bytes[0] < ctx->buf_idx) {
        ctx->processed_bytes[1]++;
    }

    pad_size = sizeof(ctx->buf) - ctx->buf_idx;
    memset(ctx->buf + ctx->buf_idx, 0, pad_size);
    tf_psa_crypto_blake2s_compress(ctx, 1);

    // little endian convert and store
    for (i = 0; i < ctx->outlen; i++) {
        out[i] = (ctx->state[i >> 2] >> (8 * (i & 3))) & 0xFF;
    }

    return 0;
}

int tf_psa_crypto_blake2s(const uint8_t *in, size_t inlen,
                          const void *key, size_t keylen,
                          uint8_t *out, size_t outlen)
{
    tf_psa_crypto_blake2s_context ctx;
    int ret;

    ret = tf_psa_crypto_blake2s_init(&ctx, outlen, key, keylen);
    if (ret != 0) {
        return ret;
    }
    tf_psa_crypto_blake2s_update(&ctx, in, inlen);
    ret = tf_psa_crypto_blake2s_finish(&ctx, out, outlen);
    tf_psa_crypto_blake2s_free(&ctx);

    return ret;
}

#endif /* MBEDTLS_PSA_BUILTIN_ALG_BLAKE2S_HASH256 */

#if defined(MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512)

static const uint64_t blake2b_iv[8] = {
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

#ifndef ROTR64
#define ROTR64(x, y)  (((x) >> (y)) ^ ((x) << (64 - (y))))
#endif

#define B2B_G(a, b, c, d, x, y) {   \
        v[a] = v[a] + v[b] + x;         \
        v[d] = ROTR64(v[d] ^ v[a], 32); \
        v[c] = v[c] + v[d];             \
        v[b] = ROTR64(v[b] ^ v[c], 24); \
        v[a] = v[a] + v[b] + y;         \
        v[d] = ROTR64(v[d] ^ v[a], 16); \
        v[c] = v[c] + v[d];             \
        v[b] = ROTR64(v[b] ^ v[c], 63); }

int tf_psa_crypto_blake2b_init(tf_psa_crypto_blake2b_context *ctx, size_t outlen,
                               const void *key, size_t keylen)
{
    size_t i;

    if (outlen == 0 || outlen > 64 || keylen > 64) {
        return TF_PSA_CRYPTO_ERR_BAD_INPUT_DATA;
    }

    memset(ctx, 0, sizeof(*ctx));

    for (i = 0; i < 8; i++) {
        ctx->state[i] = blake2b_iv[i];
    }

    ctx->state[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
    ctx->outlen = outlen;

    if (keylen > 0) {
        tf_psa_crypto_blake2b_update(ctx, key, keylen);
        ctx->buf_idx = 128;
    }

    return 0;
}

void tf_psa_crypto_blake2b_free(tf_psa_crypto_blake2b_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(*ctx));
}

void tf_psa_crypto_blake2b_clone(tf_psa_crypto_blake2b_context *dst,
                                 const tf_psa_crypto_blake2b_context *src)
{
    *dst = *src;
}

static void tf_psa_crypto_blake2b_compress(tf_psa_crypto_blake2b_context *ctx, int last)
{
    int i;
    uint64_t v[16], m[16];

    for (i = 0; i < 8; i++) {
        v[i] = ctx->state[i];
        v[i + 8] = blake2b_iv[i];
    }

    v[12] ^= ctx->processed_bytes[0];
    v[13] ^= ctx->processed_bytes[1];
    if (last) {
        v[14] = ~v[14];
    }

    for (i = 0; i < 16; i++) {          // get little-endian words
        m[i] = MBEDTLS_GET_UINT64_LE(&ctx->buf[8 * i], 0);
    }

    for (i = 0; i < 12; i++) {          // twelve rounds
        B2B_G(0, 4,  8, 12, m[blake2_sigma[i][0]], m[blake2_sigma[i][1]]);
        B2B_G(1, 5,  9, 13, m[blake2_sigma[i][2]], m[blake2_sigma[i][3]]);
        B2B_G(2, 6, 10, 14, m[blake2_sigma[i][4]], m[blake2_sigma[i][5]]);
        B2B_G(3, 7, 11, 15, m[blake2_sigma[i][6]], m[blake2_sigma[i][7]]);
        B2B_G(0, 5, 10, 15, m[blake2_sigma[i][8]], m[blake2_sigma[i][9]]);
        B2B_G(1, 6, 11, 12, m[blake2_sigma[i][10]], m[blake2_sigma[i][11]]);
        B2B_G(2, 7,  8, 13, m[blake2_sigma[i][12]], m[blake2_sigma[i][13]]);
        B2B_G(3, 4,  9, 14, m[blake2_sigma[i][14]], m[blake2_sigma[i][15]]);
    }

    for (i = 0; i < 8; ++i) {
        ctx->state[i] ^= v[i] ^ v[i + 8];
    }
}

void tf_psa_crypto_blake2b_update(tf_psa_crypto_blake2b_context *ctx,
                                  const uint8_t *in, size_t inlen)
{
    size_t space_left, to_copy;

    while (inlen > 0) {
        if (ctx->buf_idx == 128) {
            ctx->processed_bytes[0] += (uint64_t) ctx->buf_idx;
            // check overflow
            if (ctx->processed_bytes[0] < ctx->buf_idx) {
                ctx->processed_bytes[1]++;
            }
            tf_psa_crypto_blake2b_compress(ctx, 0);
            ctx->buf_idx = 0;
        }

        space_left = sizeof(ctx->buf) - ctx->buf_idx;
        to_copy = inlen > space_left ? space_left : inlen;
        memcpy(&ctx->buf[ctx->buf_idx], in, to_copy);
        inlen -= to_copy;
        in += to_copy;
        ctx->buf_idx += to_copy;
    }
}

int tf_psa_crypto_blake2b_finish(tf_psa_crypto_blake2b_context *ctx,
                                 uint8_t *out, size_t outlen)
{
    size_t i, pad_size;

    if (outlen < ctx->outlen) {
        return TF_PSA_CRYPTO_ERR_BUFFER_TOO_SMALL;
    }

    ctx->processed_bytes[0] += ctx->buf_idx;
    if (ctx->processed_bytes[0] < ctx->buf_idx) {
        ctx->processed_bytes[1]++;
    }

    pad_size = sizeof(ctx->buf) - ctx->buf_idx;
    memset(ctx->buf + ctx->buf_idx, 0, pad_size);
    tf_psa_crypto_blake2b_compress(ctx, 1);

    // little endian convert and store
    for (i = 0; i < ctx->outlen; i++) {
        out[i] = (ctx->state[i >> 3] >> (8 * (i & 7))) & 0xFF;
    }

    return 0;
}

int tf_psa_crypto_blake2b(const uint8_t *in, size_t inlen,
                          const void *key, size_t keylen,
                          uint8_t *out, size_t outlen)
{
    tf_psa_crypto_blake2b_context ctx;
    int ret;

    ret = tf_psa_crypto_blake2b_init(&ctx, outlen, key, keylen);
    if (ret != 0) {
        return ret;
    }
    tf_psa_crypto_blake2b_update(&ctx, in, inlen);
    ret = tf_psa_crypto_blake2b_finish(&ctx, out, outlen);
    tf_psa_crypto_blake2b_free(&ctx);

    return ret;
}

#endif /* MBEDTLS_PSA_BUILTIN_ALG_BLAKE2B_HASH512 */
