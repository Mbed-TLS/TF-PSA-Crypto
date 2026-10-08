/*
 *  SM4 implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 *  The SM4 block cipher was designed by the Office of State Commercial
 *  Cryptography Administration (OSCCA) of China, published as
 *  GM/T 0002-2012 and ISO/IEC 18033-3:2010.
 *
 *  https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_SM4_C)

#include "mbedtls/private/sm4.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#include "mbedtls/platform.h"

#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)                            \
    {                                                      \
        (n) = ((uint32_t) (b)[(i)] << 24)                \
            | ((uint32_t) (b)[(i) + 1] << 16)            \
            | ((uint32_t) (b)[(i) + 2] <<  8)            \
            | ((uint32_t) (b)[(i) + 3]);                 \
    }
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)                            \
    {                                                      \
        (b)[(i)] = (unsigned char) ((n) >> 24);          \
        (b)[(i) + 1] = (unsigned char) ((n) >> 16);      \
        (b)[(i) + 2] = (unsigned char) ((n) >>  8);      \
        (b)[(i) + 3] = (unsigned char) ((n));            \
    }
#endif

static const unsigned char sm4_Sbox[256] =
{
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
    0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
    0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
    0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
    0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
    0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
    0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
    0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
    0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
    0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
    0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
    0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

static const uint32_t sm4_FK[4] =
{
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

static const uint32_t sm4_CK[32] =
{
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

static uint32_t sm4_tau(uint32_t x)
{
    return ((uint32_t) sm4_Sbox[(x >> 24) & 0xFF] << 24) |
           ((uint32_t) sm4_Sbox[(x >> 16) & 0xFF] << 16) |
           ((uint32_t) sm4_Sbox[(x >>  8) & 0xFF] <<  8) |
           ((uint32_t) sm4_Sbox[(x      ) & 0xFF]      );
}

static uint32_t sm4_rotl(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t sm4_L(uint32_t x)
{
    return x ^ sm4_rotl(x, 2) ^ sm4_rotl(x, 10) ^ sm4_rotl(x, 18) ^ sm4_rotl(x, 24);
}

static uint32_t sm4_T(uint32_t x)
{
    return sm4_L(sm4_tau(x));
}

static uint32_t sm4_L_prime(uint32_t x)
{
    return x ^ sm4_rotl(x, 13) ^ sm4_rotl(x, 23);
}

static uint32_t sm4_T_prime(uint32_t x)
{
    return sm4_L_prime(sm4_tau(x));
}

static void sm4_setkey(uint32_t rk[32], const unsigned char key[16])
{
    uint32_t K[36];
    uint32_t MK[4];
    int i;

    GET_UINT32_BE(MK[0], key,  0);
    GET_UINT32_BE(MK[1], key,  4);
    GET_UINT32_BE(MK[2], key,  8);
    GET_UINT32_BE(MK[3], key, 12);

    K[0] = MK[0] ^ sm4_FK[0];
    K[1] = MK[1] ^ sm4_FK[1];
    K[2] = MK[2] ^ sm4_FK[2];
    K[3] = MK[3] ^ sm4_FK[3];

    for (i = 0; i < 32; i++) {
        K[i + 4] = K[i] ^ sm4_T_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ sm4_CK[i]);
        rk[i] = K[i + 4];
    }
}

void mbedtls_sm4_init(mbedtls_sm4_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_sm4_context));
}

void mbedtls_sm4_free(mbedtls_sm4_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sm4_context));
}

int mbedtls_sm4_setkey_enc(mbedtls_sm4_context *ctx,
                             const unsigned char key[16])
{
    sm4_setkey(ctx->rk, key);
    return 0;
}

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
int mbedtls_sm4_setkey_dec(mbedtls_sm4_context *ctx,
                             const unsigned char key[16])
{
    uint32_t rk_enc[32];
    int i;

    sm4_setkey(rk_enc, key);

    for (i = 0; i < 32; i++) {
        ctx->rk[i] = rk_enc[31 - i];
    }

    mbedtls_platform_zeroize(rk_enc, sizeof(rk_enc));
    return 0;
}
#endif /* !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */

int mbedtls_sm4_crypt_ecb(mbedtls_sm4_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16])
{
    uint32_t X[36];
    int i;

    if (mode != MBEDTLS_SM4_ENCRYPT && mode != MBEDTLS_SM4_DECRYPT) {
        return MBEDTLS_ERR_SM4_BAD_INPUT_DATA;
    }
    (void) mode;

    GET_UINT32_BE(X[0], input,  0);
    GET_UINT32_BE(X[1], input,  4);
    GET_UINT32_BE(X[2], input,  8);
    GET_UINT32_BE(X[3], input, 12);

    for (i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ sm4_T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ ctx->rk[i]);
    }

    PUT_UINT32_BE(X[35], output,  0);
    PUT_UINT32_BE(X[34], output,  4);
    PUT_UINT32_BE(X[33], output,  8);
    PUT_UINT32_BE(X[32], output, 12);

    return 0;
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_sm4_crypt_cbc(mbedtls_sm4_context *ctx,
                            int mode,
                            size_t length,
                            unsigned char iv[16],
                            const unsigned char *input,
                            unsigned char *output)
{
    int i;
    unsigned char temp[16];

    if (length % 16) {
        return MBEDTLS_ERR_SM4_INVALID_INPUT_LENGTH;
    }

    if (mode == MBEDTLS_SM4_ENCRYPT) {
        while (length > 0) {
            for (i = 0; i < 16; i++) {
                output[i] = (unsigned char) (input[i] ^ iv[i]);
            }

            mbedtls_sm4_crypt_ecb(ctx, mode, output, output);
            memcpy(iv, output, 16);

            input  += 16;
            output += 16;
            length -= 16;
        }
    } else {
        while (length > 0) {
            memcpy(temp, input, 16);
            mbedtls_sm4_crypt_ecb(ctx, mode, input, output);

            for (i = 0; i < 16; i++) {
                output[i] = (unsigned char) (output[i] ^ iv[i]);
            }

            memcpy(iv, temp, 16);

            input  += 16;
            output += 16;
            length -= 16;
        }
    }

    return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
int mbedtls_sm4_crypt_cfb128(mbedtls_sm4_context *ctx,
                               int mode,
                               size_t length,
                               size_t *iv_off,
                               unsigned char iv[16],
                               const unsigned char *input,
                               unsigned char *output)
{
    int c;
    size_t n = *iv_off;

    if (mode == MBEDTLS_SM4_ENCRYPT) {
        while (length--) {
            if (n == 0) {
                mbedtls_sm4_crypt_ecb(ctx, MBEDTLS_SM4_ENCRYPT, iv, iv);
            }

            c = *input++;
            *output++ = (unsigned char) (c ^ iv[n]);
            iv[n] = (unsigned char) (c ^ iv[n]);
            n = (n + 1) & 0x0F;
        }
    } else {
        while (length--) {
            if (n == 0) {
                mbedtls_sm4_crypt_ecb(ctx, MBEDTLS_SM4_ENCRYPT, iv, iv);
            }

            c = *input++;
            iv[n] = (unsigned char) (c ^ iv[n]);
            *output++ = (unsigned char) (c ^ iv[n]);
            n = (n + 1) & 0x0F;
        }
    }

    *iv_off = n;
    return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
int mbedtls_sm4_crypt_ofb(mbedtls_sm4_context *ctx,
                            size_t length,
                            size_t *iv_off,
                            unsigned char iv[16],
                            const unsigned char *input,
                            unsigned char *output)
{
    int c;
    size_t n = *iv_off;

    while (length--) {
        if (n == 0) {
            mbedtls_sm4_crypt_ecb(ctx, MBEDTLS_SM4_ENCRYPT, iv, iv);
        }

        c = *input++;
        *output++ = (unsigned char) (c ^ iv[n]);
        n = (n + 1) & 0x0F;
    }

    *iv_off = n;
    return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
int mbedtls_sm4_crypt_ctr(mbedtls_sm4_context *ctx,
                            size_t length,
                            size_t *nc_off,
                            unsigned char nonce_counter[16],
                            unsigned char stream_block[16],
                            const unsigned char *input,
                            unsigned char *output)
{
    int c, i;
    size_t n = *nc_off;

    while (length--) {
        if (n == 0) {
            mbedtls_sm4_crypt_ecb(ctx, MBEDTLS_SM4_ENCRYPT, nonce_counter, stream_block);

            for (i = 15; i >= 0; i--) {
                if (++nonce_counter[i] != 0) {
                    break;
                }
            }
        }
        c = *input++;
        *output++ = (unsigned char) (c ^ stream_block[n]);
        n = (n + 1) & 0x0F;
    }

    *nc_off = n;
    return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

static const unsigned char sm4_test_key[16] =
{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const unsigned char sm4_test_pt[16] =
{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const unsigned char sm4_test_ct[16] =
{
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
};

static const unsigned char sm4_test_1m_ct[16] =
{
    0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
    0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
};

int mbedtls_sm4_self_test(int verbose)
{
    mbedtls_sm4_context ctx;
    unsigned char buf[16];
    int i, ret = 0;

    mbedtls_sm4_init(&ctx);

    if (verbose != 0) {
        mbedtls_printf("  SM4-ECB #1 (encryption): ");
    }

    ret = mbedtls_sm4_setkey_enc(&ctx, sm4_test_key);
    if (ret != 0) {
        goto exit;
    }

    ret = mbedtls_sm4_crypt_ecb(&ctx, MBEDTLS_SM4_ENCRYPT, sm4_test_pt, buf);
    if (ret != 0) {
        goto exit;
    }

    if (memcmp(buf, sm4_test_ct, 16) != 0) {
        ret = 1;
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }
        goto exit;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        mbedtls_printf("  SM4-ECB #2 (decryption): ");
    }

    ret = mbedtls_sm4_setkey_dec(&ctx, sm4_test_key);
    if (ret != 0) {
        goto exit;
    }

    ret = mbedtls_sm4_crypt_ecb(&ctx, MBEDTLS_SM4_DECRYPT, sm4_test_ct, buf);
    if (ret != 0) {
        goto exit;
    }

    if (memcmp(buf, sm4_test_pt, 16) != 0) {
        ret = 1;
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }
        goto exit;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        mbedtls_printf("  SM4-ECB #3 (1M encryptions): ");
    }

    ret = mbedtls_sm4_setkey_enc(&ctx, sm4_test_key);
    if (ret != 0) {
        goto exit;
    }

    memcpy(buf, sm4_test_pt, 16);

    for (i = 0; i < 1000000; i++) {
        ret = mbedtls_sm4_crypt_ecb(&ctx, MBEDTLS_SM4_ENCRYPT, buf, buf);
        if (ret != 0) {
            goto exit;
        }
    }

    if (memcmp(buf, sm4_test_1m_ct, 16) != 0) {
        ret = 1;
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }
        goto exit;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

exit:
    mbedtls_sm4_free(&ctx);

    if (verbose != 0) {
        if (ret != 0) {
            mbedtls_printf("  SM4 self-test: FAILED\n");
        } else {
            mbedtls_printf("  SM4 self-test: passed\n");
        }
    }

    return ret;
}

#endif /* MBEDTLS_SM4_C */
