/** \brief Wrapper around sha3.h providing mldsa-native's fips202.h interface
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYTO_FIPS202_MBEDTLS_H
#define TF_PSA_CRYTO_FIPS202_MBEDTLS_H

#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include <tf-psa-crypto/build_info.h>

#include <mbedtls/private/sha3.h>

#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define SHA3_256_HASHBYTES 32
#define SHA3_512_HASHBYTES 64

typedef struct {
    mbedtls_sha3_context b;
} mld_shake128ctx;

static inline void mld_shake128_init(mld_shake128ctx *state)
{
    mbedtls_sha3_init(&state->b);
    (void) mbedtls_sha3_starts(&state->b, MBEDTLS_SHA3_SHAKE128);
}

static inline void mld_shake128_absorb(mld_shake128ctx *state,
                                const uint8_t *in, size_t inlen)
{
    (void) mbedtls_sha3_update(&state->b, in, inlen);
}

static inline void mld_shake128_finalize(mld_shake128ctx *state)
{
    (void) state;
}

static inline void mld_shake128_squeeze(uint8_t *out, size_t outlen,
                                        mld_shake128ctx *state)
{
    (void) mbedtls_sha3_finish(&state->b, out, outlen);
}

static inline void mld_shake128_release(mld_shake128ctx *state) {
    (void) mbedtls_sha3_free(&state->b);
}

typedef struct {
    mbedtls_sha3_context b;
} mld_shake256ctx;

static inline void mld_shake256_init(mld_shake256ctx *state)
{
    mbedtls_sha3_init(&state->b);
    (void) mbedtls_sha3_starts(&state->b, MBEDTLS_SHA3_SHAKE256);
}

static inline void mld_shake256_absorb(mld_shake256ctx *state,
                                const uint8_t *in, size_t inlen)
{
    (void) mbedtls_sha3_update(&state->b, in, inlen);
}

static inline void mld_shake256_finalize(mld_shake256ctx *state)
{
    (void) state;
}

static inline void mld_shake256_squeeze(uint8_t *out, size_t outlen,
                                        mld_shake256ctx *state)
{
    (void) mbedtls_sha3_finish(&state->b, out, outlen);
}

static inline void mld_shake256_release(mld_shake256ctx *state) {
    (void) mbedtls_sha3_free(&state->b);
}

static inline void mld_shake256(uint8_t *out, size_t outlen,
                                const uint8_t *in, size_t inlen) {
    mbedtls_sha3_context ctx;
    mbedtls_sha3_init(&ctx);
    (void) mbedtls_sha3_starts(&ctx, MBEDTLS_SHA3_SHAKE256);
    (void) mbedtls_sha3_update(&ctx, in, inlen);
    (void) mbedtls_sha3_finish(&ctx, out, outlen);
    mbedtls_sha3_free(&ctx);
}

#endif /* TF_PSA_CRYTO_FIPS202_MBEDTLS_H */
