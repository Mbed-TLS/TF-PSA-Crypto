/**
 * \file ascon.c
 *
 * \brief Implementation of Ascon
 *        (Ascon-Hash256 and Ascon-AEAD128).
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_BUILTIN_SOME_ASCON)

#include "ascon_internal.h"

#include "alignment.h"

static void tf_psa_crypto_ascon_permute_const(
    tf_psa_crypto_ascon_p_state_t *state,
    uint8_t k)
{
    /* For memory safety, if k is out of range, truncate it. */
    k &= 0x0f;
    static const uint8_t table[16] = {
        0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3,
        0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
    };
    state->S[2] ^= table[k];
}

static void tf_psa_crypto_ascon_permute_subst(
    tf_psa_crypto_ascon_p_state_t *state)
{
    state->S[0] ^= state->S[4];
    state->S[4] ^= state->S[3];
    state->S[2] ^= state->S[1];
    tf_psa_crypto_ascon_p_state_t mask;
    mask.S[0] = ~state->S[1] & state->S[2];
    mask.S[1] = ~state->S[2] & state->S[3];
    mask.S[2] = ~state->S[3] & state->S[4];
    mask.S[3] = ~state->S[4] & state->S[0];
    mask.S[4] = ~state->S[0] & state->S[1];
    state->S[0] ^= mask.S[0];
    state->S[1] ^= mask.S[1];
    state->S[2] ^= mask.S[2];
    state->S[3] ^= mask.S[3];
    state->S[4] ^= mask.S[4];
    state->S[1] ^= state->S[0];
    state->S[3] ^= state->S[2];
    state->S[0] ^= state->S[4];
    state->S[2] = ~state->S[2];
}

static inline uint64_t circular_shift_right(uint64_t x, uint8_t n)
{
    return (x >> n) | (x << (64 - n));
}

static inline void rotate_mask(uint64_t *x, uint8_t n1, uint8_t n2)
{
    *x ^= circular_shift_right(*x, n1) ^ circular_shift_right(*x, n2);
}

static void tf_psa_crypto_ascon_permute_diffuse(
    tf_psa_crypto_ascon_p_state_t *state)
{
    rotate_mask(&state->S[0], 19, 28);
    rotate_mask(&state->S[1], 61, 39);
    rotate_mask(&state->S[2], 1, 6);
    rotate_mask(&state->S[3], 10, 17);
    rotate_mask(&state->S[4], 7, 41);
}

MBEDTLS_STATIC_TESTABLE void tf_psa_crypto_ascon_permute_round(
    tf_psa_crypto_ascon_p_state_t *state,
    uint8_t rounds,
    uint8_t i)
{
    tf_psa_crypto_ascon_permute_const(state, 16 - rounds + i);
    tf_psa_crypto_ascon_permute_subst(state);
    tf_psa_crypto_ascon_permute_diffuse(state);
}

MBEDTLS_STATIC_TESTABLE void tf_psa_crypto_ascon_permute(
    tf_psa_crypto_ascon_p_state_t *state,
    uint8_t rounds)
{
    for (uint8_t i = 0; i < rounds; i++) {
        tf_psa_crypto_ascon_permute_round(state, rounds, i);
    }
}

#if defined(MBEDTLS_PSA_BUILTIN_SOME_ASCON_8)

void tf_psa_crypto_ascon_8_setup(
    tf_psa_crypto_ascon_8_state_t *state,
    int xof128)
{
    memset(state, 0, sizeof(*state));
    state->p.S[0] = (xof128 ?
                     0x0000080000cc0003 :
                     0x0000080100cc0002);
    tf_psa_crypto_ascon_permute(&state->p, 12);
}

#if defined(MBEDTLS_ASCON_SMALLER)

static inline uint8_t* state_byte(
    tf_psa_crypto_ascon_p_state_t *state,
    size_t offset)
{
    if (MBEDTLS_IS_BIG_ENDIAN) {
        return ((uint8_t *) state) + (offset & 0x08) + 7 - (offset & 0x07);
    } else {
        return ((uint8_t *) state) + offset;
    }
}

void tf_psa_crypto_ascon_hash256_update(
    tf_psa_crypto_ascon_8_state_t *state,
    const uint8_t *input, size_t input_length)
{
#if 0
    /* Optimized loop for aligned data. This can measurably increase
     * performance. */
    if (state->offset == 0 && (uintptr_t) input % 8 == 0) {
        uint64_t *input_words = (uint64_t *) input;
        while (input_length > 8) {
            state->p.S[0] ^= *input_words;
            tf_psa_crypto_ascon_permute(&state->p, 12);
            ++input_words;
            input_length -= 8;
        }
    }
#endif

    for (size_t i = 0; i < input_length; i++) {
        *state_byte(&state->p, state->offset) ^= input[i];
        if (state->offset == 7) {
            state->offset = 0;
            tf_psa_crypto_ascon_permute(&state->p, 12);
        } else {
            ++state->offset;
        }
    }
}

void tf_psa_crypto_ascon_8_finish(
    tf_psa_crypto_ascon_8_state_t *state)
{
    *state_byte(&state->p, state->offset) ^= 0x01;
    state->offset = 0;
}

#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_HASH256)
void tf_psa_crypto_ascon_hash256_finish(
    tf_psa_crypto_ascon_8_state_t *state,
    uint8_t output[32])
{
    *state_byte(&state->p, state->offset) ^= 0x01;

    for (size_t i = 0; i <= 3; i++) {
        tf_psa_crypto_ascon_permute(&state->p, 12);
        MBEDTLS_PUT_UINT64_LE(state->p.S[0], output, i * 8);
    }
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ASCON_HASH256 */

#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128)
void tf_psa_crypto_ascon_xof128_output(
    tf_psa_crypto_ascon_8_state_t *state,
    uint8_t* output, size_t output_length)
{
    size_t i;
    for (i = 0; i < output_length; i++) {
        if (state->offset == 0) {
            tf_psa_crypto_ascon_permute(&state->p, 12);
        }
        output[i] = *state_byte(&state->p, state->offset);
        ++state->offset;
        if (state->offset == 8) {
            state->offset = 0;
        }
    }
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128 */

#else /* MBEDTLS_ASCON_SMALLER */

static void tf_psa_crypto_ascon_absorb_block(
    tf_psa_crypto_ascon_8_state_t *state,
    const uint8_t block[8])
{
    state->p.S[0] ^= MBEDTLS_GET_UINT64_LE(block, 0);
    tf_psa_crypto_ascon_permute(&state->p, 12);
}

void tf_psa_crypto_ascon_hash256_update(
    tf_psa_crypto_ascon_8_state_t *state,
    const uint8_t *input, size_t input_length)
{
    if (input_length == 0) {
        return;
    }

    size_t available = state->u.pub.M_length + input_length;
    if (available < 8) {
        memcpy(state->u.pub.M + state->u.pub.M_length, input, input_length);
        state->u.pub.M_length = available;
        return;
    }

    const uint8_t *tail = input;
    if (state->u.pub.M_length != 0) {
        size_t missing = 8 - state->u.pub.M_length;
        memcpy(state->u.block + state->u.pub.M_length, input, missing);
        tail += missing;
        available -= 8;
        tf_psa_crypto_ascon_absorb_block(state, state->u.block);
    }

    while (available >= 8) {
        tf_psa_crypto_ascon_absorb_block(state, tail);
        tail += 8;
        available -= 8;
    }

    memcpy(state->u.pub.M, tail, available);
    memset(state->u.pub.M + available, 0, 7 - available);
    state->u.pub.M_length = available;
}

void tf_psa_crypto_ascon_8_finish(
    tf_psa_crypto_ascon_8_state_t *state)
{
    uint8_t n = state->u.pub.M_length;
    state->u.pub.M_length = 0;
    state->u.block[n] = 0x01;
    state->p.S[0] ^= MBEDTLS_GET_UINT64_LE(state->u.block, 0);
    memset(state->u.block, 0, 8);
}

#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_HASH256)
void tf_psa_crypto_ascon_hash256_finish(
    tf_psa_crypto_ascon_8_state_t *state,
    uint8_t output[32])
{
    tf_psa_crypto_ascon_8_finish(state);

    for (size_t i = 0; i <= 3; i++) {
        tf_psa_crypto_ascon_permute(&state->p, 12);
        MBEDTLS_PUT_UINT64_LE(state->p.S[0], output, i * 8);
    }
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ASCON_HASH256 */

#if defined(MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128)
void tf_psa_crypto_ascon_xof128_output(
    tf_psa_crypto_ascon_8_state_t *state,
    uint8_t *output, size_t output_length)
{
    if (output_length == 0) {
        return;
    }

    if (output_length < state->u.output.length) {
        memcpy(output, state->u.output.T + 7 - state->u.output.length, output_length);
        state->u.output.length -= output_length;
        return;
    }

    size_t remaining = output_length;
    uint8_t *tail = output;
    memcpy(tail, state->u.output.T + 7 - state->u.output.length, state->u.output.length);
    tail += state->u.output.length;
    remaining -= state->u.output.length;

    while (remaining >= 8) {
        tf_psa_crypto_ascon_permute(&state->p, 12);
        MBEDTLS_PUT_UINT64_LE(state->p.S[0], tail, 0);
        tail += 8;
        remaining -= 8;
    }

    if (remaining == 0) {
        state->u.output.length = 0;
    } else {
        tf_psa_crypto_ascon_permute(&state->p, 12);
        MBEDTLS_PUT_UINT64_LE(state->p.S[0], state->u.block, 0);
        memcpy(tail, state->u.block, remaining);
        state->u.output.length = 8 - remaining;
    }
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ASCON_XOF128 */

#endif /* MBEDTLS_ASCON_SMALLER */

#endif /* MBEDTLS_PSA_BUILTIN_SOME_ASCON_8 */

#endif /* MBEDTLS_PSA_BUILTIN_SOME_ASCON */
