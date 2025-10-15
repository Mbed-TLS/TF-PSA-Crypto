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

#endif /* MBEDTLS_PSA_BUILTIN_SOME_ASCON */
