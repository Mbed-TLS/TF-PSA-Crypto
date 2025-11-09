/**
 * \file chacha20_neon.h
 *
 * \brief Neon implementation of ChaCha20
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_CHACHA20_NEON_H
#define TF_PSA_CRYPTO_CHACHA20_NEON_H

#include "tf_psa_crypto_common.h"
#include "mbedtls/private/chacha20.h"

/*
 * The Neon implementation can be configured to process multiple blocks in parallel; increasing the
 * number of blocks gains a lot of performance, but adds on average around 250 bytes of code size
 * for each additional block.
 *
 * This is controlled by setting MBEDTLS_CHACHA20_NEON_MULTIBLOCK in the range [0..6] (0 selects
 * the scalar implementation; 1 selects single-block Neon; 2..6 select multi-block Neon).
 *
 * The default (i.e., if MBEDTLS_CHACHA20_NEON_MULTIBLOCK is not set) selects the fastest variant
 * which has better code size than the scalar implementation (based on testing for Aarch64 on clang
 * and gcc).
 *
 * Size & performance notes for Neon implementation from informal tests on Aarch64
 * (applies to both gcc and clang except as noted):
 *   - When single-block is selected, this saves around 400-550 bytes of code-size c.f. the scalar
 *     implementation
 *   - Multi-block Neon is smaller and faster than scalar (up to 2 blocks for gcc, 3 for clang)
 *   - Code size increases consistently with number of blocks
 *   - Performance increases with number of blocks (except at 5 which is slightly slower than 4)
 *   - Performance is within a few % for gcc vs clang at all settings
 *   - Performance at 4 blocks roughly matches our hardware accelerated AES-GCM impl with
 *     better code size
 *   - Performance is worse at 7 or more blocks, due to running out of Neon registers
 */

#if !defined(MBEDTLS_HAVE_NEON_INTRINSICS)
// Select scalar implementation if Neon not available
    #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 0
#elif !defined(MBEDTLS_CHACHA20_NEON_MULTIBLOCK)
// By default, select the best performing option that is not a code-size regression (based on
// measurements from recent gcc and clang).
#if defined(MBEDTLS_ARCH_IS_THUMB)
    #if defined(MBEDTLS_COMPILER_IS_GCC)
        #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 1
    #else
        #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 2
    #endif
#elif defined(MBEDTLS_ARCH_IS_ARM64)
    #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 3
#else
    #if defined(MBEDTLS_COMPILER_IS_GCC)
        #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 2
    #else
        #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 3
    #endif
#endif
#endif

#if !defined(MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK)
#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK == 0
#define MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK 1
#else
#define MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK 0
#endif
#endif

#define BLOCKS (MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK + MBEDTLS_CHACHA20_NEON_MULTIBLOCK)

typedef union {
#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK > 0
    struct {
        uint32x4_t a, b, c, d;
    };
#endif
    uint32_t s32[16];
} chacha20_block_t;


#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK > 0

// Tested on all combinations of Armv7 arm/thumb2; Armv8 arm/thumb2/aarch64; Armv8 aarch64_be on
// clang 14, gcc 11, and some more recent versions.

// Define rotate-left operations that rotate within each 32-bit element in a 128-bit vector.
static inline uint32x4_t chacha20_neon_vrotlq_16_u32(uint32x4_t v)
{
    return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)));
}

static inline uint32x4_t chacha20_neon_vrotlq_12_u32(uint32x4_t v)
{
    uint32x4_t x = vshlq_n_u32(v, 12);
    return vsriq_n_u32(x, v, 20);
}

static inline uint32x4_t chacha20_neon_vrotlq_8_u32(uint32x4_t v)
{
    uint32x4_t result;
#if defined(MBEDTLS_ARCH_IS_ARM64)
    // This implementation is slightly faster, but only supported on 64-bit Arm
    // Table look-up which results in an 8-bit rotate-left within each 32-bit element
    const uint8_t    idx_rotl8[16] = { 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14 };
    const uint8x16_t vrotl8_tbl = vld1q_u8(idx_rotl8);
    result = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), vrotl8_tbl));
#else
    uint32x4_t a = vshlq_n_u32(v, 8);
    result = vsriq_n_u32(a, v, 24);
#endif
    return result;
}

static inline uint32x4_t chacha20_neon_vrotlq_7_u32(uint32x4_t v)
{
    uint32x4_t x = vshlq_n_u32(v, 7);
    return vsriq_n_u32(x, v, 25);
}

// Increment the 32-bit element within v that corresponds to the ChaCha20 counter
static inline uint32x4_t chacha20_neon_inc_counter(uint32x4_t v)
{
    /* { 1, 0, 0, 0 } */
    uint32x4_t counter_increment = vcombine_u32(vcreate_u32(1), vdup_n_u32(0));
    return vaddq_u32(v, counter_increment);
}

static inline void chacha20_load_neon_state(chacha20_block_t *neon_state,
                                            const uint32_t *state)
{
    neon_state->a = vld1q_u32(&state[0]);
    neon_state->b = vld1q_u32(&state[4]);
    neon_state->c = vld1q_u32(&state[8]);
    neon_state->d = vld1q_u32(&state[12]);
}

static inline void chacha20_neon_prepare_blocks(chacha20_block_t *r,
                                                const chacha20_block_t *neon_state)
{
    uint32x4_t ctr = neon_state->d;
    for (unsigned i = 0; i < BLOCKS; i++) {
        r[i].a = neon_state->a;
        r[i].b = neon_state->b;
        r[i].c = neon_state->c;
        r[i].d = ctr;
        ctr = chacha20_neon_inc_counter(ctr);
#if MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK > 0
        // In principle this is needed to ensure that it is safe to read the
        // inactive member of the chacha20_block_t union, i.e., to guarantee
        // the scalar and Neon elements of the union are defined & consistent.
        // (In practice clang and GCC will do the right thing without this).
        if (i >= MBEDTLS_CHACHA20_NEON_MULTIBLOCK) {
            vst1q_u32(&r[i].s32[0],  r[i].a);
            vst1q_u32(&r[i].s32[4],  r[i].b);
            vst1q_u32(&r[i].s32[8],  r[i].c);
            vst1q_u32(&r[i].s32[12], r[i].d);
        }
#endif
    }
}

static inline void chacha20_neon_inner_block(chacha20_block_t *r)
{
    for (unsigned i = 0; i < 2; i++) {
        r->a = vaddq_u32(r->a, r->b);                    // r->a += b
        r->d = veorq_u32(r->d, r->a);                    // r->d ^= a
        r->d = chacha20_neon_vrotlq_16_u32(r->d);        // r->d <<<= 16

        r->c = vaddq_u32(r->c, r->d);                    // r->c += d
        r->b = veorq_u32(r->b, r->c);                    // r->b ^= c
        r->b = chacha20_neon_vrotlq_12_u32(r->b);        // r->b <<<= 12

        r->a = vaddq_u32(r->a, r->b);                    // r->a += b
        r->d = veorq_u32(r->d, r->a);                    // r->d ^= a
        r->d = chacha20_neon_vrotlq_8_u32(r->d);         // r->d <<<= 8

        r->c = vaddq_u32(r->c, r->d);                    // r->c += d
        r->b = veorq_u32(r->b, r->c);                    // r->b ^= c
        r->b = chacha20_neon_vrotlq_7_u32(r->b);         // r->b <<<= 7

        // re-order b, c and d for the diagonal rounds
        if (i == 0) {
            r->b = vextq_u32(r->b, r->b, 1);
            r->c = vextq_u32(r->c, r->c, 2);
            r->d = vextq_u32(r->d, r->d, 3);
        } else {
            // restore element order in b, c, d
            r->b = vextq_u32(r->b, r->b, 3);
            r->c = vextq_u32(r->c, r->c, 2);
            r->d = vextq_u32(r->d, r->d, 1);
        }
    }
}

static inline void chacha20_neon_finish_blocks(chacha20_block_t *blocks,
                                               chacha20_block_t *neon_state,
                                               const unsigned int block_count,
                                               const uint8_t *input,
                                               uint8_t *output)
{
    for (unsigned i = 0; i < block_count; i++) {
#if MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK > 0
        // In principle this is needed to ensure that it is safe to read the
        // inactive member of the chacha20_block_t union, i.e., to guarantee
        // the scalar and Neon elements of the union are defined & consistent.
        // (In practice clang and GCC will do the right thing without this).
        if (i >= MBEDTLS_CHACHA20_NEON_MULTIBLOCK) {
            blocks[i].a = vld1q_u32(&blocks[i].s32[0]);
            blocks[i].b = vld1q_u32(&blocks[i].s32[4]);
            blocks[i].c = vld1q_u32(&blocks[i].s32[8]);
            blocks[i].d = vld1q_u32(&blocks[i].s32[12]);
        }
#endif
        blocks[i].a = vaddq_u32(blocks[i].a, neon_state->a);
        blocks[i].b = vaddq_u32(blocks[i].b, neon_state->b);
        blocks[i].c = vaddq_u32(blocks[i].c, neon_state->c);
        blocks[i].d = vaddq_u32(blocks[i].d, neon_state->d);

        neon_state->d = chacha20_neon_inc_counter(neon_state->d);

        vst1q_u8(output +  0, veorq_u8(vld1q_u8(input +  0), vreinterpretq_u8_u32(blocks[i].a)));
        vst1q_u8(output + 16, veorq_u8(vld1q_u8(input + 16), vreinterpretq_u8_u32(blocks[i].b)));
        vst1q_u8(output + 32, veorq_u8(vld1q_u8(input + 32), vreinterpretq_u8_u32(blocks[i].c)));
        vst1q_u8(output + 48, veorq_u8(vld1q_u8(input + 48), vreinterpretq_u8_u32(blocks[i].d)));

        input  += MBEDTLS_CHACHA20_BLOCK_SIZE_BYTES;
        output += MBEDTLS_CHACHA20_BLOCK_SIZE_BYTES;
    }
}

static inline void chacha20_update_counter_from_neon(uint32_t *p,
                                                     const chacha20_block_t *neon_state)
{
    vst1q_u32(p, neon_state->d);
}

#endif

#endif /* TF_PSA_CRYPTO_CHACHA20_NEON_H */
