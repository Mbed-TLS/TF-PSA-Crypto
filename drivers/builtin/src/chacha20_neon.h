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
 * This implementation can be configured to process multiple blocks in
 * parallel, using Neon and/or scalar; increasing the number of blocks
 * gains a lot of performance, but adds code size for each additional
 * block.
 *
 * MBEDTLS_CHACHA20_NEON_MULTIBLOCK and MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK
 * may be set to control the number of blocks processed in parallel. The
 * range for these is unlimited, but going above 6 Neon blocks and 4 scalar
 * blocks will probably be slower.
 *
 * The default (i.e., if these are not set) selects the fastest variant
 * with smaller code size than the v1.0.0 single block scalar
 * implementation.
 */

/*
 * Size & performance notes
 *
 * From informal tests on Aarch64 (applies to both gcc and clang except as
 * noted), using clang 17.0 and gcc 15.2.
 *
 * (n,s) means n Neon blocks and s scalar blocks.
 *
 * If prioritising code-size:
 * (0,0) will select the smallest implementation (which is single-block
 * Neon, if available). If Neon is not available, this enables additional
 * code-size optimisations which save around 300b over (0,1), but cost ~50%
 * perf.
 *
 * Default settings:
 * This is about 500b larger than the minimum setting, and about 2-3x
 * faster.
 *
 * For maximum performance:
 * Typically (6,2) gives best perf. On clang, (5,3) gives same perf for a
 * bit less size. This is about 60% faster than the default setting, and
 * adds ~870b (clang) or 3032b (gcc).
 *
 * For gcc, mixed Neon and scalar is only useful at (5,1) and (5,2), which
 * sit between (6,0) and (6,2).
 *
 * For clang, after (4,0): (2,2), (3,3), (4,4), (5,3) give increasing size
 * & perf. (2,2) roughly matches (6,0) perf at smaller size.
 */


// If only one option defined, set the other to zero
#if defined(MBEDTLS_CHACHA20_NEON_MULTIBLOCK) && \
    !defined(MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK)
#define MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK 0
#endif
#if defined(MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK) && \
    !defined(MBEDTLS_CHACHA20_NEON_MULTIBLOCK)
#define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 0
#endif


// If both undefined, select a suitable default
#if !defined(MBEDTLS_CHACHA20_NEON_MULTIBLOCK) || \
    !defined(MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK)

    #if !defined(MBEDTLS_HAVE_NEON_INTRINSICS)
// No Neon support - scalar only
        #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK   0

        #if !defined(MBEDTLS_ARCH_IS_THUMB)
            #define MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK 4
        #else // MBEDTLS_ARCH_IS_THUMB
            #if defined(__clang__)
                #define MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK 4
            #else
                #define MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK 1
            #endif
        #endif // MBEDTLS_ARCH_IS_THUMB

    #else // MBEDTLS_HAVE_NEON_INTRINSICS
// Neon is available - select sensible balance between perf and size
        #define MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK 0

        #if defined(MBEDTLS_ARCH_IS_THUMB)
// thumb needs a smaller default to avoid size regression
            #if defined(__clang__)
                #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK   3
            #else
                #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK   2
            #endif
        #else
            #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK   4
        #endif

    #endif // MBEDTLS_HAVE_NEON_INTRINSICS

#endif // !NEON_MULTIBLOCK || !SCALAR_MULTIBLOCK


// if both set to zero, select the smallest implementation available
#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK == 0 && \
    MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK == 0
// enable further size optimisations
    #define MBEDTLS_CHACHA20_OPTIMISE_FOR_SIZE

    #if defined(MBEDTLS_HAVE_NEON_INTRINSICS)
// Neon available - smallest option is single-block Neon
        #undef  MBEDTLS_CHACHA20_NEON_MULTIBLOCK
        #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 1
    #else
// Neon not available - use single-block scalar
        #undef  MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK
        #define MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK 1
    #endif // MBEDTLS_HAVE_NEON_INTRINSICS

#endif // NEON_MULTIBLOCK == 0 && SCALAR_MULTIBLOCK == 0


// total number of blocks to process in parallel
#define BLOCKS (MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK + MBEDTLS_CHACHA20_NEON_MULTIBLOCK)

#if defined(__clang__) && (__clang_major__ >= 4)
    #define MBEDTLS_CHACHA20_FORCE_UNROLL      _Pragma("clang loop unroll(full)")
#elif defined(MBEDTLS_COMPILER_IS_GCC) && (MBEDTLS_GCC_VERSION >= 80200)
    #define MBEDTLS_CHACHA20_FORCE_UNROLL      _Pragma("GCC unroll 16")
#elif defined(_MSC_VER)
    #define MBEDTLS_CHACHA20_FORCE_UNROLL      __pragma(loop(unroll))
#elif defined(__IAR_SYSTEMS_ICC__)
    #define MBEDTLS_CHACHA20_FORCE_UNROLL      _Pragma("unroll")
#else
    #define MBEDTLS_CHACHA20_FORCE_UNROLL
#endif


typedef union {
#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK > 0
    struct {
        uint32x4_t a, b, c, d;
    };
#endif
#if MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK > 0
    uint32_t s32[16];
#endif
} mbedtls_chacha20_block_t;


#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK > 0

// Define rotate-left operations that rotate within each 32-bit element in a 128-bit vector.
static inline uint32x4_t mbedtls_chacha20_neon_vrotlq_16_u32(uint32x4_t v)
{
    return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)));
}

static inline uint32x4_t mbedtls_chacha20_neon_vrotlq_12_u32(uint32x4_t v)
{
    uint32x4_t x = vshlq_n_u32(v, 12);
    return vsriq_n_u32(x, v, 20);
}

static inline uint32x4_t mbedtls_chacha20_neon_vrotlq_8_u32(uint32x4_t v)
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

static inline uint32x4_t mbedtls_chacha20_neon_vrotlq_7_u32(uint32x4_t v)
{
    uint32x4_t x = vshlq_n_u32(v, 7);
    return vsriq_n_u32(x, v, 25);
}

// Increment the 32-bit element within v that corresponds to the ChaCha20 counter
static inline uint32x4_t mbedtls_chacha20_neon_inc_counter(uint32x4_t v)
{
    /* { 1, 0, 0, 0 } */
    uint32x4_t counter_increment = vcombine_u32(vcreate_u32(1), vdup_n_u32(0));
    return vaddq_u32(v, counter_increment);
}

static inline void mbedtls_chacha20_load_neon_state(mbedtls_chacha20_block_t *neon_state,
                                                    const uint32_t *state)
{
    neon_state->a = vld1q_u32(&state[0]);
    neon_state->b = vld1q_u32(&state[4]);
    neon_state->c = vld1q_u32(&state[8]);
    neon_state->d = vld1q_u32(&state[12]);
}

static inline void mbedtls_chacha20_neon_prepare_blocks(mbedtls_chacha20_block_t *r,
                                                        const mbedtls_chacha20_block_t *neon_state)
{
    uint32x4_t ctr = neon_state->d;
#if defined(MBEDTLS_COMPILER_IS_GCC) && (BLOCKS > 6)
    // significantly helps GCC perf at higher block count
    MBEDTLS_CHACHA20_FORCE_UNROLL
#endif
    for (unsigned i = 0; i < BLOCKS; i++) {
        r[i].a = neon_state->a;
        r[i].b = neon_state->b;
        r[i].c = neon_state->c;
        r[i].d = ctr;
#if BLOCKS > 1
        ctr = mbedtls_chacha20_neon_inc_counter(ctr);
#endif
#if MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK > 0
        // In principle this is needed to ensure that it is safe to read the
        // inactive member of the mbedtls_chacha20_block_t union, i.e., to guarantee
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

static inline void mbedtls_chacha20_neon_inner_block(mbedtls_chacha20_block_t *r)
{
    for (unsigned i = 0; i < 2; i++) {
        r->a = vaddq_u32(r->a, r->b);                    // r->a += b
        r->d = veorq_u32(r->d, r->a);                    // r->d ^= a
        r->d = mbedtls_chacha20_neon_vrotlq_16_u32(r->d);        // r->d <<<= 16

        r->c = vaddq_u32(r->c, r->d);                    // r->c += d
        r->b = veorq_u32(r->b, r->c);                    // r->b ^= c
        r->b = mbedtls_chacha20_neon_vrotlq_12_u32(r->b);        // r->b <<<= 12

        r->a = vaddq_u32(r->a, r->b);                    // r->a += b
        r->d = veorq_u32(r->d, r->a);                    // r->d ^= a
        r->d = mbedtls_chacha20_neon_vrotlq_8_u32(r->d);         // r->d <<<= 8

        r->c = vaddq_u32(r->c, r->d);                    // r->c += d
        r->b = veorq_u32(r->b, r->c);                    // r->b ^= c
        r->b = mbedtls_chacha20_neon_vrotlq_7_u32(r->b);         // r->b <<<= 7

        // re-order b, c and d for the diagonal rounds
        if (i == 0) {
            r->d = vextq_u32(r->d, r->d, 3);
            r->c = vextq_u32(r->c, r->c, 2);
            r->b = vextq_u32(r->b, r->b, 1);
        } else {
            // restore element order in b, c, d
            r->d = vextq_u32(r->d, r->d, 1);
            r->c = vextq_u32(r->c, r->c, 2);
            r->b = vextq_u32(r->b, r->b, 3);
        }
    }
}

static inline void mbedtls_chacha20_neon_finish_blocks(mbedtls_chacha20_block_t *blocks,
                                                       mbedtls_chacha20_block_t *neon_state,
                                                       const unsigned int block_count,
                                                       const uint8_t *input,
                                                       uint8_t *output)
{
    MBEDTLS_ASSUME(block_count > 0 && block_count <= BLOCKS);

#if defined(MBEDTLS_COMPILER_IS_GCC) && (BLOCKS > 6)
    // for GCC, this gets a little more perf at high block counts
    MBEDTLS_CHACHA20_FORCE_UNROLL
#endif
    for (unsigned i = 0; i < block_count; i++) {
        mbedtls_chacha20_block_t *p = &blocks[i];
#if MBEDTLS_CHACHA20_SCALAR_MULTIBLOCK > 0
        // In principle this is needed to ensure that it is safe to read the
        // inactive member of the mbedtls_chacha20_block_t union, i.e., to guarantee
        // the scalar and Neon elements of the union are defined & consistent.
        // (In practice clang and GCC will do the right thing without this).
        if (i >= MBEDTLS_CHACHA20_NEON_MULTIBLOCK) {
            p->a = vld1q_u32(&p->s32[0]);
            p->b = vld1q_u32(&p->s32[4]);
            p->c = vld1q_u32(&p->s32[8]);
            p->d = vld1q_u32(&p->s32[12]);
        }
#endif
        uint8x16_t ia = vld1q_u8(input +  0);
        uint8x16_t ib = vld1q_u8(input + 16);
        uint8x16_t ic = vld1q_u8(input + 32);
        uint8x16_t id = vld1q_u8(input + 48);

        uint8x16_t a = vreinterpretq_u8_u32(vaddq_u32(p->a, neon_state->a));
        uint8x16_t b = vreinterpretq_u8_u32(vaddq_u32(p->b, neon_state->b));
        uint8x16_t c = vreinterpretq_u8_u32(vaddq_u32(p->c, neon_state->c));
        uint8x16_t d = vreinterpretq_u8_u32(vaddq_u32(p->d, neon_state->d));

        a = veorq_u8(ia, a);
        vst1q_u8(output +  0, a);

        b = veorq_u8(ib, b);
        vst1q_u8(output + 16, b);

        c = veorq_u8(ic, c);
        vst1q_u8(output + 32, c);

        d = veorq_u8(id, d);
        vst1q_u8(output + 48, d);

        neon_state->d = mbedtls_chacha20_neon_inc_counter(neon_state->d);

        input  += MBEDTLS_CHACHA20_BLOCK_SIZE_BYTES;
        output += MBEDTLS_CHACHA20_BLOCK_SIZE_BYTES;
    }
}

static inline void mbedtls_chacha20_update_counter_from_neon(uint32_t *p,
                                                             const mbedtls_chacha20_block_t *neon_state)
{
    vst1q_u32(p, neon_state->d);
}

#endif

#endif /* TF_PSA_CRYPTO_CHACHA20_NEON_H */
