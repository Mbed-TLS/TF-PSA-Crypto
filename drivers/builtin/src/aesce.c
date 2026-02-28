/*
 *  Armv8-A Cryptographic Extension support functions for Aarch64
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#if defined(__clang__) || defined(__GNUC__)
#define FORCE_INLINE inline __attribute__((always_inline))
#else
#define FORCE_INLINE inline
#endif


/* C-only: prevent inlining where the compiler supports it */
#if defined(_MSC_VER)
  #define NO_INLINE __declspec(noinline)
#elif defined(__clang__)
    #define NO_INLINE __attribute__((noinline))
#elif defined(__GNUC__)
    #if (__GNUC__ > 3) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
        #define NO_INLINE __attribute__((noinline))
    #else
        #define NO_INLINE
    #endif
#else
    #define NO_INLINE
#endif


#if defined(__clang__) &&  (__clang_major__ >= 4)

/* Ideally, we would simply use MBEDTLS_ARCH_IS_ARMV8_A in the following #if,
 * but that is defined by build_info.h, and we need this block to happen first. */
#if defined(__ARM_ARCH)
#if __ARM_ARCH >= 8
#define MBEDTLS_AESCE_ARCH_IS_ARMV8_A
#endif
#endif

#if defined(MBEDTLS_AESCE_ARCH_IS_ARMV8_A) && !defined(__ARM_FEATURE_CRYPTO)
/* The intrinsic declaration are guarded by predefined ACLE macros in clang:
 * these are normally only enabled by the -march option on the command line.
 * By defining the macros ourselves we gain access to those declarations without
 * requiring -march on the command line.
 *
 * `arm_neon.h` is included by tf_psa_crypto_common.h, so we put these defines
 * at the top of this file, before any includes. This is necessary with
 * Clang <=15.x. With Clang 16.0 and above, these macro definitions are
 * no longer required, but they're harmless. See
 * https://reviews.llvm.org/D131064
 */
#define __ARM_FEATURE_CRYPTO 1
/* See: https://arm-software.github.io/acle/main/acle.html#cryptographic-extensions
 *
 * `__ARM_FEATURE_CRYPTO` is deprecated, but we need to continue to specify it
 * for older compilers.
 */
#define __ARM_FEATURE_AES    1
#define MBEDTLS_ENABLE_ARM_CRYPTO_EXTENSIONS_COMPILER_FLAG
#endif

#endif /* defined(__clang__) &&  (__clang_major__ >= 4) */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_AESCE_C)

#include <string.h>

#include "aesce.h"
#include "constant_time_internal.h"

#if defined(MBEDTLS_AESCE_HAVE_CODE)

/* Compiler version checks. */
#if defined(__clang__)
#   if defined(MBEDTLS_ARCH_IS_ARM32) && (__clang_major__ < 11)
#       error "Minimum version of Clang for MBEDTLS_AESCE_C on 32-bit Arm or Thumb is 11.0."
#   elif defined(MBEDTLS_ARCH_IS_ARM64) && (__clang_major__ < 4)
#       error "Minimum version of Clang for MBEDTLS_AESCE_C on aarch64 is 4.0."
#   endif
#elif defined(__GNUC__)
#   if __GNUC__ < 6
#       error "Minimum version of GCC for MBEDTLS_AESCE_C is 6.0."
#   endif
#elif defined(_MSC_VER)
/* TODO: We haven't verified MSVC from 1920 to 1928. If someone verified that,
 *       please update this and document of `MBEDTLS_AESCE_C` in
 *       `mbedtls_config.h`. */
#   if _MSC_VER < 1929
#       error "Minimum version of MSVC for MBEDTLS_AESCE_C is 2019 version 16.11.2."
#   endif
#elif defined(__ARMCC_VERSION)
#    if defined(MBEDTLS_ARCH_IS_ARM32) && (__ARMCC_VERSION < 6200002)
/* TODO: We haven't verified armclang for 32-bit Arm/Thumb prior to 6.20.
 * If someone verified that, please update this and document of
 * `MBEDTLS_AESCE_C` in `mbedtls_config.h`. */
#         error "Minimum version of armclang for MBEDTLS_AESCE_C on 32-bit Arm is 6.20."
#    elif defined(MBEDTLS_ARCH_IS_ARM64) && (__ARMCC_VERSION < 6060000)
#         error "Minimum version of armclang for MBEDTLS_AESCE_C on aarch64 is 6.6."
#    endif
#endif

#if !(defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES)) || \
    defined(MBEDTLS_ENABLE_ARM_CRYPTO_EXTENSIONS_COMPILER_FLAG)
#   if defined(__ARMCOMPILER_VERSION)
#       if __ARMCOMPILER_VERSION <= 6090000
#           error "Must use minimum -march=armv8-a+crypto for MBEDTLS_AESCE_C"
#       else
#           pragma clang attribute push (__attribute__((target("aes"))), apply_to=function)
#           define MBEDTLS_POP_TARGET_PRAGMA
#       endif
#   elif defined(__clang__)
#       if __clang_major__ < 7
#           pragma clang attribute push (__attribute__((target("crypto"))), apply_to=function)
#       else
#           pragma clang attribute push (__attribute__((target("aes"))), apply_to=function)
#       endif
#       define MBEDTLS_POP_TARGET_PRAGMA
#   elif defined(__GNUC__)
#       pragma GCC push_options
#       pragma GCC target ("+crypto")
#       define MBEDTLS_POP_TARGET_PRAGMA
#   elif defined(_MSC_VER)
#       error "Required feature(__ARM_FEATURE_AES) is not enabled."
#   endif
#endif /* !(__ARM_FEATURE_CRYPTO || __ARM_FEATURE_AES) ||
          MBEDTLS_ENABLE_ARM_CRYPTO_EXTENSIONS_COMPILER_FLAG */

#if defined(__linux__) && !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)

#include <sys/auxv.h>
#if !defined(HWCAP_NEON)
#define HWCAP_NEON  (1 << 12)
#endif
#if !defined(HWCAP2_AES)
#define HWCAP2_AES  (1 << 0)
#endif
#if !defined(HWCAP_AES)
#define HWCAP_AES   (1 << 3)
#endif
#if !defined(HWCAP_ASIMD)
#define HWCAP_ASIMD (1 << 1)
#endif

signed char mbedtls_aesce_has_support_result = -1;

#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
/*
 * AES instruction support detection routine
 */
int mbedtls_aesce_has_support_impl(void)
{
    /* To avoid many calls to getauxval, cache the result. This is
     * thread-safe, because we store the result in a char so cannot
     * be vulnerable to non-atomic updates.
     * It is possible that we could end up setting result more than
     * once, but that is harmless.
     */
    if (mbedtls_aesce_has_support_result == -1) {
#if defined(MBEDTLS_ARCH_IS_ARM32)
        unsigned long auxval  = getauxval(AT_HWCAP);
        unsigned long auxval2 = getauxval(AT_HWCAP2);
        if (((auxval  & HWCAP_NEON) == HWCAP_NEON) &&
            ((auxval2 & HWCAP2_AES) == HWCAP2_AES)) {
            mbedtls_aesce_has_support_result = 1;
        } else {
            mbedtls_aesce_has_support_result = 0;
        }
#else
        unsigned long auxval = getauxval(AT_HWCAP);
        if ((auxval & (HWCAP_ASIMD | HWCAP_AES)) ==
            (HWCAP_ASIMD | HWCAP_AES)) {
            mbedtls_aesce_has_support_result = 1;
        } else {
            mbedtls_aesce_has_support_result = 0;
        }
#endif
    }
    return mbedtls_aesce_has_support_result;
}
#endif

#endif /* defined(__linux__) && !defined(MBEDTLS_AES_USE_HARDWARE_ONLY) */

#if defined MBEDTLS_AES_C

/* Single round of AESCE encryption */
#define AESCE_ENCRYPT_ROUND(k)          \
    block = vaeseq_u8(block, vkeys[k]);  \
    block = vaesmcq_u8(block);
/* Two rounds of AESCE encryption */
#define AESCE_ENCRYPT_ROUND_X2(k)       \
    AESCE_ENCRYPT_ROUND(k);             \
    AESCE_ENCRYPT_ROUND(k + 1)


FORCE_INLINE
static uint8x16_t aesce_encrypt_block_inline(uint8x16_t block,
                                      const uint8x16_t *vkeys,
                                      int nr)
{
    /* 10, 12 or 14 rounds. Unroll loop. */
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    (void) nr;
#else
    if (nr & 4) {
        if (nr & 2) {
            AESCE_ENCRYPT_ROUND_X2(0);
        }
        AESCE_ENCRYPT_ROUND_X2(2);
    }
#endif
    AESCE_ENCRYPT_ROUND_X2(4);
    AESCE_ENCRYPT_ROUND_X2(6);
    AESCE_ENCRYPT_ROUND_X2(8);
    AESCE_ENCRYPT_ROUND_X2(10);
    AESCE_ENCRYPT_ROUND(12);

    /* AES AddRoundKey for the previous round.
     * SubBytes, ShiftRows for the final round.  */
    block = vaeseq_u8(block, vkeys[13]);
    block = veorq_u8(block, vkeys[14]);
    return block;
}

NO_INLINE
static uint8x16_t aesce_encrypt_block(uint8x16_t block,
                                      const uint8x16_t *vkeys,
                                      const int nr)
{
    return aesce_encrypt_block_inline(block, vkeys, nr);
}

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
/* Single round of AESCE decryption
 *
 * AES AddRoundKey, SubBytes, ShiftRows
 *
 *      block = vaesdq_u8(block, vld1q_u8(keys));
 *
 * AES inverse MixColumns for the next round.
 *
 * This means that we switch the order of the inverse AddRoundKey and
 * inverse MixColumns operations. We have to do this as AddRoundKey is
 * done in an atomic instruction together with the inverses of SubBytes
 * and ShiftRows.
 *
 * It works because MixColumns is a linear operation over GF(2^8) and
 * AddRoundKey is an exclusive or, which is equivalent to addition over
 * GF(2^8). (The inverse of MixColumns needs to be applied to the
 * affected round keys separately which has been done when the
 * decryption round keys were calculated.)
 *
 *      block = vaesimcq_u8(block);
 */
/* Single round of AESCE decryption */
#define AESCE_DECRYPT_ROUND(k)          \
    block = vaesdq_u8(block, vkeys[k]);  \
    block = vaesimcq_u8(block);
/* Two rounds of AESCE decryption */
#define AESCE_DECRYPT_ROUND_X2(k)       \
    AESCE_DECRYPT_ROUND(k);             \
    AESCE_DECRYPT_ROUND(k + 1)

static uint8x16_t aesce_decrypt_block(uint8x16_t block,
                                      const uint8x16_t *vkeys,
                                      int rounds)
{
    /* 10, 12 or 14 rounds. Unroll loop. */
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    (void) rounds;
#else
    if (rounds & 4) {
        if (rounds & 2) {
            AESCE_DECRYPT_ROUND_X2(0);
        }
        AESCE_DECRYPT_ROUND_X2(2);
    }
#endif
    AESCE_DECRYPT_ROUND_X2(4);
    AESCE_DECRYPT_ROUND_X2(6);
    AESCE_DECRYPT_ROUND_X2(8);
    AESCE_DECRYPT_ROUND_X2(10);
    AESCE_DECRYPT_ROUND(12);

    /* The inverses of AES AddRoundKey, SubBytes, ShiftRows finishing up the
     * last full round. */
    block = vaesdq_u8(block, vkeys[13]);

    /* Inverse AddRoundKey for inverting the initial round key addition. */
    block = veorq_u8(block, vkeys[14]);
    return block;
}
#endif // MBEDTLS_BLOCK_CIPHER_NO_DECRYPT

static void mbedtls_aesce_load_keys(mbedtls_aes_context *ctx, uint8x16_t *vkeys)
{
    uint8_t *p = (uint8_t *) ctx->buf;
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    for (unsigned i = 0; i <= 10; i++) {
        vkeys[i + 4] = vld1q_u8(&p[i * 16]);
    }
#else
    for (unsigned i = 0; i <= 14; i++) {
        vkeys[i] = vld1q_u8(&p[i * 16]);
    }
#endif
}

#if defined(MBEDTLS_CIPHER_MODE_CTR) && defined(MBEDTLS_AES_C)
MBEDTLS_OPTIMIZE_FOR_PERFORMANCE
void mbedtls_aesce_encrypt_blocks_ctr(mbedtls_aes_context *ctx,
                                      size_t blocks,
                                      unsigned char counter[16],
                                      const unsigned char *input,
                                      unsigned char *output)
{
    // reverse to get bytes in LE order (note that top and bottom elements are inverted)
    uint64x2_t ctr_le = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(counter)));

    // constant used for incrementing counter
    const uint64x2_t k0_1 = vcombine_u64(vcreate_u64(0), vcreate_u64(1));

    // Determine the point to exit the inner loop where either
    // (a) we run out of blocks
    // (b) we need to propagate a carry in the counter
    //
    // In case no carry propagation is required, we pick a point and exit
    // anyway to ensure constant-time behaviour w.r.t. the counter value.
    // This means that for blocks > 1, we do two carry propagations of which
    // at least one is a no-op, and for blocks == 1, we do one.
    //
    // There are a lot of awkward edge cases in correctly selecting the point to
    // exit the inner loop. Careful testing is needed.

    // Number of blocks that can be processed before we hit a block which
    // requires us to propagate the carry
    uint64_t blocks_with_no_carry = UINT64_MAX - vgetq_lane_u64(ctr_le, 1);

    // Select a point to break the main-loop for possible carry propagation.
    //
    // We process max(1, limit) blocks, then carry-propagate, then process
    // remaining blocks, then carry-propagate.
    //
    // limit is checked after processing a block, so we always process one block
    // even if limit == 0; otherwise exactly limit blocks are processed before
    // doing carry propagation.
    //
    // If no carry propagation is needed (bwnc >= blocks):
    //      any point is ok
    //      limit = 0 -> process 1 block
    // If needed for the last block (bwnc == blocks - 1):
    //      any point is ok because we always propagate after the last block
    //      limit = 0 -> process 1 block
    // Otherwise (bwnc < blocks - 1):
    //      block after processing bwnc blocks requires carry
    //      limit = bwnc + 1
    //
    // The result is only used if blocks > 0 (so "blocks - 1u" is harmless).
    size_t limit = mbedtls_ct_size_if_else_0(
        mbedtls_ct_uint_lt(blocks_with_no_carry, blocks - 1u),
        blocks_with_no_carry + 1u
        );

    uint8x16_t vkeys[15];
    mbedtls_aesce_load_keys(ctx, vkeys);

    int nr = MBEDTLS_AES_GET_NR(ctx);

    size_t i = 0;
    while (i < blocks) {
        // process blocks up to point of needing carry propagation in counter
        // (at least one block)
        do {
            uint8x16_t ctr_be = vrev64q_u8(vreinterpretq_u8_u64(ctr_le));
            uint8x16_t in = vld1q_u8(&input[i * 16]);
            uint8x16_t block = aesce_encrypt_block_inline(ctr_be, vkeys, nr);
            uint8x16_t output_block = veorq_u8(block, in);
            ctr_le = vaddq_u64(ctr_le, k0_1);
            vst1q_u8(&output[i * 16], output_block);
        } while (++i < limit);

        // Propagate carry from incrementing counter - this is slow so
        // needs to be pulled out of the main loop above. This is a no-op
        // if the least-significant 64 bits of the counter did not wrap.
        //
        // equivalent to: ctr_le[0] += ctr_le[1] == 0 ? 1 : 0
#if defined(__aarch64__)
        // saturating left shift - top bit set iff ctr_le is non-zero
        uint64x1_t x = vqshl_n_u64(vget_high_u64(ctr_le), 63);
        // cast to signed 64-bit, compare to 0. result is 0 or all bits set
        uint64x1_t is_zero = vcge_s64(vreinterpret_s64_u64(x), vcreate_s64(0));
        // apply to ctr_le
        uint64x2_t inc = vcombine_u64(is_zero, vcreate_u64(0));
        ctr_le = vsubq_u64(ctr_le, inc);
#else
        // A32 lacks suitable intrinsics for 64-bit comparison, so just use scalar
        uint64_t ls64 = vgetq_lane_u64(ctr_le, 1);
        uint64x2_t inc = vcombine_u64(vcreate_u64(ls64 == 0 ? 1 : 0), vcreate_u64(0));
        ctr_le = vaddq_u64(ctr_le, inc);
#endif

        limit = blocks;
    }

    vst1q_u8(counter, vrev64q_u8(vreinterpretq_u8_u64(ctr_le)));
}

#endif // MBEDTLS_CIPHER_MODE_CTR && MBEDTLS_AES_C

/*
 * AES-ECB block en(de)cryption
 */
int mbedtls_aesce_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16])
{
    uint8x16_t block = vld1q_u8(&input[0]);

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    if (mode == MBEDTLS_AES_DECRYPT) {
        block = aesce_decrypt_block(block, ctx->vkeys, MBEDTLS_AES_GET_NR(ctx));
    } else
#else
    (void) mode;
#endif
    {
        block = aesce_encrypt_block(block, ctx->vkeys, MBEDTLS_AES_GET_NR(ctx));
    }
    vst1q_u8(&output[0], block);

    return 0;
}

/*
 * Compute decryption round keys from encryption round keys
 */
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
void mbedtls_aesce_inverse_key(mbedtls_aes_context *dst, mbedtls_aes_context const *src)
{
    unsigned nr = MBEDTLS_AES_GET_NR(src);
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    const uint8x16_t *sk = &src->vkeys[4];
    uint8x16_t       *dk = &dst->vkeys[4];
#else
    unsigned offset  = 14 - nr;
    const uint8x16_t *sk = &src->vkeys[offset];
    uint8x16_t       *dk = &dst->vkeys[offset];
#endif

    dk[0] = sk[nr];
    for (int i = 1, j = nr - 1; j > 0; i++, j--) {
        uint8x16_t k = sk[j];
        dk[i] = vaesimcq_u8(k);
    }
    dk[nr] = sk[0];
}
#endif

static inline uint32_t aes_rot_word(uint32_t word)
{
    return (word << (32 - 8)) | (word >> 8);
}

static inline uint32_t aes_sub_word(uint32_t in)
{
    uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(in));
    uint8x16_t zero = vdupq_n_u8(0);

    /* vaeseq_u8 does both SubBytes and ShiftRows. Taking the first row yields
     * the correct result as ShiftRows doesn't change the first row. */
    v = vaeseq_u8(zero, v);
    return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}

/*
 * Key expansion function
 */
int mbedtls_aesce_setkey_enc(mbedtls_aes_context *ctx,
                             unsigned char *rk,
                             const unsigned char *key,
                             const size_t key_bit_length)
{

    uint8_t *r = rk;
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    MBEDTLS_ASSUME(key_bit_length == 128);
#else
    // ensure consistent layout (ie if 128 or 192-bit keys, the leading
    // 32 or 64 bytes are skipped, so the remaining keys always sit in the same
    // part of ctx->buf)
    // this layout simplifies loading into NEON registers, which helps
    // size and perf
    r += (256 - key_bit_length) >> 1;
#endif

    static uint8_t const rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                    0x20, 0x40, 0x80, 0x1b, 0x36 };
    /* See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
     *   - Section 5, Nr = Nk + 6
     *   - Section 5.2, the length of round keys is Nb*(Nr+1)
     */
    const size_t key_len_in_words = key_bit_length / 32;    /* Nk */
    const size_t round_key_len_in_words = 4;                /* Nb */
    const size_t rounds_needed = key_len_in_words + 6;      /* Nr */
    const size_t round_keys_len_in_words =
        round_key_len_in_words * (rounds_needed + 1);       /* Nb*(Nr+1) */
    const uint32_t *rko_end = (uint32_t *) r + round_keys_len_in_words;

    uint8x16_t vk = vld1q_u8(key);
    vst1q_u8(r, vk);
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    vk = vld1q_u8(key + (key_bit_length - 128) / 8);
    vst1q_u8(r + (key_bit_length - 128) / 8, vk);
#endif

    for (uint32_t *rki = (uint32_t *) r, iteration = 0;
         rki + key_len_in_words < rko_end;
         rki += key_len_in_words, iteration++) {
        uint32_t *rko;
        rko = rki + key_len_in_words;
        rko[0] = aes_rot_word(aes_sub_word(rki[key_len_in_words - 1]));
        rko[0] ^= rcon[iteration] ^ rki[0];

#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        rko[1] = rko[0] ^ rki[1];
        rko[2] = rko[1] ^ rki[2];
        rko[3] = rko[2] ^ rki[3];
#else
        for (unsigned i = 0; i < 7; i++) {
            rko[i + 1] = rko[i] ^ rki[i + 1];
            if (key_bit_length == 256 && i == 3) {
                rko[4] = aes_sub_word(rko[3]) ^ rki[4];
            }
        }
#endif
    }

    mbedtls_aesce_load_keys(ctx, ctx->vkeys);

    return 0;
}

#endif

#if defined(MBEDTLS_GCM_C)

/*
 * The SHA-3 cryptographic extension is required for EOR3 support. Compiler
 * support is a bit patchy, so only use it for compilers where it is known to
 * work.
 *
 * The docs specify that __ARM_FEATURE_SHA3 implies target support AND
 * intrinsics available, but this isn't always reliable, so we only use EOR3
 * for known-good compilers.
 *
 * https://arm-software.github.io/acle/main/acle.html#sha3-extension
 */

#if defined(MBEDTLS_COMPILER_IS_GCC) && defined(MBEDTLS_ARCH_IS_ARM64) \
    && defined(MBEDTLS_ARCH_IS_ARMV9_A) && defined(__ARM_FEATURE_CRYPTO)
// On 64-bit Armv9-A, the crypto extension includes the SHA3 extension, but
// gcc does not define the SHA3 feature flag.
// See:
// https://developer.arm.com/documentation/109697/2025_12/Feature-descriptions/The-Armv9-0-architecture-extension
// "If FEAT_Armv9_Crypto is implemented, then ... FEAT_SHA3 are implemented."
#define __ARM_FEATURE_SHA3
#endif

#if defined(__ARM_FEATURE_SHA3)

#if defined(__clang__) && (__clang_major__ >= 7)

// for clang >= 7, just use the intrinsic
#define VEOR3Q_U8 veor3q_u8

#elif defined(MBEDTLS_COMPILER_IS_GCC) && (MBEDTLS_GCC_VERSION >= 110000)

// GCC >= 11: use assembly
static inline uint8x16_t mbedtls_aesce_veor3q_u8(
    const uint8x16_t a,
    const uint8x16_t b,
    const uint8x16_t c)
{
    uint8x16_t r;
    asm ("eor3 %0.16b, %1.16b, %2.16b, %3.16b"
         : "=w" (r)
         : "w" (a), "w" (b), "w" (c));
    return r;
}

#define VEOR3Q_U8 mbedtls_aesce_veor3q_u8

#endif // compiler

#endif // __ARM_FEATURE_SHA3

#if !defined(VEOR3Q_U8)
// Target does not suport eor3, or unknown compiler - use 2 veorq_u8 operations
// Using a macro here (rather than a static inline function) helps MSVC codegen.

#define VEOR3Q_U8(a, b, c) veorq_u8(veorq_u8((a), (b)), (c))

#endif // VEOR3Q_U8

#if defined(MBEDTLS_ARCH_IS_ARM32)

#if defined(__clang__)
/* On clang for A32/T32, work around some missing intrinsics and types which are listed in
 * [ACLE](https://arm-software.github.io/acle/neon_intrinsics/advsimd.html#polynomial-1)
 * These are only required for GCM.
 */
#define vreinterpretq_u64_p64(a) ((uint64x2_t) a)

typedef uint8x16_t poly128_t;

static inline poly128_t vmull_p64(poly64_t a, poly64_t b)
{
    poly128_t r;
    asm ("vmull.p64 %[r], %[a], %[b]" : [r] "=w" (r) : [a] "w" (a), [b] "w" (b) :);
    return r;
}

/* This is set to cause some more missing intrinsics to be defined below */
#define COMMON_MISSING_INTRINSICS

static inline poly128_t vmull_high_p64(poly64x2_t a, poly64x2_t b)
{
    return vmull_p64((poly64_t) (vget_high_u64((uint64x2_t) a)),
                     (poly64_t) (vget_high_u64((uint64x2_t) b)));
}

#endif /* defined(__clang__) */

static inline uint8x16_t vrbitq_u8(uint8x16_t x)
{
    /* There is no vrbitq_u8 instruction in A32/T32, so provide
     * an equivalent non-Neon implementation. Reverse bit order in each
     * byte with 4x rbit, rev. */
    asm ("ldm  %[p], { r2-r5 } \n\t"
         "rbit r2, r2          \n\t"
         "rev  r2, r2          \n\t"
         "rbit r3, r3          \n\t"
         "rev  r3, r3          \n\t"
         "rbit r4, r4          \n\t"
         "rev  r4, r4          \n\t"
         "rbit r5, r5          \n\t"
         "rev  r5, r5          \n\t"
         "stm  %[p], { r2-r5 } \n\t"
         :
         /* Output: 16 bytes of memory pointed to by &x */
         "+m" (*(uint8_t(*)[16]) &x)
         :
         [p] "r" (&x)
         :
         "r2", "r3", "r4", "r5"
         );
    return x;
}

#endif /* defined(MBEDTLS_ARCH_IS_ARM32) */

#if defined(MBEDTLS_COMPILER_IS_GCC) && __GNUC__ == 5
/* Some intrinsics are not available for GCC 5.X. */
#define COMMON_MISSING_INTRINSICS
#endif /* MBEDTLS_COMPILER_IS_GCC && __GNUC__ == 5 */


#if defined(COMMON_MISSING_INTRINSICS)

/* Missing intrinsics common to both GCC 5, and Clang on 32-bit */

#define vreinterpretq_p64_u8(a)  ((poly64x2_t) a)
#define vreinterpretq_u8_p128(a) ((uint8x16_t) a)

static inline poly64x1_t vget_low_p64(poly64x2_t a)
{
    uint64x1_t r = vget_low_u64(vreinterpretq_u64_p64(a));
    return (poly64x1_t) r;

}

#endif /* COMMON_MISSING_INTRINSICS */

/* vmull_p64/vmull_high_p64 wrappers.
 *
 * Older compilers miss some intrinsic functions for `poly*_t`. We use
 * uint8x16_t and uint8x16x3_t as input/output parameters.
 */
#if defined(MBEDTLS_COMPILER_IS_GCC)
/* GCC reports incompatible type error without cast. GCC think poly64_t and
 * poly64x1_t are different, that is different with MSVC and Clang. */
#define MBEDTLS_VMULL_P64(a, b) vmull_p64((poly64_t) a, (poly64_t) b)
#else
/* MSVC reports `error C2440: 'type cast'` with cast. Clang does not report
 * error with/without cast. And I think poly64_t and poly64x1_t are same, no
 * cast for clang also. */
#define MBEDTLS_VMULL_P64(a, b) vmull_p64(a, b)
#endif /* MBEDTLS_COMPILER_IS_GCC */

static FORCE_INLINE uint8x16_t pmull_low(uint8x16_t a, uint8x16_t b)
{

    return vreinterpretq_u8_p128(
        MBEDTLS_VMULL_P64(
            (poly64_t) vreinterpret_p64_u8(vget_low_u8(a)),
            (poly64_t) vreinterpret_p64_u8(vget_low_u8(b))
            ));
}

static FORCE_INLINE uint8x16_t pmull_high(uint8x16_t a, uint8x16_t b)
{
    return vreinterpretq_u8_p128(
        vmull_high_p64(vreinterpretq_p64_u8(a),
                       vreinterpretq_p64_u8(b)));
}

/* GHASH does 128b polynomial multiplication on block in GF(2^128) defined by
 * `x^128 + x^7 + x^2 + x + 1`.
 *
 * Arm64 only has 64b->128b polynomial multipliers, we need to do 4 64b
 * multiplies to generate a 128b.
 *
 * `poly_mult_128` executes polynomial multiplication and outputs 256b that
 * represented by 3 128b due to code size optimization.
 *
 * Output layout:
 * |            |             |             |
 * |------------|-------------|-------------|
 * | ret.val[0] | h3:h2:00:00 | high   128b |
 * | ret.val[1] |   :m2:m1:00 | middle 128b |
 * | ret.val[2] |   :  :l1:l0 | low    128b |
 */
static FORCE_INLINE uint8x16x3_t poly_mult_128(uint8x16_t a, uint8x16_t b)
{
    uint8x16x3_t ret;
    uint8x16_t h, m, l; /* retval high/middle/low */
    uint8x16_t c, d, e;

    h = pmull_high(a, b);                       /* h3:h2:00:00 = a1*b1 */
    l = pmull_low(a, b);                        /*   :  :l1:l0 = a0*b0 */
    c = vextq_u8(b, b, 8);                      /*      :c1:c0 = b0:b1 */
    d = pmull_high(a, c);                       /*   :d2:d1:00 = a1*b0 */
    e = pmull_low(a, c);                        /*   :e2:e1:00 = a0*b1 */
    m = veorq_u8(d, e);                         /*   :m2:m1:00 = d + e */

    ret.val[0] = h;
    ret.val[1] = m;
    ret.val[2] = l;
    return ret;
}

/*
 * Modulo reduction.
 *
 * See: https://www.researchgate.net/publication/285612706_Implementing_GCM_on_ARMv8
 *
 * Section 4.3
 *
 * Modular reduction is slightly more complex. Write the GCM modulus as f(z) =
 * z^128 +r(z), where r(z) = z^7+z^2+z+ 1. The well known approach is to
 * consider that z^128 ≡r(z) (mod z^128 +r(z)), allowing us to write the 256-bit
 * operand to be reduced as a(z) = h(z)z^128 +l(z)≡h(z)r(z) + l(z). That is, we
 * simply multiply the higher part of the operand by r(z) and add it to l(z). If
 * the result is still larger than 128 bits, we reduce again.
 */
static FORCE_INLINE uint8x16_t poly_mult_reduce(uint8x16x3_t input)
{
    uint8x16_t const ZERO = vdupq_n_u8(0);

    uint64x2_t r = vreinterpretq_u64_u8(vdupq_n_u8(0x87));
#if defined(__GNUC__)
    /* use 'asm' as an optimisation barrier to prevent loading MODULO from
     * memory. It is for GNUC compatible compilers.
     */
    asm volatile ("" : "+w" (r));
#endif
    uint8x16_t const MODULO = vreinterpretq_u8_u64(vshrq_n_u64(r, 64 - 8));
    uint8x16_t h, m, l; /* input high/middle/low 128b */
    uint8x16_t c, d, e, f, g, n, o;
    h = input.val[0];            /* h3:h2:00:00                          */
    m = input.val[1];            /*   :m2:m1:00                          */
    l = input.val[2];            /*   :  :l1:l0                          */
    c = pmull_high(h, MODULO);   /*   :c2:c1:00 = reduction of h3        */
    d = pmull_low(h, MODULO);    /*   :  :d1:d0 = reduction of h2        */
    e = veorq_u8(c, m);          /*   :e2:e1:00 = m2:m1:00 + c2:c1:00    */
    f = pmull_high(e, MODULO);   /*   :  :f1:f0 = reduction of e2        */
    g = vextq_u8(ZERO, e, 8);    /*   :  :g1:00 = e1:00                  */
    n = veorq_u8(d, l);          /*   :  :n1:n0 = d1:d0 + l1:l0          */
    o = veorq_u8(n, f);          /*       o1:o0 = f1:f0 + n1:n0          */
    return veorq_u8(o, g);       /*             = o1:o0 + g1:00          */
}

/*
 * GCM multiplication: c = a times b in GF(2^128)
 */
static FORCE_INLINE uint8x16_t mbedtls_aesce_gcm_mult_impl_inline(
                            const uint8x16_t a,
                            const uint8x16_t b)
{
    uint8x16_t va, vb, vc;
    va = vrbitq_u8(a);
    vb = b; // assume b has already had vrbitq_u8 applied
    vc = vrbitq_u8(poly_mult_reduce(poly_mult_128(va, vb)));
    return vc;
}

NO_INLINE void mbedtls_aesce_gcm_mult(unsigned char c[16],
                            const unsigned char a[16],
                            const unsigned char b[16])
{
    uint8x16_t va, vb, vc;
    va = vld1q_u8(&a[0]);
    vb = vrbitq_u8(vld1q_u8(&b[0]));
    vc = mbedtls_aesce_gcm_mult_impl_inline(va, vb);
    vst1q_u8(&c[0], vc);
}

void mbedtls_aesce_gcm_gen_table(mbedtls_gcm_context *ctx, uint8_t hash_key[16])
{
    /*
     * Set up H so that the first 8 bytes can be used by gcm_mult as the identity,
     * and the next 8 bytes are the hash key. This allows update_block_partial
     * to avoid a conditional when (maybe) multiplying by multiplying by
     * H[(offset + len) & 16] - ie multiply by hash key iff (offset + len) == 16.
     *
     * First 16 bytes - identity. Note that pmull operates over data which is
     * bit-reversed as if vrbitq_u8 were applied, i.e.
     * [1, 0, 0, ... ] is represented as [128, 0, 0, ...].
     */
    uint8x16_t vh = vdupq_n_u8(0);
    vst1q_u8(&ctx->aesce_H[0], vh);
    ctx->aesce_H[0] = 128;
    // next 16 bytes - hash key
    vh = vld1q_u8(hash_key);
    vst1q_u8(&ctx->aesce_H[16], vh);

#if defined(MBEDTLS_AES_C) && (MBEDTLS_AESCE_OPTIMISE_FOR_SIZE == 0)
    /*
     * Pre-compute 4 powers of the hash key, so that we can efficiently compute
     * the tag over 4 blocks at a time. This is very high-impact for performance.
     *
     * This is just a size-optimised version of:
     * vghash_4.val[0] = vh
     * vghash_4.val[1] = vh * vh
     * vghash_4.val[2] = vh * vh * vh
     * vghash_4.val[3] = vh * vh * vh * vh
     */
    ctx->vghash_4.val[0] = vrbitq_u8(vh);
    for (unsigned i = 0; i < 3;) {
        uint8x16_t a = ctx->vghash_4.val[i>>1];
        i++;
        uint8x16_t b = ctx->vghash_4.val[i>>1];
        ctx->vghash_4.val[i] = poly_mult_reduce(poly_mult_128(a, b));
    }
#endif
}

#if defined(MBEDTLS_AES_C)

MBEDTLS_OPTIMIZE_FOR_PERFORMANCE
void mbedtls_aesce_gcm_update_block_partial(
    mbedtls_aes_context *aes_ctx,
    mbedtls_gcm_context *ctx,
    const uint8_t *input,
    uint8_t *output,
    unsigned offset, unsigned len, uint8_t scratch[32]
) {
    MBEDTLS_ASSUME(len > 0);
    int nr = MBEDTLS_AES_GET_NR(aes_ctx);
    const uint8x16_t *vkeys = aes_ctx->vkeys;

    uint8x16_t vctr_ne  = MBEDTLS_IS_BIG_ENDIAN ? vld1q_u8(ctx->y) : vrev32q_u8(vld1q_u8(ctx->y));
    // only increment if offset == 0
    const uint32x4_t k1 = vsetq_lane_u32(!offset, vdupq_n_u32(0), 3);
    vctr_ne = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(vctr_ne), k1));
    uint8x16_t vctr_be = MBEDTLS_IS_BIG_ENDIAN ? vctr_ne : vrev32q_u8(vctr_ne);
    vst1q_u8(ctx->y, vctr_be);
    uint8x16_t vectr = aesce_encrypt_block(vctr_be, vkeys, nr);

#if MBEDTLS_AESCE_OPTIMISE_FOR_SIZE == 1
    // in size-optimised mode, add a less-slow path to avoid perf regression
    // adds around 70b but doubles performance compared to not having it.
    if (len == 16) {
        uint8x16_t vinput = vld1q_u8(input);
        uint8x16_t vbuf = vld1q_u8(ctx->buf);
        uint8x16_t voutput = veorq_u8(vectr, vinput);
        vbuf = veorq_u8(vbuf, (ctx->mode == MBEDTLS_GCM_ENCRYPT) ? voutput : vinput);
        vst1q_u8(output, voutput);
        vst1q_u8(ctx->buf, vbuf);
    } else
#endif
    {
        uint8_t *out16, *in16;
        in16  = &scratch[0];
        out16 = &scratch[16];
        memcpy(in16 + offset, input, len);

        uint8x16_t vinput = vld1q_u8(in16);
        uint8x16_t voutput = veorq_u8(vectr, vinput);

        vst1q_u8(out16, voutput);
        memcpy(output, out16 + offset, len);

#if MBEDTLS_GCM_DECRYPT != 0 || MBEDTLS_GCM_ENCRYPT != 1
#error This code assumes MBEDTLS_GCM_DECRYPT == 0 && MBEDTLS_GCM_ENCRYPT == 1
#endif
        const uint8_t *p = &scratch[ctx->mode * 16]; // ciphertext pointer
        mbedtls_xor_small(ctx->buf + offset, ctx->buf + offset, p + offset, len);
    }

    mbedtls_aesce_gcm_mult(ctx->buf, ctx->buf, &(ctx)->aesce_H[(offset + len) & 16]);
}

#if MBEDTLS_AESCE_OPTIMISE_FOR_SIZE == 0

#if defined(MBEDTLS_COMPILER_IS_GCC)
static inline uint8x16_t
veor3q_u8(uint8x16_t a,
          uint8x16_t b,
          uint8x16_t c)
{
    uint8x16_t r;
    __asm__("eor3 %0.16b, %1.16b, %2.16b, %3.16b"
            : "=w"(r)
            : "w"(a), "w"(b), "w"(c));
    return r;
}
#endif

MBEDTLS_MAYBE_UNUSED
static FORCE_INLINE uint8x16_t ghash_update_x4(uint8x16_t X,
                                               uint8x16_t *Y,
                                               const uint8x16x4_t vh
) {
    /*
     * Equivalent to:
     *
     * for (unsigned i = 0; i < 4; i++) {
     *     acc = veorq_u8_x3(acc, poly_mult_128(vrbitq_u8(Y[i]), vh.val[3 - i]))
     * }
     *
     * Unrolling and taking advantage of eor3 gains significant perf,
     * especially for GCC.
     */

    // Unreduced accumulation in 128x128 "wide" representation (x3)
    uint8x16x3_t acc = poly_mult_128(vrbitq_u8(X),  vh.val[3]);

    // Convert operands into PMULL-domain
    uint8x16x3_t a = poly_mult_128(vrbitq_u8(Y[0]), vh.val[3]);
    uint8x16x3_t b = poly_mult_128(vrbitq_u8(Y[1]), vh.val[2]);
    acc.val[0] = veor3q_u8(acc.val[0], a.val[0], b.val[0]);
    acc.val[1] = veor3q_u8(acc.val[1], a.val[1], b.val[1]);
    uint8x16x3_t c = poly_mult_128(vrbitq_u8(Y[2]), vh.val[1]);
    acc.val[2] = veor3q_u8(acc.val[2], a.val[2], b.val[2]);
    uint8x16x3_t d = poly_mult_128(vrbitq_u8(Y[3]), vh.val[0]);
    acc.val[0] = veor3q_u8(acc.val[0], c.val[0], d.val[0]);
    acc.val[1] = veor3q_u8(acc.val[1], c.val[1], d.val[1]);
    acc.val[2] = veor3q_u8(acc.val[2], c.val[2], d.val[2]);

    // Single reduction for the whole group, then convert back
    uint8x16_t Rr = poly_mult_reduce(acc);
    return vrbitq_u8(Rr);
}

#define MBEDTLS_AESCE_GCM_MULTIBLOCK 4

MBEDTLS_OPTIMIZE_FOR_PERFORMANCE
void mbedtls_aesce_gcm_update_blocks(
                        mbedtls_aes_context *aes_ctx,
                        mbedtls_gcm_context *ctx,
                        const unsigned char *input,
                        unsigned char *output,
                        size_t blocks)
{
    const uint8x16_t *vkeys = aes_ctx->vkeys;

    MBEDTLS_MAYBE_UNUSED
    const int nr = MBEDTLS_AES_GET_NR(aes_ctx);

    const uint32x4_t k1 = vsetq_lane_u32(1, vdupq_n_u32(0), 3);
    uint8x16_t vbuf     = vld1q_u8(ctx->buf);
    uint8x16_t vctr_ne  = MBEDTLS_IS_BIG_ENDIAN ? vld1q_u8(ctx->y) : vrev32q_u8(vld1q_u8(ctx->y));
    uint8x16_t ve[MBEDTLS_AESCE_GCM_MULTIBLOCK];

    uint8x16_t vio[MBEDTLS_AESCE_GCM_MULTIBLOCK * 2];
    uint8x16_t *vin = &vio[0];
    uint8x16_t *vout = &vio[MBEDTLS_AESCE_GCM_MULTIBLOCK];
#if MBEDTLS_GCM_DECRYPT != 0 || MBEDTLS_GCM_ENCRYPT != 1
#error This code assumes MBEDTLS_GCM_DECRYPT == 0 && MBEDTLS_GCM_ENCRYPT == 1
#endif
    uint8x16_t *cts = &vio[ctx->mode * MBEDTLS_AESCE_GCM_MULTIBLOCK];

    // compute keystream in ve
    for (size_t b = 0; b < (blocks - (blocks % MBEDTLS_AESCE_GCM_MULTIBLOCK)); b += MBEDTLS_AESCE_GCM_MULTIBLOCK) {
        // manually unrolling and ordering instructions makes a big difference
        // to performance (esp. GCC), and also a small size benefit.

        ve[0] = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(vctr_ne), k1));
        ve[1] = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(ve[0]), k1));
        ve[2] = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(ve[1]), k1));
        ve[3] = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(ve[2]), k1));
        vctr_ne = ve[3];

        if (!MBEDTLS_IS_BIG_ENDIAN) {
            ve[0] = vrev32q_u8(ve[0]);
            ve[1] = vrev32q_u8(ve[1]);
            ve[2] = vrev32q_u8(ve[2]);
            ve[3] = vrev32q_u8(ve[3]);
        }

        // Having round as the outer loop reduces register pressure, which
        // helps AES-256 by around 10%
        for (unsigned round = 14 - nr; round < 13; round++) {
            ve[0] = vaeseq_u8(ve[0], vkeys[round]);
            ve[1] = vaeseq_u8(ve[1], vkeys[round]);
            ve[2] = vaeseq_u8(ve[2], vkeys[round]);
            ve[3] = vaeseq_u8(ve[3], vkeys[round]);
            ve[0] = vaesmcq_u8(ve[0]);
            ve[1] = vaesmcq_u8(ve[1]);
            ve[2] = vaesmcq_u8(ve[2]);
            ve[3] = vaesmcq_u8(ve[3]);
        }

        ve[0] = vaeseq_u8(ve[0], vkeys[13]);
        ve[1] = vaeseq_u8(ve[1], vkeys[13]);
        ve[2] = vaeseq_u8(ve[2], vkeys[13]);
        ve[3] = vaeseq_u8(ve[3], vkeys[13]);

        ve[0] = veorq_u8(ve[0], vkeys[14]);
        ve[1] = veorq_u8(ve[1], vkeys[14]);
        ve[2] = veorq_u8(ve[2], vkeys[14]);
        ve[3] = veorq_u8(ve[3], vkeys[14]);

        vin[0]  = vld1q_u8(&input[0]);
        vin[1]  = vld1q_u8(&input[16]);
        vin[2]  = vld1q_u8(&input[32]);
        vin[3]  = vld1q_u8(&input[48]);

        vout[0] = veorq_u8(vin[0], ve[0]);
        vst1q_u8(&output[0], vout[0]);

        vout[1] = veorq_u8(vin[1], ve[1]);
        vst1q_u8(&output[16], vout[1]);

        vout[2] = veorq_u8(vin[2], ve[2]);
        vst1q_u8(&output[32], vout[2]);

        vout[3] = veorq_u8(vin[3], ve[3]);
        vst1q_u8(&output[48], vout[3]);

        vbuf = ghash_update_x4(vbuf, cts, ctx->vghash_4);

        input  += 16 * MBEDTLS_AESCE_GCM_MULTIBLOCK;
        output += 16 * MBEDTLS_AESCE_GCM_MULTIBLOCK;
    }

    uint8x16_t vctr_be = MBEDTLS_IS_BIG_ENDIAN ? vctr_ne : vrev32q_u8(vctr_ne);
    vst1q_u8(ctx->buf, vbuf);
    vst1q_u8(ctx->y, vctr_be);

    size_t n = blocks % MBEDTLS_AESCE_GCM_MULTIBLOCK;
    if (n > 0) {
        uint8_t scratch[32];
        while (n--) {
            mbedtls_aesce_gcm_update_block_partial(
                aes_ctx, ctx,
                input,
                output,
                0,
                16,
                scratch
            );
            input += 16;
            output += 16;
        }
        mbedtls_platform_zeroize(scratch, 32);
    }
}

#endif // MBEDTLS_AESCE_OPTIMISE_FOR_SIZE

#endif // MBEDTLS_AES_C

#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_POP_TARGET_PRAGMA)
#if defined(__clang__)
#pragma clang attribute pop
#elif defined(__GNUC__)
#pragma GCC pop_options
#endif
#undef MBEDTLS_POP_TARGET_PRAGMA
#endif

#endif /* MBEDTLS_AESCE_HAVE_CODE */

#endif /* MBEDTLS_AESCE_C */
