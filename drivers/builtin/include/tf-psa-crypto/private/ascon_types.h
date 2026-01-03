/**
 * \file ascon_types.h
 *
 * \brief This file contains context types for Ascon
 *        (Ascon-Hash256 and Ascon-AEAD128).
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_ASCON_TYPES_H
#define TF_PSA_CRYPTO_PRIVATE_ASCON_TYPES_H
#include "mbedtls/private_access.h"

#include "tf-psa-crypto/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The state manipulated by the Ascon permutation Ascon-p. */
typedef struct {
    uint64_t S[5];
} tf_psa_crypto_ascon_p_state_t;

/** The state of an Ascon hash or XOF operation.
 */
typedef struct {
    tf_psa_crypto_ascon_p_state_t p;
#if defined(MBEDTLS_ASCON_SMALLER)
    uint8_t offset;
#else /* MBEDTLS_ASCON_SMALLER */
    /* M contains a partial block, so it is never full between calls to
     * functions (update, finish, etc.). However, it is convenient to have
     * enough space for a full block available inside the functions. */
    union {
        struct {
            /** Accumulated partial block of input (M[0] to M[M_length-1]) */
            uint8_t M[7];
            /** number of bytes in M (0..7) */
            uint8_t M_length;
        } pub;
        struct {
            /** Number of bytes in T that are not yet output (0..7). */
            uint8_t length;
            /** Remaining partial block of output (T[7-length] to T[6]) */
            uint8_t T[7];
        } output;
        uint8_t block[8];
    } u;
#endif /* MBEDTLS_ASCON_SMALLER */
} tf_psa_crypto_ascon_8_state_t;

/** The state of an Ascon AEAD128 operation.
 */
typedef struct {
    tf_psa_crypto_ascon_p_state_t p;
#if defined(MBEDTLS_ASCON_SMALLER)
    uint8_t offset;
    uint8_t have_ad;
#else /* MBEDTLS_ASCON_SMALLER */
    /* M contains a partial block, so it is never full between calls to
     * functions (update, finish, etc.). However, it is convenient to have
     * enough space for a full block available inside the functions. */
    union {
        struct {
            /** Accumulated partial block of input (while absorbing)
             * or output (while squeezing). */
            uint8_t M[15];
            /** number of bytes in M (always <= 15),
             * or 16 if waiting for AD and no AD has been presented yet. */
            uint8_t M_length;
        } pub;
        uint8_t block[16];
    } u;
#endif /* MBEDTLS_ASCON_SMALLER */
} tf_psa_crypto_ascon_16_state_t;

#ifdef __cplusplus
}
#endif

#endif /* tf-psa-crypto/private/ascon_types.h */
