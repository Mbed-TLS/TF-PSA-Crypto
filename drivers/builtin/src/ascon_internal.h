/**
 * \file ascon_internal.h
 *
 * \brief This file contains internal function definitions for Ascon
 *        (Ascon-Hash256 and Ascon-AEAD128).
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_ASCON_INTERNAL_H
#define TF_PSA_CRYPTO_ASCON_INTERNAL_H
#include "mbedtls/private_access.h"

#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa/crypto_sizes.h"
#include "psa/crypto_struct.h"

#include <stdint.h>

#if defined(MBEDTLS_TEST_HOOKS)
/** One round of the Ascon permutation Ascon-p.
 *
 * \param state     The state to act on.
 * \param rounds    The number of rounds (8 or 12).
 * \param i         The round number (0 to \p rounds - 1).
 *
 * \warning The behavior is undefined if \p rounds or \p i is not in the
 *          permitted range.
 */
void tf_psa_crypto_ascon_permute_round(tf_psa_crypto_ascon_p_state_t *state,
                                       uint8_t rounds,
                                       uint8_t i);

/** The Ascon permutation Ascon-p.
 *
 * \param state     The state to act on.
 * \param rounds    The number of rounds (8 or 12).
 *
 * \warning The behavior is undefined if \p rounds or \p i is not in the
 *          permitted range.
 */
void tf_psa_crypto_ascon_permute(tf_psa_crypto_ascon_p_state_t *state,
                                 uint8_t rounds);
#endif /* MBEDTLS_TEST_HOOKS */

#endif /* ascon_internal.h */
