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

#ifdef __cplusplus
}
#endif

#endif /* tf-psa-crypto/private/ascon_types.h */
