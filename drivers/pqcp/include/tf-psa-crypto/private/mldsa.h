/**
 * \file tf-psa-crypto/private/mldsa.h
 *
 * \brief Macro definitions in the ML-DSA driver.
 *
 * This header is experimental.
 * Its content are likely to be moved to other headers
 * (mostly the public headers psa/crypto_values.h and psa/crypto_sizes.h)
 * once ML-DSA is visible through the API.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_MLDSA_H
#define TF_PSA_CRYPTO_PRIVATE_MLDSA_H

#include <psa/crypto_driver_common.h>

/* Define macros for key types and algorithms here in a private header,
 * rather than in a public header, because ML-DSA is not yet supported
 * through the API. In particular, the size macros in <psa/crypto_sizes.h>
 * do not yet take ML-DSA into account.
 */

/** The type of an ML-DSA key pair.
 *
 * It is represented as just the 32-byte seed.
 *
 * The `bits` attribute of the key indicates the parameter set:
 * 44, 56 or 87.
 */
#define PSA_KEY_TYPE_ML_DSA_KEY_PAIR ((psa_key_type_t) 0x7002)

/** The type of an ML-DSA public key.
 *
 * The `bits` attribute of the key indicates the parameter set:
 * 44, 56 or 87.
 */
#define PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY ((psa_key_type_t) 0x4002)

/** Whether the key type is an ML-DSA key (key pair or public key). */
#define PSA_KEY_TYPE_IS_ML_DSA(type)                                    \
    ((type) == PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY ||                        \
     (type) == PSA_KEY_TYPE_ML_DSA_KEY_PAIR)

/** Hedged pure ML-DSA (without pre-hashing). */
#define PSA_ALG_ML_DSA ((psa_algorithm_t) 0x06004400)

/** Deterministic pure ML-DSA (without pre-hashing). */
#define PSA_ALG_DETERMINISTIC_ML_DSA ((psa_algorithm_t) 0x06004500)

/** Whether the given algorithm is a pure ML-DSA algorithm
 * (without pre-hashing).
 */
#define PSA_ALG_IS_ML_DSA(alg)                \
    ((alg) == PSA_ALG_DETERMINISTIC_ML_DSA || \
     (alg) == PSA_ALG_ML_DSA)

#define PSA_MLDSA_SIGNATURE_SIZE(bits)          \
    ((bits) == 44 ? 2420u :                     \
     (bits) == 65 ? 3309u :                     \
     (bits) == 87 ? 4627u :                     \
     0u)
#define PSA_MLDSA_SIGNATURE_MAX_SIZE (PSA_MLDSA_SIGNATURE_SIZE(87))

#endif /* tf-psa-crypto/private/mldsa.h */
