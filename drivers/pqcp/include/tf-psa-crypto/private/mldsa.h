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
 * By default, it is represented as just the 32-byte seed.
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

/** The size of an ML-DSA key pair in the PSA representation,
 * which is just the seed.
 */
#define TF_PSA_CRYPTO_PQCP_MLDSA_SEED_SIZE 32u

/** The size of an ML-DSA key pair in the joined representation:
 * the concatenation of the 32-byte seed with the standard ML-DSA
 * expanded key format.
 *
 * \param bits  The ML-DSA parameter set (44, 56 or 87).
 * \return      The size of the join key representation in bytes.
 *              Unpecified if \p bits is not supported.
 */
#define TF_PSA_CRYPTO_PQCP_MLDSA_JOINED_PRIVATE_KEY_SIZE(bits)      \
    (32u +                                                          \
     ((bits) == 44 ? 2560u :                                        \
      (bits) == 65 ? 4032u :                                        \
      (bits) == 87 ? 4896u :                                        \
      0u))

/** The maximum size of an ML-DSA key pair in the joined representation. */
#define TF_PSA_CRYPTO_PQCP_MLDSA_JOINED_PRIVATE_KEY_MAX_SIZE    \
    TF_PSA_CRYPTO_PQCP_MLDSA_JOINED_PRIVATE_KEY_SIZE(87)

/** The size of an ML-DSA public key.
 *
 * \param bits  The ML-DSA parameter set (44, 56 or 87).
 * \return      The size of the public key in bytes.
 *              Unpecified if \p bits is not supported.
 */
#define TF_PSA_CRYPTO_PQCP_MLDSA_PUBLIC_KEY_SIZE(bits)              \
    ((bits) == 44 ? 1312u :                                         \
     (bits) == 65 ? 1952u :                                         \
     (bits) == 87 ? 2592u :                                         \
     0u)

/** The maximum size of an ML-DSA public key. */
#define TF_PSA_CRYPTO_PQCP_MLDSA_PUBLIC_KEY_MAX_SIZE    \
    TF_PSA_CRYPTO_PQCP_MLDSA_PUBLIC_KEY_SIZE(87)

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
