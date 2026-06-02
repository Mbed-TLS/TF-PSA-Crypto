/** \brief Simple integration of mldsa-native from PQCP
 *
 * Declare the functions defined in wrap_mldsa_native.c.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_WRAP_MLDSA_NATIVE_H
#define TF_PSA_CRYPTO_WRAP_MLDSA_NATIVE_H

#include <tf-psa-crypto/build_info.h>

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

/* The mldsa-native config file defines options that apply to all
 * parameter sets. It is included both when building code that uses
 * mldsa-native (via wrap_mldsa_native.h) and when building mldsa-native
 * itself (via wrap_mldsa_native.c). */
#define MLD_CONFIG_FILE "pqcp-config.h"

/* Include the declarations of mldsa-native functions, one parameter set
 * (44, 65 or 87) at a time. The function names have the prefix
 * MLD_CONFIG_NAMESPACE_PREFIX defined in pqcp-config.h, followed by
 * the parameter set (except for functions shared between levels), e.g.
 * tf_psa_crypto_pqcp_mldsa87_keypair_internal().
 * */

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED)
#  define MLD_CONFIG_PARAMETER_SET 87
#  include "mldsa_native.h"
#  if defined(TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC)
/* alloc-wrapper functions */
static inline int tf_psa_crypto_pqcp_mldsa87_keypair_internal(
    uint8_t pk[MLDSA_PUBLICKEYBYTES(87)],
    uint8_t sk[MLDSA_SECRETKEYBYTES(87)],
    const uint8_t seed[MLDSA_SEEDBYTES]
    )
{
    int ret = tf_psa_crypto_pqcp_alloc_start();
    if (ret != 0) {
        return ret;
    }
    ret = tf_psa_crypto_pqcp_locked_mldsa87_keypair_internal(pk, sk, seed);
    int cleanup_ret = tf_psa_crypto_pqcp_alloc_done();
    if (ret != 0) {
        return ret;
    } else {
        return cleanup_ret;
    }
}

static inline int tf_psa_crypto_pqcp_mldsa87_keypair(
    uint8_t pk[MLDSA_PUBLICKEYBYTES(87)],
    uint8_t sk[MLDSA_SECRETKEYBYTES(87)]
    )
{
    int ret = tf_psa_crypto_pqcp_alloc_start();
    if (ret != 0) {
        return ret;
    }
    ret = tf_psa_crypto_pqcp_locked_mldsa87_keypair(pk, sk);
    int cleanup_ret = tf_psa_crypto_pqcp_alloc_done();
    if (ret != 0) {
        return ret;
    } else {
        return cleanup_ret;
    }
}

static inline int tf_psa_crypto_pqcp_mldsa87_signature_internal(
    uint8_t sig[MLDSA_BYTES(87)], size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pre, size_t prelen,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t sk[MLDSA_SECRETKEYBYTES(87)],
    int externalmu
    )
{
    int ret = tf_psa_crypto_pqcp_alloc_start();
    if (ret != 0) {
        return ret;
    }
    ret = tf_psa_crypto_pqcp_locked_mldsa87_signature_internal(
        sig, siglen, m, mlen, pre, prelen, rnd, sk, externalmu);
    int cleanup_ret = tf_psa_crypto_pqcp_alloc_done();
    if (ret != 0) {
        return ret;
    } else {
        return cleanup_ret;
    }
}

static inline int tf_psa_crypto_pqcp_mldsa87_signature(
    uint8_t sig[MLDSA_BYTES(87)], size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[MLDSA_SECRETKEYBYTES(87)]
    )
{
    int ret = tf_psa_crypto_pqcp_alloc_start();
    if (ret != 0) {
        return ret;
    }
    ret = tf_psa_crypto_pqcp_locked_mldsa87_signature(sig, siglen, m, mlen, ctx, ctxlen, sk);
    int cleanup_ret = tf_psa_crypto_pqcp_alloc_done();
    if (ret != 0) {
        return ret;
    } else {
        return cleanup_ret;
    }
}

static inline int tf_psa_crypto_pqcp_mldsa87_sign(
    uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[MLDSA_SECRETKEYBYTES(87)]
    )
{
    int ret = tf_psa_crypto_pqcp_alloc_start();
    if (ret != 0) {
        return ret;
    }
    ret = tf_psa_crypto_pqcp_locked_mldsa87_sign(sm, smlen, m, mlen, ctx, ctxlen, sk);
    int cleanup_ret = tf_psa_crypto_pqcp_alloc_done();
    if (ret != 0) {
        return ret;
    } else {
        return cleanup_ret;
    }
}

static inline int tf_psa_crypto_pqcp_mldsa87_verify(
    const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA_PUBLICKEYBYTES(87)]
    )
{
    int ret = tf_psa_crypto_pqcp_alloc_start();
    if (ret != 0) {
        return ret;
    }
    ret = tf_psa_crypto_pqcp_locked_mldsa87_verify(sig, siglen, m, mlen, ctx, ctxlen, pk);
    int cleanup_ret = tf_psa_crypto_pqcp_alloc_done();
    if (ret != 0) {
        return ret;
    } else {
        return cleanup_ret;
    }
}
#  endif
#  undef MLD_CONFIG_PARAMETER_SET
#endif

#endif  /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

#endif /* <wrap_mldsa_native.h> */
