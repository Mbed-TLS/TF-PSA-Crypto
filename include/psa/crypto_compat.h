/**
 * \file psa/crypto_compat.h
 *
 * \brief PSA cryptography module: Backward compatibility aliases
 *
 * This header declares alternative names for macro and functions.
 * New application code should not use these names.
 * These names may be removed in a future version of Mbed TLS.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_COMPAT_H
#define PSA_CRYPTO_COMPAT_H

#ifdef __cplusplus
extern "C" {
#endif

/* This function is not a TF-PSA-Crypto API and may be removed without notice.
 *
 * Dummy version of a function removed in
 * https://github.com/Mbed-TLS/TF-PSA-Crypto/pull/466
 *
 * The function needs to remain available during a transition period
 * for the sake of the PSA simulator, which lives in Mbed TLS.
 * Once TF-PSA-Crypto no longer needs the function,
 * `tests/psa-client-server/psasim/src/psa_sim_crypto_server.c` will
 * need to be updated to no longer need the function, and it will be
 * possible to remove the corresponding RPC call altogether.
 */
int psa_can_do_hash(psa_algorithm_t hash_alg);

/* This defition is required to provide compatibility with the PSA arch
 * tests. Without it building the tests will fail. To remove it we would
 * need to change the tests to remove all references to this symbol.
 */
#define PSA_KEY_TYPE_DES ((psa_key_type_t) 0x2301)

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_COMPAT_H */
