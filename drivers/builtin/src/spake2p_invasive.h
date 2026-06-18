/**
 * \file spake2p_invasive.h
 *
 * \brief SPAKE2+ module: interfaces for invasive testing only.
 *
 * The interfaces in this file are intended for testing purposes only.
 * They SHOULD NOT be made available in library integrations except when
 * building the library for testing.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef TF_PSA_CRYPTO_SPAKE2P_INVASIVE_H
#define TF_PSA_CRYPTO_SPAKE2P_INVASIVE_H

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_SPAKE2P_C)

#include "mbedtls/private/spake2p.h"

/**
 * \brief           Generate and write this party's public key share using a
 *                  caller-supplied ephemeral scalar.
 *
 *                  This is identical to mbedtls_spake2p_write_key_share()
 *                  except that the ephemeral scalar (\c x for a client, \c y
 *                  for a server) is taken from \p ephemeral instead of being
 *                  generated randomly. It exists solely so that the test suite
 *                  can validate the key-share output against RFC 9383 known
 *                  answer test vectors, which fix the ephemeral.
 *
 *                  The RNG is still required for the side-channel
 *                  countermeasures of the scalar multiplications; it does not
 *                  affect the deterministic output.
 *
 * \param ctx           The SPAKE2+ context. This must be set up.
 * \param ephemeral     The ephemeral scalar, big-endian, in [1, n-1].
 * \param ephemeral_len The length in bytes of \p ephemeral.
 * \param buf           The buffer to write the share to.
 * \param len           The size of \p buf in bytes.
 * \param olen          The address at which to store the number of bytes
 *                      written. This must not be \c NULL.
 * \param f_rng         The RNG function to use. This must not be \c NULL.
 * \param p_rng         The RNG parameter to pass to \p f_rng. May be \c NULL.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_spake2p_write_key_share_with_ephemeral(
    mbedtls_spake2p_context *ctx,
    const unsigned char *ephemeral, size_t ephemeral_len,
    unsigned char *buf, size_t len, size_t *olen,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);

/**
 * \brief           Test-only ephemeral injection for the next key-share write.
 *
 *                  When #mbedtls_spake2p_test_injected_ephemeral is non-NULL,
 *                  the next call to mbedtls_spake2p_write_key_share() uses it as
 *                  the ephemeral scalar instead of generating one, and then
 *                  clears the pointer (single use). Unlike
 *                  mbedtls_spake2p_write_key_share_with_ephemeral(), this seam
 *                  also reaches the share produced internally by
 *                  psa_pake_output(), whose builtin context is created lazily
 *                  and so cannot be addressed by the caller. It exists solely so
 *                  that the PSA-level test suite can validate psa_pake_output()
 *                  against RFC 9383 known-answer vectors, which fix the
 *                  ephemeral.
 */
extern const unsigned char *mbedtls_spake2p_test_injected_ephemeral;
extern size_t mbedtls_spake2p_test_injected_ephemeral_len;

/**
 * \brief           Read back the accumulated transcript-prefix hash.
 *
 *                  Returns Hash(prefix), where prefix is the share-derivable
 *                  part of the RFC 9383 Section 3.3 transcript TT (the
 *                  length-prefixed concatenation of Context, idProver,
 *                  idVerifier, M, N, shareP, shareV). It exists solely so the
 *                  test suite can validate the transcript field encoding
 *                  against RFC 9383 Appendix C values, independently of the
 *                  (out-of-scope) key schedule.
 *
 *                  The transcript TT itself is internal and normally only
 *                  observable through the downstream confirmation MAC and
 *                  shared key; this hook makes the in-scope prefix testable.
 *
 * \param ctx       The SPAKE2+ context. Both key shares must have been
 *                  exchanged (write_key_share and read_key_share both done).
 * \param out       Buffer to receive the hash.
 * \param out_size  Size of \p out in bytes; must be at least the hash length.
 * \param out_len   Address at which to store the number of bytes written.
 *
 * \return          \c 0 on success.
 * \return          A negative error code if the prefix is not yet available or
 *                  the buffer is too small.
 */
int mbedtls_spake2p_test_get_transcript_prefix_hash(
    const mbedtls_spake2p_context *ctx,
    unsigned char *out, size_t out_size, size_t *out_len);

#endif /* MBEDTLS_TEST_HOOKS && MBEDTLS_SPAKE2P_C */

#endif /* TF_PSA_CRYPTO_SPAKE2P_INVASIVE_H */
