/**
 * \file spake2p.h
 *
 * \brief SPAKE2+ password-authenticated key exchange (RFC 9383)
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef TF_PSA_CRYPTO_MBEDTLS_PRIVATE_SPAKE2P_H
#define TF_PSA_CRYPTO_MBEDTLS_PRIVATE_SPAKE2P_H
#include "mbedtls/private_access.h"

/*
 * SPAKE2+ is an augmented password-authenticated key exchange (aPAKE): the
 * Verifier stores only password-derived registration material (w0 and L), not
 * the password itself, so a compromise of the Verifier does not directly leak
 * a credential usable as the Prover.
 *
 * This file implements the elliptic-curve SPAKE2+ protocol as defined in
 * RFC 9383, for the short-Weierstrass "secp_r1" curves (P-256/P-384/P-521).
 *
 * The protocol is asymmetric. Mapping to RFC 9383 roles:
 *   - #MBEDTLS_SPAKE2P_CLIENT is the Prover   (holds w0 and w1).
 *   - #MBEDTLS_SPAKE2P_SERVER is the Verifier (holds w0 and L).
 *
 * This header covers the full protocol flow: Prover/Verifier setup, key-share
 * generation (write_key_share) and validation (read_key_share), the RFC 9383
 * Section 3.3 transcript hash TT, the confirmation MAC exchange
 * (write_confirm / read_confirm) and the shared-key export
 * (get_shared_key).
 *
 * The key-share serialization is the SEC1 uncompressed point format.
 *
 * Offline registration (deriving w0/w1/L from the password) is out of scope of
 * this module: the caller supplies the already-derived material to
 * mbedtls_spake2p_setup().
 */
#include "tf-psa-crypto/build_info.h"

#include "mbedtls/private/ecp.h"
#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Roles in the SPAKE2+ exchange.
 */
typedef enum {
    MBEDTLS_SPAKE2P_CLIENT = 0,     /**< Client / Prover                    */
    MBEDTLS_SPAKE2P_SERVER,         /**< Server / Verifier                  */
    MBEDTLS_SPAKE2P_NONE,           /**< Undefined                          */
} mbedtls_spake2p_role;

/**
 * MAC primitive used for key confirmation.
 *
 * The MAC and KDF profile is part of the ciphersuite. RFC 9383 defines both an
 * HMAC and a CMAC-AES-128 family.
 */
typedef enum {
    MBEDTLS_SPAKE2P_MAC_HMAC = 0,   /**< HMAC keyed with the ciphersuite hash */
    MBEDTLS_SPAKE2P_MAC_CMAC,       /**< AES-CMAC (CMAC-AES-128)              */
} mbedtls_spake2p_mac_type;

/**
 * SPAKE2+ context structure.
 *
 * The point and scalar names follow RFC 9383: shareP/shareV are the Prover's
 * and Verifier's public shares respectively (so for a client shareP is "mine"
 * and shareV is the peer's, and vice versa for a server). K_confirmP and
 * K_confirmV are the Prover's and Verifier's confirmation keys.
 */
typedef struct mbedtls_spake2p_context {
    mbedtls_md_type_t MBEDTLS_PRIVATE(md_type);           /**< Hash to use            */
    mbedtls_spake2p_mac_type MBEDTLS_PRIVATE(mac_type);   /**< Confirmation MAC       */
    mbedtls_ecp_group MBEDTLS_PRIVATE(grp);               /**< Elliptic curve         */
    mbedtls_spake2p_role MBEDTLS_PRIVATE(role);           /**< Client or server?      */

    mbedtls_mpi MBEDTLS_PRIVATE(w0);                      /**< Shared scalar w0       */
    mbedtls_mpi MBEDTLS_PRIVATE(w1);                      /**< Prover scalar w1       */
    mbedtls_ecp_point MBEDTLS_PRIVATE(L);                 /**< Verifier record L      */

    mbedtls_mpi MBEDTLS_PRIVATE(xy);                      /**< Own ephemeral scalar   */
    mbedtls_ecp_point MBEDTLS_PRIVATE(M);                 /**< Curve constant M       */
    mbedtls_ecp_point MBEDTLS_PRIVATE(N);                 /**< Curve constant N       */
    mbedtls_ecp_point MBEDTLS_PRIVATE(shareP);            /**< Prover public share    */
    mbedtls_ecp_point MBEDTLS_PRIVATE(shareV);            /**< Verifier public share  */
    int MBEDTLS_PRIVATE(have_shareP);                     /**< shareP is populated    */
    int MBEDTLS_PRIVATE(have_shareV);                     /**< shareV is populated    */

    /* Owned copies of the transcript identity/context strings. Either pointer
     * may be NULL, in which case the corresponding length is zero. */
    unsigned char *MBEDTLS_PRIVATE(user);                 /**< Local identity (set_user)  */
    size_t MBEDTLS_PRIVATE(user_len);
    unsigned char *MBEDTLS_PRIVATE(peer);                 /**< Peer identity (set_peer)   */
    size_t MBEDTLS_PRIVATE(peer_len);
    unsigned char *MBEDTLS_PRIVATE(context);              /**< Application context        */
    size_t MBEDTLS_PRIVATE(context_len);

    int MBEDTLS_PRIVATE(keys_ready);                      /**< Key schedule derived?  */
    int MBEDTLS_PRIVATE(confirmed);                       /**< Peer confirmation verified? */
#if defined(MBEDTLS_TEST_HOOKS)
    int MBEDTLS_PRIVATE(tt_prefix_ready);                 /**< TT prefix hash computed?*/
    /** Hash of the share-derivable TT prefix. */
    unsigned char MBEDTLS_PRIVATE(tt_prefix_hash)[MBEDTLS_MD_MAX_SIZE];
#endif /* MBEDTLS_TEST_HOOKS */
    size_t MBEDTLS_PRIVATE(hash_len);                     /**< Hash output length     */
    size_t MBEDTLS_PRIVATE(conf_key_len);                 /**< Confirmation key length*/
    size_t MBEDTLS_PRIVATE(mac_len);                      /**< Confirmation MAC length*/
    size_t MBEDTLS_PRIVATE(shared_key_len);               /**< K_shared length        */
    unsigned char MBEDTLS_PRIVATE(K_confirmP)[MBEDTLS_MD_MAX_SIZE];
    unsigned char MBEDTLS_PRIVATE(K_confirmV)[MBEDTLS_MD_MAX_SIZE];
    unsigned char MBEDTLS_PRIVATE(K_shared)[MBEDTLS_MD_MAX_SIZE];
} mbedtls_spake2p_context;

#if defined(MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS)

/**
 * \brief           Initialize a SPAKE2+ context.
 *
 * \param ctx       The SPAKE2+ context to initialize.
 *                  This must not be \c NULL.
 */
void mbedtls_spake2p_init(mbedtls_spake2p_context *ctx);

/**
 * \brief           Set up a SPAKE2+ context for use.
 *
 *                  This loads the ciphersuite (hash, MAC and curve), the
 *                  per-curve M/N constants, and the password-derived key
 *                  material. The key material is the concatenation defined by
 *                  RFC 9383 offline registration:
 *                  - For #MBEDTLS_SPAKE2P_CLIENT: \c w0 || \c w1, where each is
 *                    a big-endian scalar of length \c ceil(bits/8).
 *                  - For #MBEDTLS_SPAKE2P_SERVER: \c w0 || \c L, where \c L is a
 *                    SEC1 uncompressed point.
 *
 * \note            Supported over the secp_r1 curves (P-256/P-384/P-521).
 *                  #MBEDTLS_SPAKE2P_MAC_CMAC additionally requires
 *                  #MBEDTLS_CMAC_C. The RFC 9383 Matter ciphersuite is the
 *                  HMAC profile pinned to P-256/SHA-256, set up with
 *                  #MBEDTLS_SPAKE2P_MAC_HMAC.
 *
 * \param ctx       The SPAKE2+ context to set up. This must be initialized.
 * \param role      #MBEDTLS_SPAKE2P_CLIENT or #MBEDTLS_SPAKE2P_SERVER.
 * \param hash      The hash function identifier, e.g. #MBEDTLS_MD_SHA256.
 * \param mac       The confirmation MAC primitive.
 * \param curve     The elliptic curve identifier,
 *                  e.g. #MBEDTLS_ECP_DP_SECP256R1.
 * \param key       The password-derived key material (see above).
 * \param key_len   The length in bytes of \p key.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_spake2p_setup(mbedtls_spake2p_context *ctx,
                          mbedtls_spake2p_role role,
                          mbedtls_md_type_t hash,
                          mbedtls_spake2p_mac_type mac,
                          mbedtls_ecp_group_id curve,
                          const unsigned char *key,
                          size_t key_len);

/**
 * \brief           Set the application context string for the transcript.
 *
 *                  This is the RFC 9383 \c Context value. It may be set to an
 *                  empty string (\p len = 0). If never set, an empty context is
 *                  used. This must be called before the key schedule is derived
 *                  (i.e. before both key shares have been exchanged).
 *
 * \param ctx       The SPAKE2+ context.
 * \param context   The context bytes. May be \c NULL if \p len is \c 0.
 * \param len       The length in bytes of \p context.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_spake2p_set_context(mbedtls_spake2p_context *ctx,
                                const unsigned char *context,
                                size_t len);

/**
 * \brief           Set the local party's identity for the transcript.
 *
 *                  For a client this is \c idProver; for a server it is
 *                  \c idVerifier (see RFC 9383 Section 3.3).
 *
 * \param ctx       The SPAKE2+ context.
 * \param user      The local identity bytes. May be \c NULL if \p len is \c 0.
 * \param len       The length in bytes of \p user.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_spake2p_set_user(mbedtls_spake2p_context *ctx,
                             const unsigned char *user,
                             size_t len);

/**
 * \brief           Set the peer party's identity for the transcript.
 *
 *                  For a client this is \c idVerifier; for a server it is
 *                  \c idProver (see RFC 9383 Section 3.3).
 *
 * \param ctx       The SPAKE2+ context.
 * \param peer      The peer identity bytes. May be \c NULL if \p len is \c 0.
 * \param len       The length in bytes of \p peer.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_spake2p_set_peer(mbedtls_spake2p_context *ctx,
                             const unsigned char *peer,
                             size_t len);

/**
 * \brief           Generate and write this party's public key share.
 *
 *                  For a client this is \c shareP = x*P + w0*M; for a server it
 *                  is \c shareV = y*P + w0*N. The share is written in SEC1
 *                  uncompressed point format.
 *
 * \param ctx       The SPAKE2+ context. This must be set up.
 * \param buf       The buffer to write the share to.
 * \param len       The size of \p buf in bytes.
 * \param olen      The address at which to store the number of bytes written.
 *                  This must not be \c NULL.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG parameter to pass to \p f_rng. May be \c NULL.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_spake2p_write_key_share(mbedtls_spake2p_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng);

/**
 * \brief           Read and process the peer's public key share.
 *
 *                  The point is validated for group membership (RFC 9383
 *                  Section 6). For a client this stores \c shareV, for a server
 *                  \c shareP. Once both this party's and the peer's shares are
 *                  known, the transcript hash TT (RFC 9383 Section 3.3) is
 *                  accumulated over the fields that are derivable from the
 *                  shares (Context, idProver, idVerifier, M, N, shareP,
 *                  shareV).
 *
 *                  Once both shares are known, the shared values Z and V, the
 *                  full transcript TT and the key schedule (K_confirmP,
 *                  K_confirmV, K_shared) are derived. Deriving Z and V requires
 *                  elliptic-curve scalar multiplications, so an RNG is needed
 *                  for the side-channel countermeasures even though no new
 *                  secret is generated here.
 *
 * \param ctx       The SPAKE2+ context. This must be set up.
 * \param buf       The buffer holding the peer's share (SEC1 uncompressed).
 * \param len       The length in bytes of \p buf.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG parameter to pass to \p f_rng. May be \c NULL.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_spake2p_read_key_share(mbedtls_spake2p_context *ctx,
                                   const unsigned char *buf, size_t len,
                                   int (*f_rng)(void *, unsigned char *, size_t),
                                   void *p_rng);

/**
 * \brief           Generate and write this party's confirmation MAC.
 *
 *                  For a client this is \c confirmP = MAC(K_confirmP, shareV);
 *                  for a server it is \c confirmV = MAC(K_confirmV, shareP).
 *
 * \param ctx       The SPAKE2+ context. The key schedule must be derived
 *                  (both key shares exchanged).
 * \param buf       The buffer to write the confirmation MAC to.
 * \param len       The size of \p buf in bytes.
 * \param olen      The address at which to store the number of bytes written.
 *                  This must not be \c NULL.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_spake2p_write_confirm(mbedtls_spake2p_context *ctx,
                                  unsigned char *buf, size_t len, size_t *olen);

/**
 * \brief           Read and verify the peer's confirmation MAC.
 *
 *                  For a client the peer message is
 *                  \c confirmV = MAC(K_confirmV, shareP); for a server it is
 *                  \c confirmP = MAC(K_confirmP, shareV). The comparison is
 *                  performed in constant time.
 *
 * \param ctx       The SPAKE2+ context. The key schedule must be derived.
 * \param buf       The buffer holding the peer's confirmation MAC.
 * \param len       The length in bytes of \p buf.
 *
 * \return          \c 0 if the confirmation message is valid.
 * \return          #MBEDTLS_ERR_ECP_VERIFY_FAILED if the MAC does not match.
 * \return          Another negative error code on other failures.
 */
int mbedtls_spake2p_read_confirm(mbedtls_spake2p_context *ctx,
                                 const unsigned char *buf, size_t len);

/**
 * \brief           Write the derived shared key (RFC 9383 \c K_shared).
 *
 * \note            As a security measure this fails unless the peer's key
 *                  confirmation has been successfully verified with
 *                  mbedtls_spake2p_read_confirm(): the shared key must never be
 *                  released before key confirmation completes. This check is
 *                  independent of any call-sequence enforcement done by the
 *                  caller.
 *
 * \param ctx       The SPAKE2+ context. The key schedule must be derived and
 *                  the peer's confirmation must have been verified.
 * \param buf       The buffer to write the shared key to.
 * \param len       The size of \p buf in bytes.
 * \param olen      The address at which to store the number of bytes written.
 *                  This must not be \c NULL.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_spake2p_get_shared_key(mbedtls_spake2p_context *ctx,
                                   unsigned char *buf, size_t len, size_t *olen);

/**
 * \brief           Clear a SPAKE2+ context and free embedded data.
 *
 * \param ctx       The SPAKE2+ context to free. This may be \c NULL, in which
 *                  case this function does nothing. Otherwise it must point to
 *                  an initialized SPAKE2+ context.
 */
void mbedtls_spake2p_free(mbedtls_spake2p_context *ctx);

#endif /* MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS */

#ifdef __cplusplus
}
#endif

#endif /* TF_PSA_CRYPTO_MBEDTLS_PRIVATE_SPAKE2P_H */
