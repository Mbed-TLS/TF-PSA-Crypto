/*
 *  SPAKE2+ password-authenticated key exchange (RFC 9383)
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References in the code are to RFC 9383, "SPAKE2+, an Augmented Password-
 * Authenticated Key Exchange (PAKE) Protocol".
 *
 * This module implements the secp_r1 ciphersuites (P-256/P-384/P-521). The
 * cofactor h is 1 for all of these curves, so the "h*" cofactor
 * multiplications of RFC 9383 Section 3.3 are no-ops and are omitted; group
 * membership is enforced with mbedtls_ecp_check_pubkey().
 *
 * This slice covers setup, the generation of this party's public key share
 * (write_key_share), reading the peer's key share (read_key_share), the
 * accumulation of the RFC 9383 Section 3.3 transcript hash TT, the key schedule
 * that derives K_confirmP / K_confirmV / K_shared from TT (RFC 9383 Section
 * 3.3-3.4), and the verifier confirmation MAC output (write_confirm).
 *
 * Only the HMAC confirmation profile is wired in this slice; the CMAC/Matter
 * MAC arms, the peer confirmation check (read_confirm) and the shared-key
 * export (get_shared_key) land in subsequent changes.
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_SPAKE2P_C)

#include "mbedtls/private/spake2p.h"
#include "spake2p_invasive.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/private/error_common.h"

#include <string.h>

/* CMAC-AES-128 confirmation key length / tag length (RFC 9383 Section 3.4). */
#define SPAKE2P_CMAC_KEY_LEN  16
#define SPAKE2P_CMAC_TAG_LEN  16

/*
 * Per-curve constant points M and N (RFC 9383 Section 4), stored in SEC1
 * compressed form. mbedtls_ecp_point_read_binary() decompresses them.
 */
static const unsigned char spake2p_secp256r1_M[] = {
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7,
    0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab,
    0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f,
};
static const unsigned char spake2p_secp256r1_N[] = {
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99,
    0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49,
    0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
};
static const unsigned char spake2p_secp384r1_M[] = {
    0x03, 0x0f, 0xf0, 0x89, 0x5a, 0xe5, 0xeb, 0xf6, 0x18, 0x70, 0x80, 0xa8,
    0x2d, 0x82, 0xb4, 0x2e, 0x27, 0x65, 0xe3, 0xb2, 0xf8, 0x74, 0x9c, 0x7e,
    0x05, 0xeb, 0xa3, 0x66, 0x43, 0x4b, 0x36, 0x3d, 0x3d, 0xc3, 0x6f, 0x15,
    0x31, 0x47, 0x39, 0x07, 0x4d, 0x2e, 0xb8, 0x61, 0x3f, 0xce, 0xec, 0x28,
    0x53,
};
static const unsigned char spake2p_secp384r1_N[] = {
    0x02, 0xc7, 0x2c, 0xf2, 0xe3, 0x90, 0x85, 0x3a, 0x1c, 0x1c, 0x4a, 0xd8,
    0x16, 0xa6, 0x2f, 0xd1, 0x58, 0x24, 0xf5, 0x60, 0x78, 0x91, 0x8f, 0x43,
    0xf9, 0x22, 0xca, 0x21, 0x51, 0x8f, 0x9c, 0x54, 0x3b, 0xb2, 0x52, 0xc5,
    0x49, 0x02, 0x14, 0xcf, 0x9a, 0xa3, 0xf0, 0xba, 0xab, 0x4b, 0x66, 0x5c,
    0x10,
};
static const unsigned char spake2p_secp521r1_M[] = {
    0x02, 0x00, 0x3f, 0x06, 0xf3, 0x81, 0x31, 0xb2, 0xba, 0x26, 0x00, 0x79,
    0x1e, 0x82, 0x48, 0x8e, 0x8d, 0x20, 0xab, 0x88, 0x9a, 0xf7, 0x53, 0xa4,
    0x18, 0x06, 0xc5, 0xdb, 0x18, 0xd3, 0x7d, 0x85, 0x60, 0x8c, 0xfa, 0xe0,
    0x6b, 0x82, 0xe4, 0xa7, 0x2c, 0xd7, 0x44, 0xc7, 0x19, 0x19, 0x35, 0x62,
    0xa6, 0x53, 0xea, 0x1f, 0x11, 0x9e, 0xef, 0x93, 0x56, 0x90, 0x7e, 0xdc,
    0x9b, 0x56, 0x97, 0x99, 0x62, 0xd7, 0xaa,
};
static const unsigned char spake2p_secp521r1_N[] = {
    0x02, 0x00, 0xc7, 0x92, 0x4b, 0x9e, 0xc0, 0x17, 0xf3, 0x09, 0x45, 0x62,
    0x89, 0x43, 0x36, 0xa5, 0x3c, 0x50, 0x16, 0x7b, 0xa8, 0xc5, 0x96, 0x38,
    0x76, 0x88, 0x05, 0x42, 0xbc, 0x66, 0x9e, 0x49, 0x4b, 0x25, 0x32, 0xd7,
    0x6c, 0x5b, 0x53, 0xdf, 0xb3, 0x49, 0xfd, 0xf6, 0x91, 0x54, 0xb9, 0xe0,
    0x04, 0x8c, 0x58, 0xa4, 0x2e, 0x8e, 0xd0, 0x4c, 0xef, 0x05, 0x2a, 0x3b,
    0xc3, 0x49, 0xd9, 0x55, 0x75, 0xcd, 0x25,
};

/*
 * Look up the compressed M and N constants for a curve.
 * Returns 0 and fills the pointers/length on success, a negative error if the
 * curve is not a supported SPAKE2+ ciphersuite group.
 */
static int spake2p_get_mn(mbedtls_ecp_group_id curve,
                          const unsigned char **m, const unsigned char **n,
                          size_t *clen)
{
    switch (curve) {
        case MBEDTLS_ECP_DP_SECP256R1:
            *m = spake2p_secp256r1_M;
            *n = spake2p_secp256r1_N;
            *clen = sizeof(spake2p_secp256r1_M);
            return 0;
        case MBEDTLS_ECP_DP_SECP384R1:
            *m = spake2p_secp384r1_M;
            *n = spake2p_secp384r1_N;
            *clen = sizeof(spake2p_secp384r1_M);
            return 0;
        case MBEDTLS_ECP_DP_SECP521R1:
            *m = spake2p_secp521r1_M;
            *n = spake2p_secp521r1_N;
            *clen = sizeof(spake2p_secp521r1_M);
            return 0;
        default:
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
}

/*
 * HKDF (RFC 5869) with a nil salt, as used by the SPAKE2+ key schedule:
 * OKM = HKDF-Expand(HKDF-Extract(0, IKM), info, okm_len).
 * okm_len is bounded by the key schedule (at most 2 * hash_len).
 */
static int spake2p_hkdf(const mbedtls_md_info_t *md_info, size_t hash_len,
                        const unsigned char *ikm, size_t ikm_len,
                        const char *info, size_t info_len,
                        unsigned char *okm, size_t okm_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char salt[MBEDTLS_MD_MAX_SIZE];
    unsigned char prk[MBEDTLS_MD_MAX_SIZE];
    unsigned char t[MBEDTLS_MD_MAX_SIZE];
    unsigned char in[MBEDTLS_MD_MAX_SIZE + 32];
    size_t done = 0, t_len = 0;
    unsigned char counter = 0;

    /* HKDF-Extract: a nil salt is HashLen zero bytes (RFC 5869 Section 2.2). */
    memset(salt, 0, hash_len);
    ret = mbedtls_md_hmac(md_info, salt, hash_len, ikm, ikm_len, prk);
    if (ret != 0) {
        goto exit;
    }

    /* HKDF-Expand. */
    while (done < okm_len) {
        size_t off = 0, n;
        counter++;
        if (t_len != 0) {
            memcpy(in, t, t_len);
            off = t_len;
        }
        memcpy(in + off, info, info_len);
        off += info_len;
        in[off++] = counter;

        ret = mbedtls_md_hmac(md_info, prk, hash_len, in, off, t);
        if (ret != 0) {
            goto exit;
        }
        t_len = hash_len;

        n = (okm_len - done < hash_len) ? okm_len - done : hash_len;
        memcpy(okm + done, t, n);
        done += n;
    }

    ret = 0;

exit:
    mbedtls_platform_zeroize(salt, sizeof(salt));
    mbedtls_platform_zeroize(prk, sizeof(prk));
    mbedtls_platform_zeroize(t, sizeof(t));
    mbedtls_platform_zeroize(in, sizeof(in));
    return ret;
}

/*
 * Initialize context
 */
void mbedtls_spake2p_init(mbedtls_spake2p_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->md_type = MBEDTLS_MD_NONE;
    ctx->mac_type = MBEDTLS_SPAKE2P_MAC_HMAC;
    ctx->role = MBEDTLS_SPAKE2P_NONE;
    mbedtls_ecp_group_init(&ctx->grp);

    mbedtls_mpi_init(&ctx->w0);
    mbedtls_mpi_init(&ctx->w1);
    mbedtls_ecp_point_init(&ctx->L);

    mbedtls_mpi_init(&ctx->xy);
    mbedtls_ecp_point_init(&ctx->M);
    mbedtls_ecp_point_init(&ctx->N);
    mbedtls_ecp_point_init(&ctx->shareP);
    mbedtls_ecp_point_init(&ctx->shareV);
}

/*
 * Free context
 */
void mbedtls_spake2p_free(mbedtls_spake2p_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_ecp_group_free(&ctx->grp);

    mbedtls_mpi_free(&ctx->w0);
    mbedtls_mpi_free(&ctx->w1);
    mbedtls_ecp_point_free(&ctx->L);

    mbedtls_mpi_free(&ctx->xy);
    mbedtls_ecp_point_free(&ctx->M);
    mbedtls_ecp_point_free(&ctx->N);
    mbedtls_ecp_point_free(&ctx->shareP);
    mbedtls_ecp_point_free(&ctx->shareV);

    mbedtls_free(ctx->user);
    mbedtls_free(ctx->peer);
    mbedtls_free(ctx->context);

    mbedtls_platform_zeroize(ctx->K_confirmP, sizeof(ctx->K_confirmP));
    mbedtls_platform_zeroize(ctx->K_confirmV, sizeof(ctx->K_confirmV));
    mbedtls_platform_zeroize(ctx->K_shared, sizeof(ctx->K_shared));

    memset(ctx, 0, sizeof(*ctx));
}

/*
 * Set up context
 */
int mbedtls_spake2p_setup(mbedtls_spake2p_context *ctx,
                          mbedtls_spake2p_role role,
                          mbedtls_md_type_t hash,
                          mbedtls_spake2p_mac_type mac,
                          mbedtls_ecp_group_id curve,
                          const unsigned char *key,
                          size_t key_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_md_info_t *md_info;
    const unsigned char *m_const, *n_const;
    size_t clen, plen, point_len;

    if (role != MBEDTLS_SPAKE2P_CLIENT && role != MBEDTLS_SPAKE2P_SERVER) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    md_info = mbedtls_md_info_from_type(hash);
    if (md_info == NULL) {
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }

    ctx->role = role;
    ctx->md_type = hash;
    ctx->mac_type = mac;
    ctx->hash_len = mbedtls_md_get_size(md_info);
    /* The KDF (HKDF) and K_shared always use the ciphersuite hash; only the
     * confirmation MAC and its key length depend on the MAC primitive
     * (RFC 9383 Section 3.4). */
    ctx->shared_key_len = ctx->hash_len;

    switch (mac) {
        case MBEDTLS_SPAKE2P_MAC_HMAC:
            /* HMAC: confirmation key and tag length equal the hash length. */
            ctx->conf_key_len = ctx->hash_len;
            ctx->mac_len = ctx->hash_len;
            break;
        case MBEDTLS_SPAKE2P_MAC_CMAC:
#if defined(MBEDTLS_CMAC_C)
            ctx->conf_key_len = SPAKE2P_CMAC_KEY_LEN;
            ctx->mac_len = SPAKE2P_CMAC_TAG_LEN;
            break;
#else
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#endif
        default:
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    if ((ret = spake2p_get_mn(curve, &m_const, &n_const, &clen)) != 0) {
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&ctx->grp, curve));

    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->M,
                                                  m_const, clen));
    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->N,
                                                  n_const, clen));

    /* Scalar and coordinate byte length (equal for secp_r1). */
    plen = mbedtls_mpi_size(&ctx->grp.P);
    point_len = 2 * plen + 1;

    if (role == MBEDTLS_SPAKE2P_CLIENT) {
        /* key = w0 || w1, each a plen-byte scalar. */
        if (key_len != 2 * plen) {
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            goto cleanup;
        }
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->w0, key, plen));
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->w1, key + plen, plen));
        /* w0 and w1 are scalars mod n (RFC 9383 Section 3.2). Reduce so the
         * constant-time scalar multiplications are well-defined even for an
         * out-of-range imported value. */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&ctx->w1, &ctx->w1, &ctx->grp.N));
    } else {
        /* key = w0 || L, with L a SEC1 uncompressed point. */
        if (key_len != plen + point_len) {
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            goto cleanup;
        }
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->w0, key, plen));
        MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->L,
                                                      key + plen, point_len));
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(&ctx->grp, &ctx->L));
    }
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&ctx->w0, &ctx->w0, &ctx->grp.N));

cleanup:
    if (ret != 0) {
        mbedtls_spake2p_free(ctx);
    }

    return ret;
}

/*
 * Replace a heap-allocated transcript string with a fresh copy.
 */
static int spake2p_set_buf(unsigned char **dst, size_t *dst_len,
                           const unsigned char *src, size_t len)
{
    mbedtls_free(*dst);
    *dst = NULL;
    *dst_len = 0;

    if (len > 0) {
        *dst = mbedtls_calloc(1, len);
        if (*dst == NULL) {
            return MBEDTLS_ERR_MPI_ALLOC_FAILED;
        }
        memcpy(*dst, src, len);
        *dst_len = len;
    }

    return 0;
}

int mbedtls_spake2p_set_context(mbedtls_spake2p_context *ctx,
                                const unsigned char *context, size_t len)
{
    if (ctx->keys_ready) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    return spake2p_set_buf(&ctx->context, &ctx->context_len, context, len);
}

int mbedtls_spake2p_set_user(mbedtls_spake2p_context *ctx,
                             const unsigned char *user, size_t len)
{
    if (ctx->keys_ready) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    return spake2p_set_buf(&ctx->user, &ctx->user_len, user, len);
}

int mbedtls_spake2p_set_peer(mbedtls_spake2p_context *ctx,
                             const unsigned char *peer, size_t len)
{
    if (ctx->keys_ready) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    return spake2p_set_buf(&ctx->peer, &ctx->peer_len, peer, len);
}

/*
 * Absorb one 8-byte little-endian length-prefixed field into the running
 * transcript hash (the TT encoding of RFC 9383 Section 3.3).
 */
static int spake2p_tt_update(mbedtls_md_context_t *md,
                             const unsigned char *data, size_t len)
{
    unsigned char lenbuf[8];
    int ret;

    MBEDTLS_PUT_UINT64_LE((uint64_t) len, lenbuf, 0);
    if ((ret = mbedtls_md_update(md, lenbuf, sizeof(lenbuf))) != 0) {
        return ret;
    }
    if (len > 0) {
        if ((ret = mbedtls_md_update(md, data, len)) != 0) {
            return ret;
        }
    }
    return 0;
}

static int spake2p_tt_update_point(mbedtls_md_context_t *md,
                                   const mbedtls_ecp_group *grp,
                                   const mbedtls_ecp_point *pt)
{
    unsigned char tmp[MBEDTLS_ECP_MAX_PT_LEN];
    size_t len;
    int ret = mbedtls_ecp_point_write_binary(grp, pt,
                                             MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &len, tmp, sizeof(tmp));
    if (ret != 0) {
        return ret;
    }
    return spake2p_tt_update(md, tmp, len);
}

/*
 * Accumulate the share-derivable prefix of the transcript TT into a hash.
 *
 * TT is the hash of 10 length-prefixed fields (RFC 9383 Section 3.3):
 *   Context, idProver, idVerifier, M, N, shareP, shareV, Z, V, w0.
 * The first seven are fixed by the ciphersuite and the exchanged shares; the
 * remaining three (Z, V, w0) are secret-derived and belong to the key schedule
 * (out of scope here). This computes Hash(prefix) once both shares exist so the
 * transcript field encoding can be validated independently of key derivation.
 *
 * idProver/idVerifier are fixed by RFC role, not by which party we are.
 */
#if defined(MBEDTLS_TEST_HOOKS)
static int spake2p_update_tt_prefix(mbedtls_spake2p_context *ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(ctx->md_type);
    mbedtls_md_context_t md_ctx;
    const unsigned char *id_prover, *id_verifier;
    size_t id_prover_len, id_verifier_len;

    mbedtls_md_init(&md_ctx);

    if (ctx->role == MBEDTLS_SPAKE2P_CLIENT) {
        id_prover = ctx->user;   id_prover_len = ctx->user_len;
        id_verifier = ctx->peer; id_verifier_len = ctx->peer_len;
    } else {
        id_prover = ctx->peer;   id_prover_len = ctx->peer_len;
        id_verifier = ctx->user; id_verifier_len = ctx->user_len;
    }

    MBEDTLS_MPI_CHK(mbedtls_md_setup(&md_ctx, md_info, 0));
    MBEDTLS_MPI_CHK(mbedtls_md_starts(&md_ctx));
    MBEDTLS_MPI_CHK(spake2p_tt_update(&md_ctx, ctx->context, ctx->context_len));
    MBEDTLS_MPI_CHK(spake2p_tt_update(&md_ctx, id_prover, id_prover_len));
    MBEDTLS_MPI_CHK(spake2p_tt_update(&md_ctx, id_verifier, id_verifier_len));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &ctx->M));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &ctx->N));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &ctx->shareP));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &ctx->shareV));
    MBEDTLS_MPI_CHK(mbedtls_md_finish(&md_ctx, ctx->tt_prefix_hash));

    ctx->tt_prefix_ready = 1;

cleanup:
    mbedtls_md_free(&md_ctx);
    return ret;
}
#endif /* MBEDTLS_TEST_HOOKS */

/*
 * Derive the SPAKE2+ key schedule once both shares are known (RFC 9383
 * Section 3.3-3.4): compute the shared values Z and V, finalize the full
 * transcript TT (10 fields, adding Z, V and w0 to the share-derivable prefix),
 * and expand K_main into K_confirmP / K_confirmV / K_shared.
 *
 * Only the HMAC profile is wired here; the CMAC/Matter MAC arms land in a
 * later change. shared_key_len, conf_key_len and mac_len are fixed at setup.
 */
static int spake2p_derive_keys(mbedtls_spake2p_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(ctx->md_type);
    mbedtls_ecp_point T, Z, V, mask;
    mbedtls_mpi one, neg_w0;
    const mbedtls_ecp_point *Ks, *peer_share;
    mbedtls_md_context_t md_ctx;
    size_t plen = mbedtls_mpi_size(&ctx->grp.P);
    const unsigned char *id_prover, *id_verifier;
    size_t id_prover_len, id_verifier_len;
    unsigned char k_main[MBEDTLS_MD_MAX_SIZE];
    unsigned char conf[2 * MBEDTLS_MD_MAX_SIZE];
    unsigned char w0_buf[MBEDTLS_ECP_MAX_BYTES];

    mbedtls_ecp_point_init(&T);
    mbedtls_ecp_point_init(&Z);
    mbedtls_ecp_point_init(&V);
    mbedtls_ecp_point_init(&mask);
    mbedtls_mpi_init(&one);
    mbedtls_mpi_init(&neg_w0);
    mbedtls_md_init(&md_ctx);

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));
    /* neg_w0 = (-w0) mod n, so (neg_w0)*K = -w0*K for an order-n point K. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&neg_w0, &ctx->grp.N, &ctx->w0));

    if (ctx->role == MBEDTLS_SPAKE2P_CLIENT) {
        Ks = &ctx->N;
        peer_share = &ctx->shareV;
    } else {
        Ks = &ctx->M;
        peer_share = &ctx->shareP;
    }

    /* T = peer_share - w0*Ks. Compute the secret (-w0)*Ks with the
     * constant-time mbedtls_ecp_mul() (not the variable-time muladd, which
     * would leak w0), then add to peer_share with a public-scalar muladd. */
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &mask, &neg_w0, Ks,
                                    f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&ctx->grp, &T,
                                       &one, peer_share, &one, &mask));

    /* Z and V (cofactor h = 1 for secp_r1). */
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &Z, &ctx->xy, &T, f_rng, p_rng));
    if (ctx->role == MBEDTLS_SPAKE2P_CLIENT) {
        /* V = w1 * (shareV - w0*N) */
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &V, &ctx->w1, &T,
                                        f_rng, p_rng));
    } else {
        /* V = y * L */
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &V, &ctx->xy, &ctx->L,
                                        f_rng, p_rng));
    }

    /* Defence in depth (RFC 9383 Section 6): a degenerate shared value means
     * the peer's share or L drove Z/V to the identity; abort rather than
     * derive keys from it. */
    if (mbedtls_ecp_is_zero(&Z) || mbedtls_ecp_is_zero(&V)) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    /* idProver/idVerifier are fixed by RFC role, not by who we are. */
    if (ctx->role == MBEDTLS_SPAKE2P_CLIENT) {
        id_prover = ctx->user;   id_prover_len = ctx->user_len;
        id_verifier = ctx->peer; id_verifier_len = ctx->peer_len;
    } else {
        id_prover = ctx->peer;   id_prover_len = ctx->peer_len;
        id_verifier = ctx->user; id_verifier_len = ctx->user_len;
    }

    /* TT = 10 length-prefixed fields: Context, idProver, idVerifier, M, N,
     * shareP, shareV, Z, V, w0. RFC 9383 hashes their concatenation; we absorb
     * them one field at a time so no full-transcript buffer is required. */
    MBEDTLS_MPI_CHK(mbedtls_md_setup(&md_ctx, md_info, 0));
    MBEDTLS_MPI_CHK(mbedtls_md_starts(&md_ctx));
    MBEDTLS_MPI_CHK(spake2p_tt_update(&md_ctx, ctx->context, ctx->context_len));
    MBEDTLS_MPI_CHK(spake2p_tt_update(&md_ctx, id_prover, id_prover_len));
    MBEDTLS_MPI_CHK(spake2p_tt_update(&md_ctx, id_verifier, id_verifier_len));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &ctx->M));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &ctx->N));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &ctx->shareP));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &ctx->shareV));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &Z));
    MBEDTLS_MPI_CHK(spake2p_tt_update_point(&md_ctx, &ctx->grp, &V));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->w0, w0_buf, plen));
    MBEDTLS_MPI_CHK(spake2p_tt_update(&md_ctx, w0_buf, plen));

    /* K_main = Hash(TT) */
    MBEDTLS_MPI_CHK(mbedtls_md_finish(&md_ctx, k_main));

    /* K_confirmP || K_confirmV = HKDF(nil, K_main, "ConfirmationKeys") */
    MBEDTLS_MPI_CHK(spake2p_hkdf(md_info, ctx->hash_len,
                                 k_main, ctx->hash_len,
                                 "ConfirmationKeys", 16,
                                 conf, 2 * ctx->conf_key_len));
    memcpy(ctx->K_confirmP, conf, ctx->conf_key_len);
    memcpy(ctx->K_confirmV, conf + ctx->conf_key_len, ctx->conf_key_len);

    /* K_shared = HKDF(nil, K_main, "SharedKey") */
    MBEDTLS_MPI_CHK(spake2p_hkdf(md_info, ctx->hash_len,
                                 k_main, ctx->hash_len,
                                 "SharedKey", 9,
                                 ctx->K_shared, ctx->shared_key_len));

    ctx->keys_ready = 1;
    ret = 0;

cleanup:
    mbedtls_ecp_point_free(&T);
    mbedtls_ecp_point_free(&Z);
    mbedtls_ecp_point_free(&V);
    mbedtls_ecp_point_free(&mask);
    mbedtls_mpi_free(&one);
    mbedtls_mpi_free(&neg_w0);
    mbedtls_md_free(&md_ctx);
    mbedtls_platform_zeroize(k_main, sizeof(k_main));
    mbedtls_platform_zeroize(conf, sizeof(conf));
    mbedtls_platform_zeroize(w0_buf, sizeof(w0_buf));
    return ret;
}

/*
 * Compute and serialize this party's public share from the (already chosen)
 * ephemeral scalar ctx->xy.
 */
static int spake2p_make_own_share(mbedtls_spake2p_context *ctx,
                                  unsigned char *buf, size_t len, size_t *olen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point *own;
    const mbedtls_ecp_point *Ks;
    mbedtls_ecp_point eph, mask;
    mbedtls_mpi one;

    mbedtls_ecp_point_init(&eph);
    mbedtls_ecp_point_init(&mask);
    mbedtls_mpi_init(&one);
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));

    if (ctx->role == MBEDTLS_SPAKE2P_CLIENT) {
        own = &ctx->shareP;     /* shareP = x*P + w0*M */
        Ks = &ctx->M;
    } else {
        own = &ctx->shareV;     /* shareV = y*P + w0*N */
        Ks = &ctx->N;
    }

    /* Compute the two secret-scalar multiplications with the constant-time
     * mbedtls_ecp_mul() (mbedtls_ecp_muladd() is not constant-time and would
     * leak the ephemeral scalar and, critically, w0), then add the two points
     * with a public-scalar muladd. */
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &eph, &ctx->xy, &ctx->grp.G,
                                    f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &mask, &ctx->w0, Ks,
                                    f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&ctx->grp, own,
                                       &one, &eph, &one, &mask));
    MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(&ctx->grp, own,
                                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                   olen, buf, len));

    if (ctx->role == MBEDTLS_SPAKE2P_CLIENT) {
        ctx->have_shareP = 1;
    } else {
        ctx->have_shareV = 1;
    }

    if (ctx->have_shareP && ctx->have_shareV) {
#if defined(MBEDTLS_TEST_HOOKS)
        if (!ctx->tt_prefix_ready) {
            MBEDTLS_MPI_CHK(spake2p_update_tt_prefix(ctx));
        }
#endif
        if (!ctx->keys_ready) {
            MBEDTLS_MPI_CHK(spake2p_derive_keys(ctx, f_rng, p_rng));
        }
    }

cleanup:
    mbedtls_ecp_point_free(&eph);
    mbedtls_ecp_point_free(&mask);
    mbedtls_mpi_free(&one);
    return ret;
}

#if defined(MBEDTLS_TEST_HOOKS)
const unsigned char *mbedtls_spake2p_test_injected_ephemeral = NULL;
size_t mbedtls_spake2p_test_injected_ephemeral_len = 0;
#endif

int mbedtls_spake2p_write_key_share(mbedtls_spake2p_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_TEST_HOOKS)
    /* Single-use test seam: pin the ephemeral for a known-answer test, even
     * when the share is produced inside psa_pake_output(). */
    if (mbedtls_spake2p_test_injected_ephemeral != NULL) {
        const unsigned char *ephemeral = mbedtls_spake2p_test_injected_ephemeral;
        size_t ephemeral_len = mbedtls_spake2p_test_injected_ephemeral_len;
        mbedtls_spake2p_test_injected_ephemeral = NULL;
        mbedtls_spake2p_test_injected_ephemeral_len = 0;
        return mbedtls_spake2p_write_key_share_with_ephemeral(
            ctx, ephemeral, ephemeral_len, buf, len, olen, f_rng, p_rng);
    }
#endif

    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(&ctx->grp, &ctx->xy,
                                            f_rng, p_rng));
    MBEDTLS_MPI_CHK(spake2p_make_own_share(ctx, buf, len, olen, f_rng, p_rng));

cleanup:
    return ret;
}

#if defined(MBEDTLS_TEST_HOOKS)
int mbedtls_spake2p_write_key_share_with_ephemeral(
    mbedtls_spake2p_context *ctx,
    const unsigned char *ephemeral, size_t ephemeral_len,
    unsigned char *buf, size_t len, size_t *olen,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->xy, ephemeral, ephemeral_len));
    MBEDTLS_MPI_CHK(spake2p_make_own_share(ctx, buf, len, olen, f_rng, p_rng));

cleanup:
    return ret;
}
#endif /* MBEDTLS_TEST_HOOKS */

int mbedtls_spake2p_read_key_share(mbedtls_spake2p_context *ctx,
                                   const unsigned char *buf, size_t len,
                                   int (*f_rng)(void *, unsigned char *, size_t),
                                   void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point *peer;

    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* The peer's share is the other role's: a client reads shareV, a server
     * reads shareP. */
    peer = (ctx->role == MBEDTLS_SPAKE2P_CLIENT) ? &ctx->shareV : &ctx->shareP;

    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&ctx->grp, peer, buf, len));
    /* Group membership check (RFC 9383 Section 6). */
    MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(&ctx->grp, peer));

    if (ctx->role == MBEDTLS_SPAKE2P_CLIENT) {
        ctx->have_shareV = 1;
    } else {
        ctx->have_shareP = 1;
    }

    if (ctx->have_shareP && ctx->have_shareV) {
#if defined(MBEDTLS_TEST_HOOKS)
        if (!ctx->tt_prefix_ready) {
            MBEDTLS_MPI_CHK(spake2p_update_tt_prefix(ctx));
        }
#endif
        if (!ctx->keys_ready) {
            MBEDTLS_MPI_CHK(spake2p_derive_keys(ctx, f_rng, p_rng));
        }
    }

cleanup:
    return ret;
}

/*
 * MAC over a key share, used for the confirmation messages.
 * Only the HMAC profile is wired here (tag length = hash_len); the CMAC arm
 * lands in a later change.
 */
static int spake2p_mac(mbedtls_spake2p_context *ctx,
                       const unsigned char *key, size_t key_len,
                       const mbedtls_ecp_point *share,
                       unsigned char *out, size_t *out_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char msg[MBEDTLS_ECP_MAX_PT_LEN];
    size_t msg_len;

    MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(&ctx->grp, share,
                                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                   &msg_len, msg, sizeof(msg)));

    if (ctx->mac_type == MBEDTLS_SPAKE2P_MAC_HMAC) {
        const mbedtls_md_info_t *md_info =
            mbedtls_md_info_from_type(ctx->md_type);
        MBEDTLS_MPI_CHK(mbedtls_md_hmac(md_info, key, key_len,
                                        msg, msg_len, out));
    } else {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        goto cleanup;
    }

    *out_len = ctx->mac_len;
    ret = 0;

cleanup:
    mbedtls_platform_zeroize(msg, sizeof(msg));
    return ret;
}

int mbedtls_spake2p_write_confirm(mbedtls_spake2p_context *ctx,
                                  unsigned char *buf, size_t len, size_t *olen)
{
    const unsigned char *own_key;
    const mbedtls_ecp_point *peer_share;

    if (!ctx->keys_ready) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (len < ctx->mac_len) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    /* confirmP = MAC(K_confirmP, shareV); confirmV = MAC(K_confirmV, shareP).
     * Each party MACs the peer's share with its own confirmation key. */
    if (ctx->role == MBEDTLS_SPAKE2P_CLIENT) {
        own_key = ctx->K_confirmP;
        peer_share = &ctx->shareV;
    } else {
        own_key = ctx->K_confirmV;
        peer_share = &ctx->shareP;
    }

    return spake2p_mac(ctx, own_key, ctx->conf_key_len, peer_share, buf, olen);
}

#if defined(MBEDTLS_TEST_HOOKS)
int mbedtls_spake2p_test_get_transcript_prefix_hash(
    const mbedtls_spake2p_context *ctx,
    unsigned char *out, size_t out_size, size_t *out_len)
{
    if (!ctx->tt_prefix_ready) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (out_size < ctx->hash_len) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    memcpy(out, ctx->tt_prefix_hash, ctx->hash_len);
    *out_len = ctx->hash_len;
    return 0;
}
#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_SPAKE2P_C */
