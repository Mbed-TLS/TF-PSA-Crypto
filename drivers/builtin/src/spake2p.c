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
 * This slice covers setup and the generation of this party's public key share
 * (write_key_share). The remaining protocol steps land in subsequent changes.
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

#endif /* MBEDTLS_SPAKE2P_C */
