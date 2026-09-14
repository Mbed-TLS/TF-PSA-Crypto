/*
 *  PSA SPAKE2+ layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_core.h"
#include "psa_crypto_spake2p.h"
#include "psa_crypto_random_impl.h"
#include "psa_util_internal.h"

#include <string.h>
#include <mbedtls/private/ecp.h>

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_SPAKE2P_KEY_PAIR_BASIC) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_SPAKE2P_PUBLIC_KEY)

typedef struct {
    psa_ecc_family_t family;
    size_t w0_len;
    size_t L_len;
    mbedtls_ecp_group_id grp_id;
    size_t bits;
} psa_spake2p_curve_info_t;

static const psa_spake2p_curve_info_t spake2p_supported_curves[] =
{
#if defined(PSA_WANT_ECC_SECP_R1_256)
    { PSA_ECC_FAMILY_SECP_R1, 32, 65, MBEDTLS_ECP_DP_SECP256R1, 256 },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_384)
    { PSA_ECC_FAMILY_SECP_R1, 48, 97, MBEDTLS_ECP_DP_SECP384R1, 384 },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_521)
    { PSA_ECC_FAMILY_SECP_R1, 66, 133, MBEDTLS_ECP_DP_SECP521R1, 521 },
#endif
    /* Sentinel so that the array is never empty. Family 0 is not a valid
     * PSA ECC family, so this entry never matches a lookup. */
    { 0, 0, 0, MBEDTLS_ECP_DP_NONE, 0 },
};

/* Look up the curve whose public-key encoding (w0 || L) for this family is
 * data_length bytes long. The table is the single source of truth. */
static const psa_spake2p_curve_info_t *psa_spake2p_get_curve_from_data_length(
    size_t data_length,
    psa_ecc_family_t family)
{
    for (size_t i = 0; i < ARRAY_LENGTH(spake2p_supported_curves); i++) {
        const psa_spake2p_curve_info_t *info = &spake2p_supported_curves[i];
        if (info->family == family &&
            info->w0_len + info->L_len == data_length) {
            return info;
        }
    }
    return NULL;
}

/* Determine the status for a scalar length that does not match any curve
 * enabled in the build: a length that belongs to a curve that this
 * implementation knows about, but which is not enabled, is reported as
 * NOT_SUPPORTED; any other length is a malformed encoding, hence
 * INVALID_ARGUMENT. */
static psa_status_t psa_spake2p_unknown_scalar_len_status(
    psa_ecc_family_t family,
    size_t scalar_len)
{
    if (family == PSA_ECC_FAMILY_SECP_R1 &&
        (scalar_len == 32 || scalar_len == 48 || scalar_len == 66)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_ERROR_INVALID_ARGUMENT;
}

/* Look up the SECP_R1 curve whose key-pair scalars (w0/w1) are scalar_len
 * bytes long, using the same table as the public-key lookup so the curve set
 * is defined in one place. */
static const psa_spake2p_curve_info_t *psa_spake2p_get_curve_from_scalar_len(
    size_t scalar_len)
{
    for (size_t i = 0; i < ARRAY_LENGTH(spake2p_supported_curves); i++) {
        const psa_spake2p_curve_info_t *info = &spake2p_supported_curves[i];
        if (info->family == PSA_ECC_FAMILY_SECP_R1 && info->w0_len == scalar_len) {
            return info;
        }
    }
    return NULL;
}

psa_status_t mbedtls_psa_spake2p_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type = psa_get_key_type(attributes);

    if (!PSA_KEY_TYPE_IS_SPAKE2P(key_type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    psa_ecc_family_t family = PSA_KEY_TYPE_SPAKE2P_GET_FAMILY(key_type);
    size_t key_bits = 0;

    /* SPAKE2+ over Edwards curves (RFC 9383) is not implemented. */
    if (family == PSA_ECC_FAMILY_TWISTED_EDWARDS) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Validate the curve family and the data length before the policy
     * checks, so that an unsupported curve is reported as NOT_SUPPORTED
     * independently of the key's algorithm policy. */
    const psa_spake2p_curve_info_t *spake2_curve_info = NULL;
    if (PSA_KEY_TYPE_IS_SPAKE2P_PUBLIC_KEY(key_type)) {
        /* Verifier registration record: w0 || L, with L a public point. */
        spake2_curve_info =
            psa_spake2p_get_curve_from_data_length(data_length, family);
        if (spake2_curve_info == NULL) {
            /* A public key is w0 || L, i.e. 3 * scalar_len + 1 bytes. */
            if (data_length % 3 != 1) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            return psa_spake2p_unknown_scalar_len_status(family, data_length / 3);
        }
        key_bits = spake2_curve_info->bits;
    } else {
        /* Prover key pair: w0 || w1, two equal-length scalars. */
        if (family != PSA_ECC_FAMILY_SECP_R1 || (data_length % 2) != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        spake2_curve_info =
            psa_spake2p_get_curve_from_scalar_len(data_length / 2);
        if (spake2_curve_info == NULL) {
            return psa_spake2p_unknown_scalar_len_status(family, data_length / 2);
        }
        key_bits = spake2_curve_info->bits;
    }

    if (key_buffer_size < data_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_algorithm_t alg = psa_get_key_algorithm(attributes);

    /* A SPAKE2+ key's permitted-algorithm policy must be a SPAKE2+ algorithm,
     * or PSA_ALG_NONE for a key with no intended algorithm (e.g. a key kept
     * only in storage). An explicit incompatible policy is rejected. */
    if (alg != PSA_ALG_NONE && !PSA_ALG_IS_SPAKE2P(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_KEY_TYPE_IS_SPAKE2P_PUBLIC_KEY(key_type)) {
        mbedtls_ecp_group grp;
        mbedtls_ecp_point pt;

        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&pt);

        status = mbedtls_to_psa_error(
            mbedtls_ecp_group_load(&grp, spake2_curve_info->grp_id));
        if (status != PSA_SUCCESS) {
            goto exit;
        }

        /* w0 is a scalar in the same range as an EC private key: reject 0
         * and values >= the group order n (like the key-pair path). */
        {
            mbedtls_mpi w0;
            mbedtls_mpi_init(&w0);
            status = mbedtls_to_psa_error(
                mbedtls_mpi_read_binary(&w0, data, spake2_curve_info->w0_len));
            if (status == PSA_SUCCESS &&
                (mbedtls_mpi_cmp_int(&w0, 0) == 0 ||
                 mbedtls_mpi_cmp_mpi(&w0, &grp.N) >= 0)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            mbedtls_mpi_free(&w0);
            if (status != PSA_SUCCESS) {
                goto exit;
            }
        }

        status = mbedtls_to_psa_error(
            mbedtls_ecp_point_read_binary(&grp, &pt,
                                          data + spake2_curve_info->w0_len,
                                          spake2_curve_info->L_len));
        if (status != PSA_SUCCESS) {
            goto exit;
        }

        /* Check that the point is on the curve. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_check_pubkey(&grp, &pt));
exit:
        mbedtls_ecp_point_free(&pt);
        mbedtls_ecp_group_free(&grp);
        if (status != PSA_SUCCESS) {
            *key_buffer_length = 0;
            *bits = 0;
            return status;
        }
    } else {
        /* w0 and w1 are scalars in the same range as an elliptic curve
         * private key from the group: reject 0 and values >= the group
         * order n, like ECC private-key import does. */
        size_t scalar_len = data_length / 2;
        mbedtls_ecp_group grp;
        mbedtls_mpi w;

        mbedtls_ecp_group_init(&grp);
        mbedtls_mpi_init(&w);

        status = mbedtls_to_psa_error(
            mbedtls_ecp_group_load(&grp, spake2_curve_info->grp_id));
        for (size_t i = 0; i < 2 && status == PSA_SUCCESS; i++) {
            status = mbedtls_to_psa_error(
                mbedtls_mpi_read_binary(&w, data + i * scalar_len,
                                        scalar_len));
            if (status == PSA_SUCCESS &&
                (mbedtls_mpi_cmp_int(&w, 0) == 0 ||
                 mbedtls_mpi_cmp_mpi(&w, &grp.N) >= 0)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
        }

        mbedtls_mpi_free(&w);
        mbedtls_ecp_group_free(&grp);
        if (status != PSA_SUCCESS) {
            *key_buffer_length = 0;
            *bits = 0;
            return status;
        }
    }

    memcpy(key_buffer, data, data_length);
    *key_buffer_length = data_length;
    /* The key size is the curve size (like ECC keys), not the length of the
     * serialized w0||w1 / w0||L material. */
    *bits = key_bits;

    return PSA_SUCCESS;
}

psa_status_t mbedtls_psa_spake2p_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    mbedtls_ecp_group grp;
    mbedtls_ecp_point L;
    mbedtls_mpi w1;
    size_t point_length = 0;

    /* The key material is w0 || w1, two equal-length SECP_R1 scalars, as
     * validated at import. */
    if (!PSA_KEY_TYPE_IS_SPAKE2P_KEY_PAIR(key_type) ||
        PSA_KEY_TYPE_SPAKE2P_GET_FAMILY(key_type) != PSA_ECC_FAMILY_SECP_R1 ||
        (key_buffer_size % 2) != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t scalar_len = key_buffer_size / 2;
    const psa_spake2p_curve_info_t *spake2_curve_info =
        psa_spake2p_get_curve_from_scalar_len(scalar_len);
    if (spake2_curve_info == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (data_size < spake2_curve_info->w0_len + spake2_curve_info->L_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&L);
    mbedtls_mpi_init(&w1);

    status = mbedtls_to_psa_error(
        mbedtls_ecp_group_load(&grp, spake2_curve_info->grp_id));
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* The public key (verifier registration record) is w0 || L with
     * L = w1 * P, P the group generator (RFC 9383), L uncompressed. */
    status = mbedtls_to_psa_error(
        mbedtls_mpi_read_binary(&w1, key_buffer + scalar_len, scalar_len));
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = mbedtls_to_psa_error(
        mbedtls_ecp_mul(&grp, &L, &w1, &grp.G,
                        mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE));
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    memcpy(data, key_buffer, scalar_len);
    status = mbedtls_to_psa_error(
        mbedtls_ecp_point_write_binary(&grp, &L, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &point_length,
                                       data + scalar_len,
                                       data_size - scalar_len));
    if (status != PSA_SUCCESS) {
        memset(data, 0, data_size);
        goto exit;
    }

    *data_length = scalar_len + point_length;

exit:
    /* w1 is secret key material: mbedtls_mpi_free() zeroizes it. */
    mbedtls_mpi_free(&w1);
    mbedtls_ecp_point_free(&L);
    mbedtls_ecp_group_free(&grp);
    return status;
}

#endif /* defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_SPAKE2P_KEY_PAIR_BASIC) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_SPAKE2P_PUBLIC_KEY) */

#endif /* MBEDTLS_PSA_CRYPTO_C */
