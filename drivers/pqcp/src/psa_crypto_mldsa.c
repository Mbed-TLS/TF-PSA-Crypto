/* PSA driver for ML-DSA using mldsa-native */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

#include <psa/crypto.h>
#include "psa_crypto_mldsa.h"
#include "wrap_mldsa_native.h"
#include <mbedtls/platform_util.h>
#include <mbedtls/platform.h>

#if defined(TF_PSA_CRYPTO_PQCP_OWN_SHAKE)
#include "../mldsa-native/mldsa/src/fips202/fips202.h"

/* The mldsa-native header defines the SHAKE context types, declares
 * the functions that work on that type, and declares macros mld_xxx.
 *
 * We need to expose the context type in our public headers since it
 * appears in multipart operation structure, but we don't want to
 * expose the function declarations. (Maybe we will in the future, but
 * at the time of writing, it would be a hassle because fips202.h
 * references many headers of mldsa-native that we don't want to
 * install.)
 *
 * Therefore we define a public type which has (at least) the same size
 * and alignment requirements as context type from mldsa-native, but
 * is a distinct type according to the C language. We call the
 * mldsa-native SHAKE functions through a wrapper that puns the
 * pointer type. We pun via a union to a byte array to make the compiler
 * understand that this must be aliasing of memory.
 *
 * In this source file, we want to call the SHAKE256 operations through
 * the same names as when using the PSA callbacks for SHAKE, i.e. the
 * mld_xxx names. So we replace the mld_xxx macros by wrappers that
 * do the necessary pointer punning.
 */

#undef mld_shake256_init
#undef mld_shake256_absorb
#undef mld_shake256_finalize
#undef mld_shake256_squeeze
#undef mld_shake256_release

static inline void mld_shake256_init(tf_psa_crypto_mldsa_shake256_t *state)
{
    MLD_NAMESPACE(shake256_init)((mld_shake256ctx *) &state->bytes);
}

static inline void mld_shake256_absorb(tf_psa_crypto_mldsa_shake256_t *state,
                                       const uint8_t *in, size_t inlen)
{
    MLD_NAMESPACE(shake256_absorb)((mld_shake256ctx *) &state->bytes,
                                   in, inlen);
}

static inline void mld_shake256_finalize(tf_psa_crypto_mldsa_shake256_t *state)
{
    MLD_NAMESPACE(shake256_finalize)((mld_shake256ctx *) &state->bytes);
}

static inline void mld_shake256_squeeze(uint8_t *out, size_t outlen,
                                        tf_psa_crypto_mldsa_shake256_t *state)
{
    MLD_NAMESPACE(shake256_squeeze)(out, outlen,
                                    (mld_shake256ctx *) &state->bytes);
}

static inline void mld_shake256_release(tf_psa_crypto_mldsa_shake256_t *state)
{
    MLD_NAMESPACE(shake256_release)((mld_shake256ctx *) &state->bytes);
}

#else /* TF_PSA_CRYPTO_PQCP_OWN_SHAKE */
#include "fips202_psa.h"
#endif

/* The size of an ML-DSA seed in bytes.
 * The PSA API uses the seed as the private key.
 * (Some other ML-DSA interfaces use the "expanded secret", which is
 * derived from the seed, as the private key.)
 */
#define SEED_SIZE 32

/* The offset of the public key hash (tr) in an expanded private key. */
#define SK_TR_OFFSET 64
/* The offset of the public key hash (tr) in joined private key
 * (seed followed by thn expanded private key). */
#define JOINED_TR_OFFSET (SEED_SIZE + SK_TR_OFFSET)
/* The length of tr is MLDSA_TRBYTES. */

/* We want to expose size values in public headers, but we don't want to
 * expose the header that defines macros for these values in mldsa-native.
 * So we define our own macros in public headers, and check that the
 * values match.
 */
MBEDTLS_STATIC_ASSERT(MLDSA87_BYTES == PSA_MLDSA_SIGNATURE_SIZE(87),
                      "PSA and mldsa-native disagree on the ML-DSA-87 signature size");

/* For now, hard-coded value for MLDSA-87 */
#define TF_PSA_CRYPTO_PQCP_MLDSA_EXPANDED_SECRET_MAX_SIZE MLDSA87_SECRETKEYBYTES

static psa_status_t pqcp_to_psa_error(int ret, psa_status_t default_error)
{
    if (ret == 0) {
        return PSA_SUCCESS;
    } else if (ret == MLD_ERR_OUT_OF_MEMORY) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    } else if (ret == MLD_ERR_FAIL) {
        return default_error;
    } else {
        /* MLD_ERR_RNG_FAIL is intentionally not mapped: we don't install
         * mldsa-native's RNG callback (mu is computed on our side for
         * hedged ML-DSA), so it shouldn't be reachable. It would land
         * here and be reported as a generic driver failure.
         *
         * Not really hardware, but PSA_ERROR_HARDWARE_FAILURE is the
         * fallback error code for something unexpectedly going wrong
         * in a driver. */
        return PSA_ERROR_HARDWARE_FAILURE;
    }
}

psa_status_t tf_psa_crypto_mldsa_expand_private_key(
    size_t bits,
    const uint8_t *standard_key, size_t standard_key_length,
    uint8_t *custom_key, size_t custom_key_size, size_t *custom_key_length)
{
    *custom_key_length = 0;

    if (standard_key_length != SEED_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (bits != 87) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (custom_key_size < SEED_SIZE + MLDSA87_SECRETKEYBYTES) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    size_t output_length = SEED_SIZE + MLDSA87_SECRETKEYBYTES;

    psa_status_t status = tf_psa_crypto_pqcp_alloc_start();
    if (status != PSA_SUCCESS) {
        return status;
    }
    /* Beyond this point, we must go through the cleanup code. */
#if !defined(TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC)
    uint8_t tf_psa_crypto_pqcp_mldsa_public_key[TF_PSA_CRYPTO_PQCP_MLDSA_PUBLIC_KEY_MAX_SIZE];
#endif

    int ret = tf_psa_crypto_pqcp_mldsa87_keypair_internal(
        tf_psa_crypto_pqcp_mldsa_public_key,
        custom_key + SEED_SIZE,
        standard_key);

    status = tf_psa_crypto_pqcp_alloc_done();
    if (status == PSA_SUCCESS) {
        status = pqcp_to_psa_error(ret, PSA_ERROR_HARDWARE_FAILURE);
    }
    if (status == PSA_SUCCESS) {
        /* This function is guaranteed to support
         * custom_key == standard_key, but no other overlap. */
        if (custom_key != standard_key) {
            memcpy(custom_key, standard_key, SEED_SIZE);
        }
        *custom_key_length = output_length;
    } else {
        /* We haven't touched the first SEED_SIZE bytes of the output buffer,
         * and we don't want to change it in case it aliases the
         * input buffer. */
        mbedtls_platform_zeroize(custom_key + SEED_SIZE,
                                 output_length - SEED_SIZE);
    }
    return status;
}

static psa_status_t seed_to_public_key(
    size_t bits,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    if (key_buffer_size != SEED_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (bits != 87) {
        /* Other parameter sets are not supported yet. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t public_key_length = MLDSA87_PUBLICKEYBYTES;
    if (data_size < public_key_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_status_t status = tf_psa_crypto_pqcp_alloc_start();
    if (status != PSA_SUCCESS) {
        return status;
    }
    /* Beyond this point, we must go through the cleanup code. */
    uint8_t secret[TF_PSA_CRYPTO_PQCP_MLDSA_EXPANDED_SECRET_MAX_SIZE];

    int ret = tf_psa_crypto_pqcp_mldsa87_keypair_internal(data,
                                                          secret,
                                                          key_buffer);
    if (ret != 0) {
        goto cleanup;
    }
    ret = 0;
    *data_length = public_key_length;

cleanup:
    status = tf_psa_crypto_pqcp_alloc_done();
    mbedtls_platform_zeroize(secret, sizeof(secret));
    if (status != PSA_SUCCESS) {
        return status;
    } else {
        return pqcp_to_psa_error(ret, PSA_ERROR_HARDWARE_FAILURE);
    }
}

static psa_status_t export_public_from_expanded(
    size_t bits,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    if (bits != 87) {
        /* Other parameter sets are not supported yet. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_buffer_size != SEED_SIZE + MLDSA87_SECRETKEYBYTES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const uint8_t *sk = key_buffer + SEED_SIZE;

    size_t public_key_length = MLDSA87_PUBLICKEYBYTES;
    if (data_size < public_key_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_status_t status = tf_psa_crypto_pqcp_alloc_start();
    if (status != PSA_SUCCESS) {
        return status;
    }

    int ret = tf_psa_crypto_pqcp_mldsa87_pk_from_sk(data, sk);
    status = pqcp_to_psa_error(ret, PSA_ERROR_INVALID_ARGUMENT);
    if (status == PSA_SUCCESS) {
        *data_length = public_key_length;
    }

    psa_status_t alloc_status = tf_psa_crypto_pqcp_alloc_done();
    if (alloc_status != PSA_SUCCESS) {
        return alloc_status;
    } else {
        return status;
    }
}

psa_status_t tf_psa_crypto_mldsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    *data_length = 0;           /* Safe default */

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_buffer_size == SEED_SIZE) {
        return seed_to_public_key(psa_get_key_bits(attributes),
                                  key_buffer, key_buffer_size,
                                  data, data_size, data_length);
    } else {
        return export_public_from_expanded(psa_get_key_bits(attributes),
                                           key_buffer, key_buffer_size,
                                           data, data_size, data_length);
    }
}

psa_status_t tf_psa_crypto_mldsa_generate_key_custom(
    const psa_key_attributes_t *attributes,
    const psa_custom_key_parameters_t *custom,
    const uint8_t *custom_data, size_t custom_data_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    /* Safe default */
    *key_buffer_length = 0;

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (psa_get_key_bits(attributes) != 87) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if ((custom->flags & ~(PSA_CUSTOM_KEY_FLAG_EXPAND)) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    int expand = !!(custom->flags & PSA_CUSTOM_KEY_FLAG_EXPAND);
    if (custom_data_length != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void) custom_data;

    size_t prv_len = SEED_SIZE + (expand ? MLDSA87_SECRETKEYBYTES : 0);
    if (key_buffer_size < prv_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_status_t status = psa_generate_random(key_buffer, SEED_SIZE);
    /* Now private_key contains the new seed. We don't need to zeroize
     * the seed on failure since it's just been randomly generated. */
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (!expand) {
        goto exit;
    }

    status = tf_psa_crypto_pqcp_alloc_start();
    if (status != PSA_SUCCESS) {
        return status;
    }
    /* Beyond this point, we must go through the cleanup code. */

#if !defined(TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC)
    uint8_t tf_psa_crypto_pqcp_mldsa_public_key[TF_PSA_CRYPTO_PQCP_MLDSA_PUBLIC_KEY_MAX_SIZE];
#endif

    uint8_t *expanded_private_key = key_buffer + SEED_SIZE;
    int ret = tf_psa_crypto_pqcp_mldsa87_keypair_internal(
        tf_psa_crypto_pqcp_mldsa_public_key,
        expanded_private_key,
        key_buffer);

    status = tf_psa_crypto_pqcp_alloc_done();
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = pqcp_to_psa_error(ret, PSA_ERROR_HARDWARE_FAILURE);
    if (status != PSA_SUCCESS) {
        return status;
    }

exit:
    /* No memory wiping needed, because any sensitive content is a
     * freshly generated key that is either returned as an output on
     * success, or will not be used on error. */
    *key_buffer_length = prv_len;
    return PSA_SUCCESS;
}


static int sign_from_expanded(
    const uint8_t *secret,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t *signature_length)
{
    const uint8_t prefix[2] = { 0, 0 }; // pure ML-DSA with empty context
    const size_t prefix_length = sizeof(prefix);
    const uint8_t rnd[MLDSA_RNDBYTES] = { 0 };

    return tf_psa_crypto_pqcp_mldsa87_signature_internal(signature,
                                                         signature_length,
                                                         message, message_length,
                                                         prefix, prefix_length,
                                                         rnd,
                                                         secret,
                                                         0);
}

static psa_status_t sign_from_seed(
    const uint8_t seed[SEED_SIZE],
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t *signature_length)
{
    uint8_t secret[TF_PSA_CRYPTO_PQCP_MLDSA_EXPANDED_SECRET_MAX_SIZE];
    uint8_t public[TF_PSA_CRYPTO_PQCP_MLDSA_PUBLIC_KEY_MAX_SIZE];

    int ret = tf_psa_crypto_pqcp_mldsa87_keypair_internal(public,
                                                          secret,
                                                          seed);
    if (ret != 0) {
        goto cleanup;
    }

    ret = sign_from_expanded(secret,
                             message, message_length,
                             signature, signature_length);

cleanup:
    mbedtls_platform_zeroize(secret, sizeof(secret));
    return pqcp_to_psa_error(ret, PSA_ERROR_HARDWARE_FAILURE);
}

psa_status_t tf_psa_crypto_mldsa_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    *signature_length = 0;      /* Safe default */

    if (alg != PSA_ALG_DETERMINISTIC_ML_DSA) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (psa_get_key_bits(attributes) != 87) {
        /* Other parameter sets are not supported yet. */
        return PSA_ERROR_NOT_SUPPORTED;
    }
    size_t actual_signature_length = MLDSA87_BYTES;

    if (signature_size < actual_signature_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_status_t status = tf_psa_crypto_pqcp_alloc_start();
    if (status != PSA_SUCCESS) {
        return status;
    }
    /* Beyond this point, we must go through the cleanup code. */

    if (key_buffer_size == SEED_SIZE) {
        status = sign_from_seed(key_buffer,
                                message, message_length,
                                signature, signature_length);
    } else if (key_buffer_size == SEED_SIZE + MLDSA87_SECRETKEYBYTES) {
        status = pqcp_to_psa_error(sign_from_expanded(key_buffer + SEED_SIZE,
                                                      message, message_length,
                                                      signature, signature_length),
                                   PSA_ERROR_HARDWARE_FAILURE);
    } else {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t alloc_status = tf_psa_crypto_pqcp_alloc_done();
    if (alloc_status != PSA_SUCCESS) {
        return alloc_status;
    } else {
        return status;
    }
}

psa_status_t tf_psa_crypto_mldsa_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length)
{
    if (!PSA_ALG_IS_ML_DSA(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (psa_get_key_bits(attributes) != 87) {
        /* Other parameter sets are not supported yet. */
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (key_buffer_size != MLDSA87_PUBLICKEYBYTES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (signature_length != MLDSA87_BYTES) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    psa_status_t status = tf_psa_crypto_pqcp_alloc_start();
    if (status != PSA_SUCCESS) {
        return status;
    }

    int ret = tf_psa_crypto_pqcp_mldsa87_verify(signature, signature_length,
                                                message, message_length,
                                                NULL, 0,
                                                key_buffer);

    psa_status_t alloc_status = tf_psa_crypto_pqcp_alloc_done();
    if (alloc_status != PSA_SUCCESS) {
        return alloc_status;
    } else {
        return pqcp_to_psa_error(ret, PSA_ERROR_INVALID_SIGNATURE);
    }
}

static psa_status_t setup(
    tf_psa_crypto_mldsa_operation_t *operation,
    const psa_key_attributes_t *attributes,
    psa_algorithm_t alg)
{
    memset(operation, 0, sizeof(*operation));

    if (psa_get_key_bits(attributes) != 87) {
        /* Other parameter sets are not supported yet. */
        return PSA_ERROR_NOT_SUPPORTED;
    }
    operation->parameter_set = (uint8_t) psa_get_key_bits(attributes);

    switch (alg) {
        case PSA_ALG_DETERMINISTIC_ML_DSA:
            operation->hedged = 0;
            break;
        case PSA_ALG_ML_DSA:
            operation->hedged = 1;
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

static void hash_public_key(tf_psa_crypto_mldsa_shake256_t *shake_ctx,
                            const uint8_t *key_buffer, size_t key_buffer_size,
                            uint8_t tr[MLDSA_TRBYTES])
{
    mld_shake256_init(shake_ctx);
    mld_shake256_absorb(shake_ctx, key_buffer, key_buffer_size);
    mld_shake256_finalize(shake_ctx);
    mld_shake256_squeeze(tr, MLDSA_TRBYTES, shake_ctx);
    mld_shake256_release(shake_ctx);
}

static void start_pure(tf_psa_crypto_mldsa_shake256_t *shake_ctx,
                       const uint8_t tr[MLDSA_TRBYTES])
{
    mld_shake256_init(shake_ctx);
    mld_shake256_absorb(shake_ctx, tr, MLDSA_TRBYTES);

    /* Hash the domain separation prefix */
    uint8_t pre[2] = {
        0,                  /* pure ML-DSA (1 for Hash-ML-DSA) */
        0,                  /* context length */
    };
    mld_shake256_absorb(shake_ctx, pre, 2);
}

psa_status_t tf_psa_crypto_mldsa_sign_setup(
    tf_psa_crypto_mldsa_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status = setup(operation, attributes, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (operation->hedged) {
        /* not implemented yet */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (key_buffer_size == SEED_SIZE) {
        /* We'll expand the key below */
    } else if (key_buffer_size == SEED_SIZE + MLDSA87_SECRETKEYBYTES) {
        start_pure(&operation->shake, key_buffer + JOINED_TR_OFFSET);
        return PSA_SUCCESS;
    } else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = tf_psa_crypto_pqcp_alloc_start();
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* After this point, we may allocate memory, so we must go through
     * cleanup, including calling tf_psa_crypto_pqcp_alloc_done() to release
     * the buffer allocator's mutex. */

    /* The signature process needs the (hash of the) public key at the
     * beginning, and the (expanded) private key at the end (finish step).
     * The PSA representation of the key is just the seed, and the same
     * mldsa-native function calculates both the expanded private key and
     * the public key from the seed. We store the expanded private key
     * in the operation object so that the finish step doesn't need to
     * recalculate it. We put both the public key and the expanded private
     * key on the heap because they are very big (multiple kB) on the scale
     * of embedded devices.
     */
    size_t public_key_length = MLDSA87_PUBLICKEYBYTES;
    uint8_t *public_key = mbedtls_calloc(1, public_key_length);
    if (public_key == NULL) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto cleanup;
    }
    operation->key = mbedtls_calloc(1, MLDSA87_SECRETKEYBYTES);
    if (operation->key == NULL) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto cleanup;
    }
    operation->key_length = MLDSA87_SECRETKEYBYTES;

    int ret = tf_psa_crypto_pqcp_mldsa87_keypair_internal(public_key,
                                                          operation->key,
                                                          key_buffer);
    if (ret != 0) {
        status = pqcp_to_psa_error(ret, PSA_ERROR_HARDWARE_FAILURE);
        goto cleanup;
    }

    start_pure(&operation->shake, operation->key + SK_TR_OFFSET);

cleanup:
    mbedtls_free(public_key);
    psa_status_t alloc_status = tf_psa_crypto_pqcp_alloc_done();
    if (status != PSA_SUCCESS || alloc_status != PSA_SUCCESS) {
        mbedtls_zeroize_and_free(operation->key, operation->key_length);
        mld_shake256_release(&operation->shake);
        mbedtls_platform_zeroize(operation, sizeof(*operation));
    }
    if (alloc_status != PSA_SUCCESS) {
        return alloc_status;
    } else {
        return status;
    }
}

psa_status_t tf_psa_crypto_mldsa_verify_setup(
    tf_psa_crypto_mldsa_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status = setup(operation, attributes, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (key_buffer_size != MLDSA87_PUBLICKEYBYTES) {
        /* Technically setup() doesn't care about the public key size, only
         * finish() will care. But it's easier for users to debug a wrong-key
         * problem if we complain as soon as the problem is noticeable. */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t tr[MLDSA_TRBYTES];
    hash_public_key(&operation->shake, key_buffer, key_buffer_size, tr);
    start_pure(&operation->shake, tr);

    return PSA_SUCCESS;
}

psa_status_t tf_psa_crypto_mldsa_update(
    tf_psa_crypto_mldsa_operation_t *operation,
    const uint8_t *input, size_t input_length)
{
    mld_shake256_absorb(&operation->shake, input, input_length);
    return PSA_SUCCESS;
}

psa_status_t tf_psa_crypto_mldsa_sign_finish(
    tf_psa_crypto_mldsa_operation_t *operation,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    *signature_length = 0;

    if (operation->parameter_set != 87) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (signature_size < MLDSA87_BYTES) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    const uint8_t *private_key = NULL;
    if (key_buffer_size == SEED_SIZE) {
        /* Rely on setup() having stored the expanded private key in the
         * operation structure. This is a performance/memory trade-off:
         * we could instead re-expand the private key from the seed
         * in \p key_buffer here. */
        if (operation->key_length != MLDSA87_SECRETKEYBYTES) {
            return PSA_ERROR_BAD_STATE;
        }
        private_key = operation->key;
    } else if (key_buffer_size == SEED_SIZE + MLDSA87_SECRETKEYBYTES) {
        private_key = key_buffer + SEED_SIZE;
    } else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = tf_psa_crypto_pqcp_alloc_start();
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* From this point on, we must not return without calling
     * tf_psa_crypto_pqcp_alloc_done() to release the buffer allocator's
     * mutex. */

    uint8_t mu[MLDSA_CRHBYTES];
    mld_shake256_finalize(&operation->shake);
    mld_shake256_squeeze(mu, sizeof(mu), &operation->shake);
    mld_shake256_release(&operation->shake);

    uint8_t rnd[MLDSA_RNDBYTES];
    memset(rnd, 0, sizeof(rnd));

    int ret = tf_psa_crypto_pqcp_mldsa87_signature_internal(
        signature, signature_length,
        mu, sizeof(mu),
        NULL, 0, rnd,
        private_key, 1);

    status = tf_psa_crypto_pqcp_alloc_done();
    psa_status_t abort_status = tf_psa_crypto_mldsa_abort(operation);

    if (status != PSA_SUCCESS) {
        return status;
    }
    if (abort_status != PSA_SUCCESS) {
        return abort_status;
    }
    return pqcp_to_psa_error(ret, PSA_ERROR_HARDWARE_FAILURE);
}

psa_status_t tf_psa_crypto_mldsa_verify_finish(
    tf_psa_crypto_mldsa_operation_t *operation,
    const uint8_t *key_buffer, size_t key_buffer_size,
    const uint8_t *signature, size_t signature_length)
{
    if (operation->parameter_set != 87) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (key_buffer_size != MLDSA87_PUBLICKEYBYTES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (signature_length != MLDSA87_BYTES) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    psa_status_t status = tf_psa_crypto_pqcp_alloc_start();
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* From this point on, we must not return without calling
     * tf_psa_crypto_pqcp_alloc_done() to release the buffer allocator's
     * mutex. */

    uint8_t mu[MLDSA_CRHBYTES];
    mld_shake256_finalize(&operation->shake);
    mld_shake256_squeeze(mu, sizeof(mu), &operation->shake);
    mld_shake256_release(&operation->shake);

    int ret = tf_psa_crypto_pqcp_mldsa87_verify_internal(
        signature, signature_length,
        mu, sizeof(mu),
        NULL, 0,
        key_buffer, 1);

    status = tf_psa_crypto_pqcp_alloc_done();
    psa_status_t abort_status = tf_psa_crypto_mldsa_abort(operation);

    if (status != PSA_SUCCESS) {
        return status;
    }
    if (abort_status != PSA_SUCCESS) {
        return abort_status;
    }
    return pqcp_to_psa_error(ret, PSA_ERROR_INVALID_SIGNATURE);
}

psa_status_t tf_psa_crypto_mldsa_abort(
    tf_psa_crypto_mldsa_operation_t *operation)
{
    /* If operation->parameter_set is 0, we may have an operation object
     * that's only partially initialized. This shouldn't happen, since
     * the PSA crypto driver specification says that the core initialized
     * driver contexts to all-bits-zero. But avoid calling free() in that
     * case as an extra bit of robustness. Of course, if the operation
     * object is completely uninitialized, there's no way to detect that.
     */
    if (operation->parameter_set != 0) {
        mbedtls_zeroize_and_free(operation->key, operation->key_length);
        mld_shake256_release(&operation->shake);
    }
    mbedtls_platform_zeroize(operation, sizeof(*operation));
    return PSA_SUCCESS;
}

#endif /* MBEDTLS_PSA_CRYPTO_C && TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */
