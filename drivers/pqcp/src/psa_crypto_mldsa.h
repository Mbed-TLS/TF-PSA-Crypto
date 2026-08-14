/* PSA driver for ML-DSA using mldsa-native */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PSA_CRYPTO_MLDSA_H
#define TF_PSA_CRYPTO_PSA_CRYPTO_MLDSA_H

#include <psa/crypto.h>
#include <tf-psa-crypto/private/mldsa.h>

#if defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED)

/** Expand a seed into a joined format: the concatenation of the 32-byte seed
 * and the standard expanded private key format.
 *
 * \param bits                  The ML-DSA parameter set (44, 56 or 87).
 * \param[in] standard_key      The seed to expand.
 * \param standard_key_length   The length of \p seed, in bytes. This must be
 *                              #TF_PSA_CRYPTO_PQCP_MLDSA_SEED_SIZE.
 * \param[out] custom_key       On success, the key in joined format.
 *                              The pointers \p custom_key and \p standard_key
 *                              may be equal, but no other overlap between
 *                              the buffers is supported.
 * \param custom_key_size       The size of the \p custom_key buffer in bytes.
 *                              This must be at least
 *                              #TF_PSA_CRYPTO_PQCP_MLDSA_JOINED_PRIVATE_KEY_SIZE(\p bits).
 * \param[out] custom_key_length The length of the output, in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The value of \p bits is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p standard_key_length is invalid.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         \p custom_key_size is too small.
 */
psa_status_t tf_psa_crypto_mldsa_expand_private_key(
    size_t bits,
    const uint8_t *standard_key, size_t standard_key_length,
    uint8_t *custom_key, size_t custom_key_size, size_t *custom_key_length);

/** Export the public key of an ML-DSA key pair.
 *
 * \param[in] attributes        The key attributes.
 * \param[in] key_buffer        The key material. This may be either:
 *                              * a key pair in the standard representation,
 *                                i.e. just the 32-byte seed; or
 *                              * the concatenation of the 32-byte seed and the
 *                                standard expanded private key format.
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 *                              This must be at least
 *                              #TF_PSA_CRYPTO_PQCP_MLDSA_PUBLIC_KEY_SIZE(\c bits)
 *                              where \c bits is the ML-DSA parameter set
 *                              equal to psa_get_key_bits(\p attributes).
 * \param[out] data             On success, the exported key.
 * \param data_size             The size of \p data, in bytes.
 * \param[out] data_length      On success, the length of the data written
 *                              to \p data.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or size registered in \p attributes is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material is invalid.
 *         Note that this function is not guaranteed to detect all cases
 *         of invalid or inconsistent keys.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         \p data_size is too small.
 */
psa_status_t tf_psa_crypto_mldsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length);

/** Sign a message using pure-ML-DSA (without pre-hashing).
 *
 * \param[in] attributes        The key attributes.
 * \param[in] key_buffer        The key material. This may be either:
 *                              * a key pair in the standard representation,
 *                                i.e. just the 32-byte seed; or
 *                              * the concatenation of the 32-byte seed and the
 *                                standard expanded private key format.
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 * \param alg                   The algorithm:
 *                              #PSA_ALG_ML_DSA (not implemented yet) or
 *                              #PSA_ALG_DETERMINISTIC_ML_DSA.
 * \param[in] message           The message to sign.
 * \param message_length        The length of \p message, in bytes.
 * \param[out] signature        On success, the exported key.
 * \param signature_size        The size of \p signature, in bytes.
 * \param[out] signature_length On success, the length of the data written
 *                              to \p signature.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or size registered in \p attributes is not supported,
 *         or the algorithm is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material is invalid, or the key type is invalid for the
 *         given algorithm.
 *         Note that this function is not guaranteed to detect all cases
 *         of invalid or inconsistent keys.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         \p signature_size is too small.
 */
psa_status_t tf_psa_crypto_mldsa_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length);

/** Verify a message using pure-ML-DSA (without pre-hashing).
 *
 * \param[in] attributes        The key attributes.
 * \param[in] key_buffer        The key material. This must be a public key
 *                              in the standard representation.
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 * \param alg                   The algorithm:
 *                              #PSA_ALG_ML_DSA (not implemented yet) or
 *                              #PSA_ALG_DETERMINISTIC_ML_DSA.
 * \param[in] message           The message to verify.
 * \param message_length        The length of \p message, in bytes.
 * \param[in] signature         The signature to verify.
 * \param signature_length      The length of \p signature, in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or size registered in \p attributes is not supported,
 *         or the algorithm is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material is invalid.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The signature is not valid for this message.
 */
psa_status_t tf_psa_crypto_mldsa_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length);

/** Set up a pure-ML-DSA signature operation.
 *
 * \param operation             An operation structure. It must not
 *                              be in use.
 * \param[in] attributes        The key attributes.
 * \param[in] key_buffer        The key material. This may be either:
 *                              * a key pair in the standard representation,
 *                                i.e. just the 32-byte seed; or
 *                              * the concatenation of the 32-byte seed and the
 *                                standard expanded private key format.
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 * \param alg                   The algorithm:
 *                              #PSA_ALG_ML_DSA (not implemented yet) or
 *                              #PSA_ALG_DETERMINISTIC_ML_DSA.
 *
 * \retval 0
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or size registered in \p attributes is not supported,
 *         or the algorithm is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material is invalid, or the key type is invalid for the
 *         given algorithm.
 *         Note that this function is not guaranteed to detect all cases
 *         of invalid or inconsistent keys.
 */
psa_status_t tf_psa_crypto_mldsa_sign_setup(
    tf_psa_crypto_mldsa_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg);

/** Set up a pure-ML-DSA verification operation.
 *
 * \param operation             An operation structure. It must not
 *                              be in use.
 * \param[in] attributes        The key attributes.
 * \param[in] key_buffer        The key material. This must be a public key
 *                              in the standard representation.
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 * \param alg                   The algorithm:
 *                              #PSA_ALG_ML_DSA or
 *                              #PSA_ALG_DETERMINISTIC_ML_DSA.
 *
 * \retval 0
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or size registered in \p attributes is not supported,
 *         or the algorithm is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material is invalid, or the key type is invalid for the
 *         given algorithm.
 */
psa_status_t tf_psa_crypto_mldsa_verify_setup(
    tf_psa_crypto_mldsa_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg);

/** Add a message chunk to a pure-ML-DSA signature or verification operation.
 *
 * \param operation             An operation structure. It must have
 *                              been set up and not finished
 *                              or aborted yet.
 * \param[in] input             The message chunk.
 * \param input_length          The length of \p input, in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The state of \p operation has been detected as inconsistent
 *         with the request. Note that this function does not guarantee
 *         that an inconsistent state is detected.
 */
psa_status_t tf_psa_crypto_mldsa_update(
    tf_psa_crypto_mldsa_operation_t *operation,
    const uint8_t *input, size_t input_length);

/** Finish a pure-ML-DSA signature operation.
 *
 * \param operation             An operation structure. It must have
 *                              been set up for signing and not finished
 *                              or aborted yet.
 * \param[in] key_buffer        The key material. This must be the same key
 *                              (in the same representation) that was
 *                              passed to tf_psa_crypto_mldsa_sign_setup().
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 * \param[out] signature        On success, the exported key.
 * \param signature_size        The size of \p signature, in bytes.
 * \param[out] signature_length On success, the length of the data written
 *                              to \p signature.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The state of \p operation has been detected as inconsistent
 *         with the request. Note that this function does not guarantee
 *         that an inconsistent state is detected.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material has been detected to be invalid or inconsistent
 *         with the key passed during setup. Note that this function does not
 *         guarantee that an inconsistent key is detected.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         \p signature_size is too small.
 */
psa_status_t tf_psa_crypto_mldsa_sign_finish(
    tf_psa_crypto_mldsa_operation_t *operation,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *signature, size_t signature_size, size_t *signature_length);

/** Finish a pure-ML-DSA verification operation.
 *
 * \param operation             An operation structure. It must have
 *                              been set up for verifying and not finished
 *                              or aborted yet.
 * \param[in] key_buffer        The key material. This must be the same
 *                              public key passed to
 *                              tf_psa_crypto_mldsa_verify_setup().
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 * \param[in] signature         The signature to verify.
 * \param signature_length      The length of \p signature, in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The state of \p operation has been detected as inconsistent
 *         with the request. Note that this function does not guarantee
 *         that an inconsistent state is detected.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material has been detected to be invalid or inconsistent
 *         with the key passed during setup. Note that this function does not
 *         guarantee that an inconsistent key is detected.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The signature is not valid for this message.
 */
psa_status_t tf_psa_crypto_mldsa_verify_finish(
    tf_psa_crypto_mldsa_operation_t *operation,
    const uint8_t *key_buffer, size_t key_buffer_size,
    const uint8_t *signature, size_t signature_length);

/** Abort a pure-ML-DSA signature or verification operation.
 *
 * \param operation             An operation structure. It must have
 *                              been initialized.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 */
psa_status_t tf_psa_crypto_mldsa_abort(
    tf_psa_crypto_mldsa_operation_t *operation);

#endif /* TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED */

#endif /* "psa_crypto_mldsa.h" */
