#ifndef MBEDTLS_PSA_CRYPTO_ASYNC_DRIVER_H
#define MBEDTLS_PSA_CRYPTO_ASYNC_DRIVER_H

#include "mbedtls/psa_crypto_async_contexts.h"
#include "mbedtls/psa_crypto_async_curves.h"
#include "mbedtls/psa_crypto_async_provider.h"

#include <stdbool.h>
#include <string.h>

static inline bool mbedtls_psa_async_crypto_less_than(const uint8_t* left, const uint8_t* right,
                                                      size_t size) {
  for (size_t index = 0u; index < size; ++index) {
    if (left[index] != right[index]) {
      return left[index] < right[index];
    }
  }
  return false;
}

static inline bool
mbedtls_psa_async_crypto_valid_nonce(const uint8_t* nonce,
                                     const mbedtls_psa_async_crypto_prime_curve_t* curve) {
  bool nonzero = false;
  for (size_t index = 0u; index < curve->order.length; ++index) {
    nonzero = nonzero || nonce[index] != 0u;
  }
  return nonzero &&
         mbedtls_psa_async_crypto_less_than(nonce, curve->order.data, curve->order.length);
}

static inline void mbedtls_psa_async_crypto_zeroize(uint8_t* data, size_t size) {
  volatile uint8_t* output = data;
  while (size-- > 0u) {
    *output++ = 0u;
  }
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_operation_start(
    mbedtls_psa_async_crypto_driver_operation_t* operation,
    mbedtls_psa_async_crypto_provider_t* provider,
    const mbedtls_psa_async_crypto_request_t* request) {
  if (operation == NULL || provider == NULL || request == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  return mbedtls_psa_async_crypto_start(provider, &operation->provider_operation, request);
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_operation_complete(
    mbedtls_psa_async_crypto_driver_operation_t* operation,
    mbedtls_psa_async_crypto_provider_t* provider) {
  if (operation == NULL || provider == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  return mbedtls_psa_async_crypto_complete(provider, &operation->provider_operation);
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_operation_abort(
    mbedtls_psa_async_crypto_driver_operation_t* operation,
    mbedtls_psa_async_crypto_provider_t* provider) {
  if (operation == NULL || provider == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  return mbedtls_psa_async_crypto_abort(provider, &operation->provider_operation);
}

static inline uint32_t mbedtls_psa_async_crypto_transparent_operation_get_num_ops(
    const mbedtls_psa_async_crypto_driver_operation_t* operation,
    const mbedtls_psa_async_crypto_provider_t* provider) {
  if (operation == NULL || provider == NULL) {
    return 0u;
  }
  return mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation);
}

static inline void mbedtls_psa_async_crypto_reset_random_operation(
    mbedtls_psa_async_crypto_random_operation_t* operation) {
  if (operation != NULL) {
    memset(operation, 0, sizeof(*operation));
  }
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_generate_random_start(
    mbedtls_psa_async_crypto_random_operation_t* operation, uint8_t* output, size_t output_size) {
  if (operation == NULL || output == NULL || output_size == 0u || operation->provider != NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  mbedtls_psa_async_crypto_provider_t* provider = mbedtls_psa_async_crypto_bound_provider();
  if (provider == NULL) {
#if MBEDTLS_PSA_ASYNC_CRYPTO_SOFTWARE_ENABLED
    return PSA_ERROR_NOT_SUPPORTED;
#else
    return PSA_ERROR_BAD_STATE;
#endif
  }
  operation->provider = provider;
  memset(&operation->request, 0, sizeof(operation->request));
  operation->request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RANDOM;
  operation->request.output = (mbedtls_psa_async_crypto_buffer_t){output, output_size};
  const psa_status_t status = mbedtls_psa_async_crypto_start(
      operation->provider, &operation->provider_operation, &operation->request);
  if (status != PSA_SUCCESS) {
    mbedtls_psa_async_crypto_reset_random_operation(operation);
  }
  return status;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_generate_random_complete(
    mbedtls_psa_async_crypto_random_operation_t* operation) {
  if (operation == NULL || operation->provider == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  const psa_status_t status =
      mbedtls_psa_async_crypto_complete(operation->provider, &operation->provider_operation);
  if (status != PSA_OPERATION_INCOMPLETE) {
    operation->num_ops += mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation);
    memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
    memset(&operation->request, 0, sizeof(operation->request));
  }
  return status;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_generate_random_abort(
    mbedtls_psa_async_crypto_random_operation_t* operation) {
  if (operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->provider != NULL &&
      operation->provider_operation.state != MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE) {
    (void)mbedtls_psa_async_crypto_abort(operation->provider, &operation->provider_operation);
  }
  mbedtls_psa_async_crypto_reset_random_operation(operation);
  return PSA_SUCCESS;
}

static inline uint32_t mbedtls_psa_async_crypto_transparent_generate_random_get_num_ops(
    const mbedtls_psa_async_crypto_random_operation_t* operation) {
  if (operation == NULL) {
    return 0u;
  }
  const uint32_t current =
      operation->provider != NULL
          ? mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation)
          : 0u;
  return operation->num_ops + current;
}

static inline psa_status_t mbedtls_psa_async_crypto_aead_start(
    mbedtls_psa_async_crypto_aead_operation_t* operation, const psa_key_attributes_t* attributes,
    const uint8_t* key_buffer, size_t key_buffer_size, psa_algorithm_t algorithm,
    mbedtls_psa_async_crypto_direction_t direction, const uint8_t* nonce, size_t nonce_length,
    const uint8_t* additional_data, size_t additional_data_length, const uint8_t* input,
    size_t input_length, uint8_t* output, size_t output_size) {
  if (operation == NULL || attributes == NULL || key_buffer == NULL || nonce == NULL ||
      output == NULL || operation->provider != NULL ||
      (additional_data == NULL && additional_data_length != 0u) ||
      (input == NULL && input_length != 0u)) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  const psa_key_type_t key_type = psa_get_key_type(attributes);
  const size_t key_bits = psa_get_key_bits(attributes);
  const size_t tag_length = PSA_AEAD_TAG_LENGTH(key_type, key_bits, algorithm);
  if (key_type != PSA_KEY_TYPE_AES || key_buffer_size * 8u != key_bits ||
      (key_bits != 128u && key_bits != 192u && key_bits != 256u) ||
      (algorithm != PSA_ALG_GCM && algorithm != PSA_ALG_CCM) || tag_length != 16u) {
    return PSA_ERROR_NOT_SUPPORTED;
  }

  size_t payload_length = input_length;
  if (direction == MBEDTLS_PSA_ASYNC_CRYPTO_DECRYPT) {
    if (input_length < tag_length) {
      return PSA_ERROR_INVALID_ARGUMENT;
    }
    payload_length -= tag_length;
  }
  const size_t required_output =
      direction == MBEDTLS_PSA_ASYNC_CRYPTO_ENCRYPT ? payload_length + tag_length : payload_length;
  if (output_size < required_output) {
    return PSA_ERROR_BUFFER_TOO_SMALL;
  }

  mbedtls_psa_async_crypto_provider_t* provider = mbedtls_psa_async_crypto_bound_provider();
  if (provider == NULL) {
#if MBEDTLS_PSA_ASYNC_CRYPTO_SOFTWARE_ENABLED
    return PSA_ERROR_NOT_SUPPORTED;
#else
    return PSA_ERROR_BAD_STATE;
#endif
  }
  operation->provider = provider;
  operation->output_length = required_output;
  memset(&operation->request, 0, sizeof(operation->request));
  operation->request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AEAD;
  operation->request.key_type = key_type;
  operation->request.key_bits = key_bits;
  operation->request.alg = algorithm;
  operation->request.direction = direction;
  operation->request.key = (mbedtls_psa_async_crypto_const_buffer_t){key_buffer, key_buffer_size};
  operation->request.nonce = (mbedtls_psa_async_crypto_const_buffer_t){nonce, nonce_length};
  operation->request.additional_data =
      (mbedtls_psa_async_crypto_const_buffer_t){additional_data, additional_data_length};
  operation->request.input = (mbedtls_psa_async_crypto_const_buffer_t){input, payload_length};
  operation->request.output = (mbedtls_psa_async_crypto_buffer_t){output, payload_length};
  if (direction == MBEDTLS_PSA_ASYNC_CRYPTO_ENCRYPT) {
    operation->request.output_tag =
        (mbedtls_psa_async_crypto_buffer_t){output + payload_length, tag_length};
  } else {
    operation->request.input_tag =
        (mbedtls_psa_async_crypto_const_buffer_t){input + payload_length, tag_length};
  }
  const psa_status_t status = mbedtls_psa_async_crypto_start(
      operation->provider, &operation->provider_operation, &operation->request);
  if (status != PSA_SUCCESS) {
    memset(operation, 0, sizeof(*operation));
  }
  return status;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_aead_encrypt_start(
    mbedtls_psa_async_crypto_aead_operation_t* operation, const psa_key_attributes_t* attributes,
    const uint8_t* key_buffer, size_t key_buffer_size, psa_algorithm_t algorithm,
    const uint8_t* nonce, size_t nonce_length, const uint8_t* additional_data,
    size_t additional_data_length, const uint8_t* plaintext, size_t plaintext_length,
    uint8_t* ciphertext, size_t ciphertext_size) {
  return mbedtls_psa_async_crypto_aead_start(
      operation, attributes, key_buffer, key_buffer_size, algorithm,
      MBEDTLS_PSA_ASYNC_CRYPTO_ENCRYPT, nonce, nonce_length, additional_data,
      additional_data_length, plaintext, plaintext_length, ciphertext, ciphertext_size);
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_aead_decrypt_start(
    mbedtls_psa_async_crypto_aead_operation_t* operation, const psa_key_attributes_t* attributes,
    const uint8_t* key_buffer, size_t key_buffer_size, psa_algorithm_t algorithm,
    const uint8_t* nonce, size_t nonce_length, const uint8_t* additional_data,
    size_t additional_data_length, const uint8_t* ciphertext, size_t ciphertext_length,
    uint8_t* plaintext, size_t plaintext_size) {
  return mbedtls_psa_async_crypto_aead_start(
      operation, attributes, key_buffer, key_buffer_size, algorithm,
      MBEDTLS_PSA_ASYNC_CRYPTO_DECRYPT, nonce, nonce_length, additional_data,
      additional_data_length, ciphertext, ciphertext_length, plaintext, plaintext_size);
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_aead_complete(
    mbedtls_psa_async_crypto_aead_operation_t* operation, size_t* output_length) {
  if (operation == NULL || operation->provider == NULL || output_length == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  const psa_status_t status =
      mbedtls_psa_async_crypto_complete(operation->provider, &operation->provider_operation);
  if (status == PSA_OPERATION_INCOMPLETE) {
    return status;
  }
  operation->num_ops += mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation);
  memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
  memset(&operation->request, 0, sizeof(operation->request));
  if (status == PSA_SUCCESS) {
    *output_length = operation->output_length;
  } else {
    *output_length = 0u;
  }
  operation->output_length = 0u;
  return status;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_aead_abort(
    mbedtls_psa_async_crypto_aead_operation_t* operation) {
  if (operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->provider != NULL &&
      operation->provider_operation.state != MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE) {
    (void)mbedtls_psa_async_crypto_abort(operation->provider, &operation->provider_operation);
  }
  memset(operation, 0, sizeof(*operation));
  return PSA_SUCCESS;
}

static inline uint32_t mbedtls_psa_async_crypto_transparent_aead_get_num_ops(
    const mbedtls_psa_async_crypto_aead_operation_t* operation) {
  if (operation == NULL) {
    return 0u;
  }
  const uint32_t current =
      operation->provider != NULL
          ? mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation)
          : 0u;
  return operation->num_ops + current;
}

static inline void mbedtls_psa_async_crypto_reset_signature_operation(
    mbedtls_psa_async_crypto_signature_operation_t* operation) {
  if (operation != NULL) {
    mbedtls_psa_async_crypto_zeroize(operation->nonce, sizeof(operation->nonce));
    mbedtls_psa_async_crypto_zeroize(operation->signature, sizeof(operation->signature));
    mbedtls_psa_async_crypto_zeroize(operation->key, sizeof(operation->key));
    mbedtls_psa_async_crypto_zeroize(operation->hash, sizeof(operation->hash));
    memset(operation, 0, sizeof(*operation));
  }
}

static inline void mbedtls_psa_async_crypto_finish_signature_operation(
    mbedtls_psa_async_crypto_signature_operation_t* operation) {
  mbedtls_psa_async_crypto_zeroize(operation->nonce, sizeof(operation->nonce));
  mbedtls_psa_async_crypto_zeroize(operation->signature, sizeof(operation->signature));
  mbedtls_psa_async_crypto_zeroize(operation->key, sizeof(operation->key));
  mbedtls_psa_async_crypto_zeroize(operation->hash, sizeof(operation->hash));
  memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
  memset(&operation->request, 0, sizeof(operation->request));
  operation->curve = NULL;
  operation->key_size = 0u;
  operation->hash_size = 0u;
  operation->key_type = 0u;
  operation->algorithm = 0u;
  operation->random_attempts = 0u;
  operation->stage = MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE_INACTIVE;
}

static inline psa_status_t mbedtls_psa_async_crypto_prepare_signature_operation(
    mbedtls_psa_async_crypto_signature_operation_t* operation,
    const psa_key_attributes_t* attributes, const uint8_t* key_buffer, size_t key_buffer_size,
    psa_algorithm_t algorithm, const uint8_t* hash, size_t hash_length) {
  if (operation == NULL || attributes == NULL || key_buffer == NULL || hash == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->stage != MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE_INACTIVE) {
    return PSA_ERROR_BAD_STATE;
  }

  mbedtls_psa_async_crypto_provider_t* provider = mbedtls_psa_async_crypto_bound_provider();
  if (provider == NULL) {
#if MBEDTLS_PSA_ASYNC_CRYPTO_SOFTWARE_ENABLED
    return PSA_ERROR_NOT_SUPPORTED;
#else
    return PSA_ERROR_BAD_STATE;
#endif
  }
  const psa_key_type_t key_type = psa_get_key_type(attributes);
  const size_t key_bits = psa_get_key_bits(attributes);
  const mbedtls_psa_async_crypto_prime_curve_t* curve =
      mbedtls_psa_async_crypto_resolve_prime_curve(key_type, key_bits);
  if (curve == NULL || !PSA_ALG_IS_ECDSA(algorithm) ||
      PSA_ALG_SIGN_GET_HASH(algorithm) != PSA_ALG_SHA_256) {
    return PSA_ERROR_NOT_SUPPORTED;
  }
  if (hash_length != curve->hash_length) {
    return PSA_ERROR_NOT_SUPPORTED;
  }
  if (key_buffer_size > sizeof(operation->key) || hash_length > sizeof(operation->hash)) {
    return PSA_ERROR_NOT_SUPPORTED;
  }

  operation->provider = provider;
  operation->curve = curve;
  operation->key_size = key_buffer_size;
  operation->hash_size = hash_length;
  operation->key_type = key_type;
  operation->algorithm = algorithm;
  memcpy(operation->key, key_buffer, key_buffer_size);
  memcpy(operation->hash, hash, hash_length);
  return PSA_SUCCESS;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_sign_hash_start(
    mbedtls_psa_async_crypto_signature_operation_t* operation,
    const psa_key_attributes_t* attributes, const uint8_t* key_buffer, size_t key_buffer_size,
    psa_algorithm_t algorithm, const uint8_t* hash, size_t hash_length) {
  psa_status_t status = mbedtls_psa_async_crypto_prepare_signature_operation(
      operation, attributes, key_buffer, key_buffer_size, algorithm, hash, hash_length);
  if (status != PSA_SUCCESS) {
    return status;
  }
  if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(operation->key_type) ||
      operation->key_size != operation->curve->order.length) {
    mbedtls_psa_async_crypto_reset_signature_operation(operation);
    return PSA_ERROR_NOT_SUPPORTED;
  }

  memset(&operation->request, 0, sizeof(operation->request));
  operation->request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RANDOM;
  operation->request.output =
      (mbedtls_psa_async_crypto_buffer_t){operation->nonce, operation->curve->order.length};
  status = mbedtls_psa_async_crypto_start(operation->provider, &operation->provider_operation,
                                          &operation->request);
  if (status != PSA_SUCCESS) {
    mbedtls_psa_async_crypto_reset_signature_operation(operation);
    return status;
  }
  operation->random_attempts = 1u;
  operation->stage = MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE_RANDOM;
  return PSA_SUCCESS;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_sign_hash_complete(
    mbedtls_psa_async_crypto_signature_operation_t* operation, uint8_t* signature,
    size_t signature_size, size_t* signature_length) {
  if (operation == NULL || signature == NULL || signature_length == NULL ||
      operation->provider == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

complete_signature:
  if (operation->stage == MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE_RANDOM) {
    psa_status_t status =
        mbedtls_psa_async_crypto_complete(operation->provider, &operation->provider_operation);
    if (status == PSA_OPERATION_INCOMPLETE) {
      return status;
    }
    operation->num_ops += mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation);
    memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
    if (status != PSA_SUCCESS) {
      mbedtls_psa_async_crypto_finish_signature_operation(operation);
      return status;
    }
    if (!mbedtls_psa_async_crypto_valid_nonce(operation->nonce, operation->curve)) {
      if (operation->random_attempts >= 8u) {
        mbedtls_psa_async_crypto_finish_signature_operation(operation);
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
      }
      status = mbedtls_psa_async_crypto_start(operation->provider, &operation->provider_operation,
                                              &operation->request);
      if (status != PSA_SUCCESS) {
        mbedtls_psa_async_crypto_finish_signature_operation(operation);
        return status;
      }
      ++operation->random_attempts;
      return PSA_OPERATION_INCOMPLETE;
    }

    memset(&operation->request, 0, sizeof(operation->request));
    operation->request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_SIGN_HASH;
    operation->request.key_type = operation->key_type;
    operation->request.key_bits = operation->curve->order.length * 8u;
    operation->request.alg = operation->algorithm;
    operation->request.key =
        (mbedtls_psa_async_crypto_const_buffer_t){operation->key, operation->key_size};
    operation->request.private_key =
        (mbedtls_psa_async_crypto_const_buffer_t){operation->key, operation->key_size};
    operation->request.nonce_scalar =
        (mbedtls_psa_async_crypto_const_buffer_t){operation->nonce, operation->curve->order.length};
    operation->request.hash =
        (mbedtls_psa_async_crypto_const_buffer_t){operation->hash, operation->hash_size};
    operation->request.signature = (mbedtls_psa_async_crypto_buffer_t){
        operation->signature, operation->curve->order.length * 2u};
    operation->request.prime_curve = operation->curve;
    status = mbedtls_psa_async_crypto_start(operation->provider, &operation->provider_operation,
                                            &operation->request);
    if (status != PSA_SUCCESS) {
      mbedtls_psa_async_crypto_finish_signature_operation(operation);
      return status;
    }
    operation->stage = MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE;
    goto complete_signature;
  }

  if (operation->stage != MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE) {
    return PSA_ERROR_BAD_STATE;
  }
  const psa_status_t status =
      mbedtls_psa_async_crypto_complete(operation->provider, &operation->provider_operation);
  if (status == PSA_OPERATION_INCOMPLETE) {
    return status;
  }
  operation->num_ops += mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation);
  memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
  if (status != PSA_SUCCESS) {
    mbedtls_psa_async_crypto_finish_signature_operation(operation);
    return status;
  }
  const size_t output_length = operation->curve->order.length * 2u;
  if (signature_size < output_length) {
    mbedtls_psa_async_crypto_finish_signature_operation(operation);
    return PSA_ERROR_BUFFER_TOO_SMALL;
  }
  memcpy(signature, operation->signature, output_length);
  *signature_length = output_length;
  return PSA_SUCCESS;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_verify_hash_start(
    mbedtls_psa_async_crypto_signature_operation_t* operation,
    const psa_key_attributes_t* attributes, const uint8_t* key_buffer, size_t key_buffer_size,
    psa_algorithm_t algorithm, const uint8_t* hash, size_t hash_length, const uint8_t* signature,
    size_t signature_length) {
  psa_status_t status = mbedtls_psa_async_crypto_prepare_signature_operation(
      operation, attributes, key_buffer, key_buffer_size, algorithm, hash, hash_length);
  if (status != PSA_SUCCESS) {
    return status;
  }
  if (!PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(operation->key_type) ||
      operation->key_size != 1u + 2u * operation->curve->prime.length || key_buffer[0] != 0x04u ||
      signature == NULL || signature_length != 2u * operation->curve->order.length) {
    mbedtls_psa_async_crypto_reset_signature_operation(operation);
    return PSA_ERROR_NOT_SUPPORTED;
  }
  memcpy(operation->signature, signature, signature_length);

  memset(&operation->request, 0, sizeof(operation->request));
  operation->request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_VERIFY_HASH;
  operation->request.key_type = operation->key_type;
  operation->request.key_bits = operation->curve->order.length * 8u;
  operation->request.alg = operation->algorithm;
  operation->request.key = (mbedtls_psa_async_crypto_const_buffer_t){key_buffer, key_buffer_size};
  operation->request.public_key =
      (mbedtls_psa_async_crypto_const_buffer_t){key_buffer, key_buffer_size};
  operation->request.hash = (mbedtls_psa_async_crypto_const_buffer_t){hash, hash_length};
  operation->request.signature =
      (mbedtls_psa_async_crypto_buffer_t){operation->signature, signature_length};
  operation->request.prime_curve = operation->curve;
  status = mbedtls_psa_async_crypto_start(operation->provider, &operation->provider_operation,
                                          &operation->request);
  if (status != PSA_SUCCESS) {
    mbedtls_psa_async_crypto_reset_signature_operation(operation);
    return status;
  }
  operation->stage = MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE;
  return PSA_SUCCESS;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_verify_hash_complete(
    mbedtls_psa_async_crypto_signature_operation_t* operation) {
  if (operation == NULL || operation->provider == NULL ||
      operation->stage != MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE) {
    return PSA_ERROR_BAD_STATE;
  }
  const psa_status_t status =
      mbedtls_psa_async_crypto_complete(operation->provider, &operation->provider_operation);
  if (status != PSA_OPERATION_INCOMPLETE) {
    operation->num_ops += mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation);
    mbedtls_psa_async_crypto_finish_signature_operation(operation);
  }
  return status;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_signature_abort(
    mbedtls_psa_async_crypto_signature_operation_t* operation) {
  if (operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->provider != NULL &&
      operation->provider_operation.state != MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE) {
    mbedtls_psa_async_crypto_abort(operation->provider, &operation->provider_operation);
  }
  mbedtls_psa_async_crypto_reset_signature_operation(operation);
  return PSA_SUCCESS;
}

static inline uint32_t mbedtls_psa_async_crypto_transparent_signature_get_num_ops(
    const mbedtls_psa_async_crypto_signature_operation_t* operation) {
  if (operation == NULL) {
    return 0u;
  }
  const uint32_t current =
      operation->provider != NULL
          ? mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation)
          : 0u;
  const uint32_t total = operation->num_ops + current;
  return total == 0u && operation->stage != MBEDTLS_PSA_ASYNC_CRYPTO_SIGNATURE_INACTIVE ? 1u
                                                                                        : total;
}

static inline void mbedtls_psa_async_crypto_reset_key_agreement_operation(
    mbedtls_psa_async_crypto_key_agreement_operation_t* operation) {
  if (operation != NULL) {
    mbedtls_psa_async_crypto_zeroize(operation->shared_secret, sizeof(operation->shared_secret));
    memset(operation, 0, sizeof(*operation));
  }
}

static inline void mbedtls_psa_async_crypto_finish_key_agreement_operation(
    mbedtls_psa_async_crypto_key_agreement_operation_t* operation) {
  mbedtls_psa_async_crypto_zeroize(operation->shared_secret, sizeof(operation->shared_secret));
  memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
  memset(&operation->request, 0, sizeof(operation->request));
  operation->curve = NULL;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_key_agreement_setup(
    mbedtls_psa_async_crypto_key_agreement_operation_t* operation,
    const psa_key_attributes_t* private_key_attributes, const uint8_t* private_key_buffer,
    size_t private_key_buffer_size, const uint8_t* peer_key, size_t peer_key_length) {
  if (operation == NULL || private_key_attributes == NULL || private_key_buffer == NULL ||
      peer_key == NULL || operation->provider != NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  mbedtls_psa_async_crypto_provider_t* provider = mbedtls_psa_async_crypto_bound_provider();
  if (provider == NULL) {
    return PSA_ERROR_BAD_STATE;
  }
  const psa_key_type_t key_type = psa_get_key_type(private_key_attributes);
  const size_t key_bits = psa_get_key_bits(private_key_attributes);
  const mbedtls_psa_async_crypto_prime_curve_t* curve =
      mbedtls_psa_async_crypto_resolve_prime_curve(key_type, key_bits);
  if (curve == NULL || !PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) ||
      private_key_buffer_size != curve->order.length ||
      peer_key_length != 1u + 2u * curve->prime.length || peer_key[0] != 0x04u) {
    return PSA_ERROR_NOT_SUPPORTED;
  }

  operation->provider = provider;
  operation->curve = curve;
  memset(&operation->request, 0, sizeof(operation->request));
  operation->request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_KEY_AGREEMENT;
  operation->request.key_type = key_type;
  operation->request.key_bits = key_bits;
  operation->request.alg = PSA_ALG_ECDH;
  operation->request.key =
      (mbedtls_psa_async_crypto_const_buffer_t){private_key_buffer, private_key_buffer_size};
  operation->request.private_key =
      (mbedtls_psa_async_crypto_const_buffer_t){private_key_buffer, private_key_buffer_size};
  operation->request.peer_key =
      (mbedtls_psa_async_crypto_const_buffer_t){peer_key, peer_key_length};
  operation->request.shared_secret = (mbedtls_psa_async_crypto_buffer_t){
      operation->shared_secret, curve->order.length};
  operation->request.prime_curve = curve;
  const psa_status_t status = mbedtls_psa_async_crypto_start(
      operation->provider, &operation->provider_operation, &operation->request);
  if (status != PSA_SUCCESS) {
    mbedtls_psa_async_crypto_reset_key_agreement_operation(operation);
  }
  return status;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_key_agreement_complete(
    mbedtls_psa_async_crypto_key_agreement_operation_t* operation, uint8_t* shared_secret,
    size_t shared_secret_size, size_t* shared_secret_length) {
  if (operation == NULL || operation->provider == NULL || shared_secret == NULL ||
      shared_secret_length == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  const psa_status_t status =
      mbedtls_psa_async_crypto_complete(operation->provider, &operation->provider_operation);
  if (status == PSA_OPERATION_INCOMPLETE) {
    return status;
  }
  operation->num_ops += mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation);
  memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
  if (status != PSA_SUCCESS) {
    mbedtls_psa_async_crypto_finish_key_agreement_operation(operation);
    return status;
  }
  const size_t output_length = operation->curve->order.length;
  if (shared_secret_size < output_length) {
    mbedtls_psa_async_crypto_finish_key_agreement_operation(operation);
    return PSA_ERROR_BUFFER_TOO_SMALL;
  }
  memcpy(shared_secret, operation->shared_secret, output_length);
  *shared_secret_length = output_length;
  mbedtls_psa_async_crypto_finish_key_agreement_operation(operation);
  return PSA_SUCCESS;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_key_agreement_abort(
    mbedtls_psa_async_crypto_key_agreement_operation_t* operation) {
  if (operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->provider != NULL &&
      operation->provider_operation.state != MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE) {
    mbedtls_psa_async_crypto_abort(operation->provider, &operation->provider_operation);
  }
  mbedtls_psa_async_crypto_reset_key_agreement_operation(operation);
  return PSA_SUCCESS;
}

static inline uint32_t mbedtls_psa_async_crypto_transparent_key_agreement_get_num_ops(
    const mbedtls_psa_async_crypto_key_agreement_operation_t* operation) {
  if (operation == NULL) {
    return 0u;
  }
  const uint32_t current =
      operation->provider != NULL
          ? mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation)
          : 0u;
  return operation->num_ops + current;
}

static inline void mbedtls_psa_async_crypto_reset_export_public_key_operation(
    mbedtls_psa_async_crypto_export_public_key_operation_t* operation) {
  if (operation != NULL) {
    mbedtls_psa_async_crypto_zeroize(operation->public_key, sizeof(operation->public_key));
    memset(operation, 0, sizeof(*operation));
  }
}

static inline void mbedtls_psa_async_crypto_finish_export_public_key_operation(
    mbedtls_psa_async_crypto_export_public_key_operation_t* operation) {
  mbedtls_psa_async_crypto_zeroize(operation->public_key, sizeof(operation->public_key));
  memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
  memset(&operation->request, 0, sizeof(operation->request));
  operation->curve = NULL;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_export_public_key_iop_setup(
    mbedtls_psa_async_crypto_export_public_key_operation_t* operation, uint8_t* private_key,
    size_t private_key_length, const psa_key_attributes_t* private_key_attributes) {
  if (operation == NULL || private_key == NULL || private_key_attributes == NULL ||
      operation->provider != NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  mbedtls_psa_async_crypto_provider_t* provider = mbedtls_psa_async_crypto_bound_provider();
  if (provider == NULL) {
    return PSA_ERROR_BAD_STATE;
  }
  const psa_key_type_t key_type = psa_get_key_type(private_key_attributes);
  const size_t key_bits = psa_get_key_bits(private_key_attributes);
  const mbedtls_psa_async_crypto_prime_curve_t* curve =
      mbedtls_psa_async_crypto_resolve_prime_curve(key_type, key_bits);
  if (curve == NULL || !PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) ||
      private_key_length != curve->order.length) {
    return PSA_ERROR_NOT_SUPPORTED;
  }

  operation->provider = provider;
  operation->curve = curve;
  memset(&operation->request, 0, sizeof(operation->request));
  operation->request.operation = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_EXPORT_PUBLIC_KEY;
  operation->request.key_type = key_type;
  operation->request.key_bits = key_bits;
  operation->request.key =
      (mbedtls_psa_async_crypto_const_buffer_t){private_key, private_key_length};
  operation->request.private_key =
      (mbedtls_psa_async_crypto_const_buffer_t){private_key, private_key_length};
  operation->request.public_key_output =
      (mbedtls_psa_async_crypto_buffer_t){operation->public_key, 1u + 2u * curve->prime.length};
  operation->request.prime_curve = curve;
  const psa_status_t status = mbedtls_psa_async_crypto_start(
      operation->provider, &operation->provider_operation, &operation->request);
  if (status != PSA_SUCCESS) {
    mbedtls_psa_async_crypto_reset_export_public_key_operation(operation);
  }
  return status;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_export_public_key_iop_complete(
    mbedtls_psa_async_crypto_export_public_key_operation_t* operation, uint8_t* public_key,
    size_t public_key_size, size_t* public_key_length) {
  if (operation == NULL || operation->provider == NULL || public_key == NULL ||
      public_key_length == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  const psa_status_t status =
      mbedtls_psa_async_crypto_complete(operation->provider, &operation->provider_operation);
  if (status == PSA_OPERATION_INCOMPLETE) {
    return status;
  }
  operation->num_ops += mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation);
  memset(&operation->provider_operation, 0, sizeof(operation->provider_operation));
  if (status != PSA_SUCCESS) {
    mbedtls_psa_async_crypto_finish_export_public_key_operation(operation);
    return status;
  }
  const size_t output_length = 1u + 2u * operation->curve->prime.length;
  if (public_key_size < output_length) {
    mbedtls_psa_async_crypto_finish_export_public_key_operation(operation);
    return PSA_ERROR_BUFFER_TOO_SMALL;
  }
  memcpy(public_key, operation->public_key, output_length);
  *public_key_length = output_length;
  mbedtls_psa_async_crypto_finish_export_public_key_operation(operation);
  return PSA_SUCCESS;
}

static inline psa_status_t mbedtls_psa_async_crypto_transparent_export_public_key_iop_abort(
    mbedtls_psa_async_crypto_export_public_key_operation_t* operation) {
  if (operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->provider != NULL &&
      operation->provider_operation.state != MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE) {
    mbedtls_psa_async_crypto_abort(operation->provider, &operation->provider_operation);
  }
  mbedtls_psa_async_crypto_reset_export_public_key_operation(operation);
  return PSA_SUCCESS;
}

static inline uint32_t mbedtls_psa_async_crypto_transparent_export_public_key_iop_get_num_ops(
    const mbedtls_psa_async_crypto_export_public_key_operation_t* operation) {
  if (operation == NULL) {
    return 0u;
  }
  const uint32_t current =
      operation->provider != NULL
          ? mbedtls_psa_async_crypto_get_num_ops(&operation->provider_operation)
          : 0u;
  return operation->num_ops + current;
}

#endif /* MBEDTLS_PSA_CRYPTO_ASYNC_DRIVER_H */
