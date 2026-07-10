#include "mbedtls/psa_crypto_async_provider.h"

#include <string.h>

static mbedtls_psa_async_crypto_provider_t* bound_provider;

#if MBEDTLS_PSA_ASYNC_CRYPTO_HARDWARE_ENABLED
static int has_capability(mbedtls_psa_async_crypto_capability_t capabilities,
                          mbedtls_psa_async_crypto_capability_t capability) {
  return (capabilities & capability) == capability;
}

static int valid_const_buffer(mbedtls_psa_async_crypto_const_buffer_t buffer) {
  return buffer.data != NULL || buffer.length == 0;
}

static int valid_buffer(mbedtls_psa_async_crypto_buffer_t buffer) {
  return buffer.data != NULL || buffer.length == 0;
}

static int valid_stream_buffers(const mbedtls_psa_async_crypto_request_t* request) {
  return request->input.data != NULL && request->output.data != NULL &&
         request->input.length != 0 && request->input.length == request->output.length;
}

static int valid_aes_key(const mbedtls_psa_async_crypto_request_t* request) {
  return request->key_type == PSA_KEY_TYPE_AES && request->key.data != NULL &&
         request->key.length == request->key_bits / 8 &&
         (request->key_bits == 128 || request->key_bits == 192 || request->key_bits == 256);
}

static size_t hash_output_length(psa_algorithm_t alg) {
  if (alg == PSA_ALG_SHA_1) {
    return 20;
  }
  if (alg == PSA_ALG_SHA_224) {
    return 28;
  }
  if (alg == PSA_ALG_SHA_256) {
    return 32;
  }
  return 0;
}

static int valid_request_input(const mbedtls_psa_async_crypto_request_t* request) {
  size_t index;
  size_t total = 0;

  if (request->input_segment_count == 0) {
    return request->input_segments == NULL && request->input.data != NULL &&
           request->input.length != 0;
  }
  if (request->input.data != NULL || request->input.length != 0 ||
      request->input_segments == NULL ||
      request->input_segment_count > MBEDTLS_PSA_ASYNC_CRYPTO_MAX_INPUT_SEGMENTS) {
    return 0;
  }
  for (index = 0; index < request->input_segment_count; ++index) {
    if (request->input_segments[index].data == NULL || request->input_segments[index].length == 0 ||
        request->input_segments[index].length > SIZE_MAX - total) {
      return 0;
    }
    total += request->input_segments[index].length;
  }
  return total != 0;
}

static mbedtls_psa_async_crypto_capability_t
request_capability(const mbedtls_psa_async_crypto_request_t* request,
                   mbedtls_psa_async_crypto_capability_t capabilities) {
  switch (request->operation) {
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RANDOM:
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_RANDOM;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_CIPHER:
    if (request->key_type != PSA_KEY_TYPE_AES) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;
    }
    if (request->alg == PSA_ALG_ECB_NO_PADDING) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_ECB;
    }
    if (request->alg == PSA_ALG_CBC_NO_PADDING) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_CBC;
    }
    if (request->alg == PSA_ALG_CTR) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_CTR;
    }
    if (request->alg == PSA_ALG_CFB) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_CFB;
    }
    if (request->alg == PSA_ALG_OFB) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_OFB;
    }
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AEAD:
    if (request->key_type != PSA_KEY_TYPE_AES) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;
    }
    if (request->alg == PSA_ALG_GCM) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_GCM;
    }
    if (request->alg == PSA_ALG_CCM) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_CCM;
    }
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AES_GHASH:
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_AES_GHASH;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_HASH:
    if (request->alg == PSA_ALG_SHA_1) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_SHA_1;
    }
    if (request->alg == PSA_ALG_SHA_224) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_SHA_224;
    }
    if (request->alg == PSA_ALG_SHA_256) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_SHA_256;
    }
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_HMAC:
    if (!PSA_ALG_IS_HMAC(request->alg)) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;
    }
    if (PSA_ALG_HMAC_GET_HASH(request->alg) == PSA_ALG_SHA_1) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_HMAC_SHA_1;
    }
    if (PSA_ALG_HMAC_GET_HASH(request->alg) == PSA_ALG_SHA_224) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_HMAC_SHA_224;
    }
    if (PSA_ALG_HMAC_GET_HASH(request->alg) == PSA_ALG_SHA_256) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_HMAC_SHA_256;
    }
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_SIGN_HASH:
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_VERIFY_HASH:
    if (PSA_KEY_TYPE_IS_RSA(request->key_type)) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_RSA;
    }
    if (request->prime_curve != NULL) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_ECDSA;
    }
    if (request->binary_curve != NULL) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_ECDSA_GF2N;
    }
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_KEY_AGREEMENT:
    if (request->prime_curve != NULL) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_ECDH;
    }
    if (request->binary_curve != NULL) {
      return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_ECDH_GF2N;
    }
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_EXPORT_PUBLIC_KEY:
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_EXPORT_PUBLIC_KEY;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RAW_RSA:
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_RSA;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RSA_CRT:
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_RSA_CRT;

  default:
    (void)capabilities;
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;
  }
}

static int valid_request(const mbedtls_psa_async_crypto_request_t* request) {
  if (request == NULL || !valid_const_buffer(request->input) || !valid_buffer(request->output)) {
    return 0;
  }

  switch (request->operation) {
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RANDOM:
    return request->output.data != NULL && request->output.length != 0;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_CIPHER:
    if (!valid_aes_key(request) || !valid_stream_buffers(request)) {
      return 0;
    }
    if (request->alg == PSA_ALG_ECB_NO_PADDING) {
      return request->input.length % 16 == 0;
    }
    if (request->alg == PSA_ALG_CBC_NO_PADDING) {
      return request->iv.data != NULL && request->iv.length == 16 &&
             request->input.length % 16 == 0;
    }
    if (request->alg == PSA_ALG_CTR || request->alg == PSA_ALG_CFB || request->alg == PSA_ALG_OFB) {
      return request->iv.data != NULL && request->iv.length == 16;
    }
    return 0;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AEAD:
    return valid_aes_key(request) && request->nonce.data != NULL && request->nonce.length != 0 &&
           valid_const_buffer(request->additional_data) && valid_const_buffer(request->input_tag) &&
           valid_buffer(request->output_tag) && valid_stream_buffers(request) &&
           (request->direction == MBEDTLS_PSA_ASYNC_CRYPTO_ENCRYPT
                ? request->output_tag.data != NULL && request->output_tag.length != 0
                : request->input_tag.data != NULL && request->input_tag.length != 0);

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AES_GHASH:
    return request->key.data != NULL && request->key.length == 16 && request->input.data != NULL &&
           request->input.length != 0 && request->input.length % 16 == 0 &&
           request->output.data != NULL && request->output.length == 16;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_HASH:
    return valid_request_input(request) && request->output.data != NULL &&
           request->output.length == hash_output_length(request->alg);

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_HMAC:
    return request->key_type == PSA_KEY_TYPE_HMAC && request->key.data != NULL &&
           request->key.length != 0 && request->key_bits == request->key.length * 8 &&
           valid_request_input(request) && request->output.data != NULL &&
           request->output.length == hash_output_length(PSA_ALG_HMAC_GET_HASH(request->alg));

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_SIGN_HASH:
    return request->private_key.data != NULL && request->private_key.length != 0 &&
           request->hash.data != NULL && request->hash.length != 0 &&
           request->signature.data != NULL && request->signature.length != 0 &&
           (PSA_KEY_TYPE_IS_RSA(request->key_type) || request->prime_curve != NULL ||
            request->binary_curve != NULL) &&
           (!PSA_KEY_TYPE_IS_ECC(request->key_type) ||
            (request->nonce_scalar.data != NULL && request->nonce_scalar.length != 0));

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_VERIFY_HASH:
    return request->public_key.data != NULL && request->public_key.length != 0 &&
           request->hash.data != NULL && request->hash.length != 0 &&
           request->signature.data != NULL && request->signature.length != 0 &&
           (PSA_KEY_TYPE_IS_RSA(request->key_type) || request->prime_curve != NULL ||
            request->binary_curve != NULL);

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_KEY_AGREEMENT:
    return PSA_KEY_TYPE_IS_ECC(request->key_type) &&
           (request->prime_curve != NULL || request->binary_curve != NULL) &&
           request->private_key.data != NULL && request->private_key.length != 0 &&
           request->peer_key.data != NULL && request->peer_key.length != 0 &&
           request->shared_secret.data != NULL && request->shared_secret.length != 0;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_EXPORT_PUBLIC_KEY:
    return PSA_KEY_TYPE_IS_ECC_KEY_PAIR(request->key_type) && request->prime_curve != NULL &&
           request->binary_curve == NULL && request->private_key.data != NULL &&
           request->private_key.length == request->prime_curve->order.length &&
           request->public_key_output.data != NULL &&
           request->public_key_output.length == 1 + 2 * request->prime_curve->prime.length;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RAW_RSA:
    return request->modulus.data != NULL && request->exponent.data != NULL &&
           request->modulus.length != 0 && request->exponent.length != 0 &&
           valid_stream_buffers(request) && request->output.length == request->modulus.length;

  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RSA_CRT:
    return request->prime_p.data != NULL && request->prime_q.data != NULL &&
           request->exponent_p.data != NULL && request->exponent_q.data != NULL &&
           request->q_inverse.data != NULL && request->prime_p.length != 0 &&
           request->prime_q.length == request->prime_p.length &&
           request->exponent_p.length == request->prime_p.length &&
           request->exponent_q.length == request->prime_p.length &&
           request->q_inverse.length == request->prime_p.length && valid_stream_buffers(request) &&
           request->output.length == 2 * request->prime_p.length;

  default:
    return 0;
  }
}
#endif

static void reset_operation(mbedtls_psa_async_crypto_operation_t* operation) {
  operation->state = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE;
  operation->status = PSA_SUCCESS;
  operation->num_ops = 0;
}

static void release_slot(mbedtls_psa_async_crypto_completion_slot_t* slot) {
  memset(slot, 0, sizeof(*slot));
}

#if MBEDTLS_PSA_ASYNC_CRYPTO_HARDWARE_ENABLED
static void finish_slot(mbedtls_psa_async_crypto_completion_slot_t* slot, psa_status_t status) {
  if (slot->operation != NULL) {
    slot->operation->state = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_COMPLETE;
    slot->operation->status = status;
    slot->operation->num_ops = 1;
  }
  release_slot(slot);
}

static void hardware_complete(psa_status_t status, void* context) {
  mbedtls_psa_async_crypto_completion_slot_t* slot = context;

  if (slot == NULL || !slot->allocated || slot->provider == NULL) {
    return;
  }
  finish_slot(slot, status);
}

static mbedtls_psa_async_crypto_hardware_operation_t
operation_function(const mbedtls_psa_async_crypto_hardware_functions_t* functions,
                   mbedtls_psa_async_crypto_operation_kind_t operation) {
  switch (operation) {
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RANDOM:
    return functions->generate_random;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_CIPHER:
    return functions->cipher;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AEAD:
    return functions->aead;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_AES_GHASH:
    return functions->aes_ghash;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_HASH:
    return functions->hash;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_HMAC:
    return functions->hmac;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_SIGN_HASH:
    return functions->sign_hash;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_VERIFY_HASH:
    return functions->verify_hash;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_KEY_AGREEMENT:
    return functions->key_agreement;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_EXPORT_PUBLIC_KEY:
    return functions->export_public_key;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RAW_RSA:
    return functions->raw_rsa;
  case MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_RSA_CRT:
    return functions->rsa_crt;
  default:
    return NULL;
  }
}

static psa_status_t dispatch_slot(mbedtls_psa_async_crypto_completion_slot_t* slot,
                                  int terminal_on_failure) {
  const mbedtls_psa_async_crypto_hardware_t* hardware = slot->provider->hardware;
  mbedtls_psa_async_crypto_hardware_operation_t function =
      operation_function(hardware->functions, slot->request.operation);
  psa_status_t status;

  if (function == NULL) {
    status = PSA_ERROR_NOT_SUPPORTED;
  } else {
    slot->queued = 0;
    slot->active = 1;
    slot->completion.callback = hardware_complete;
    slot->completion.context = slot;
    status = function(hardware->context, &slot->request, &slot->completion);
    if (!slot->allocated) {
      return PSA_SUCCESS;
    }
    slot->active = 0;
  }

  if (status == PSA_OPERATION_INCOMPLETE) {
    slot->active = 1;
    return PSA_SUCCESS;
  }
  if (status == PSA_ERROR_BAD_STATE) {
    slot->queued = 1;
    return PSA_OPERATION_INCOMPLETE;
  }
  if (status == PSA_SUCCESS) {
    finish_slot(slot, PSA_SUCCESS);
    return PSA_SUCCESS;
  }
  if (terminal_on_failure) {
    finish_slot(slot, status);
  }
  return status;
}
#endif

static void dispatch_queued(mbedtls_psa_async_crypto_provider_t* provider) {
#if MBEDTLS_PSA_ASYNC_CRYPTO_HARDWARE_ENABLED
  uint32_t previous_sequence = 0;
  size_t attempt;

  for (attempt = 0; attempt < MBEDTLS_PSA_ASYNC_CRYPTO_MAX_CONCURRENT_OPERATIONS; ++attempt) {
    mbedtls_psa_async_crypto_completion_slot_t* next = NULL;
    size_t index;

    for (index = 0; index < MBEDTLS_PSA_ASYNC_CRYPTO_MAX_CONCURRENT_OPERATIONS; ++index) {
      mbedtls_psa_async_crypto_completion_slot_t* candidate = &provider->completion_slots[index];
      if (candidate->allocated && candidate->queued && candidate->sequence > previous_sequence &&
          (next == NULL || candidate->sequence < next->sequence)) {
        next = candidate;
      }
    }
    if (next == NULL) {
      return;
    }
    previous_sequence = next->sequence;
    (void)dispatch_slot(next, 1);
  }
#else
  (void)provider;
#endif
}

void mbedtls_psa_async_crypto_provider_init(mbedtls_psa_async_crypto_provider_t* provider,
                                            const mbedtls_psa_async_crypto_hardware_t* hardware) {
  if (provider == NULL) {
    return;
  }
  memset(provider, 0, sizeof(*provider));
  provider->hardware = hardware;
  provider->next_sequence = 1;
}

psa_status_t mbedtls_psa_async_crypto_bind_provider(mbedtls_psa_async_crypto_provider_t* provider) {
  if (provider == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (bound_provider != NULL && bound_provider != provider) {
    return PSA_ERROR_ALREADY_EXISTS;
  }
  bound_provider = provider;
  return PSA_SUCCESS;
}

psa_status_t
mbedtls_psa_async_crypto_unbind_provider(mbedtls_psa_async_crypto_provider_t* provider) {
  if (provider == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (bound_provider != provider) {
    return PSA_ERROR_DOES_NOT_EXIST;
  }
  bound_provider = NULL;
  return PSA_SUCCESS;
}

mbedtls_psa_async_crypto_provider_t* mbedtls_psa_async_crypto_bound_provider(void) {
  return bound_provider;
}

psa_status_t mbedtls_psa_async_crypto_start(mbedtls_psa_async_crypto_provider_t* provider,
                                            mbedtls_psa_async_crypto_operation_t* operation,
                                            const mbedtls_psa_async_crypto_request_t* request) {
  if (provider == NULL || operation == NULL || request == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->state != MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE) {
    return PSA_ERROR_BAD_STATE;
  }

#if !MBEDTLS_PSA_ASYNC_CRYPTO_HARDWARE_ENABLED
  (void)provider;
  (void)request;
  return PSA_ERROR_NOT_SUPPORTED;
#else
  mbedtls_psa_async_crypto_completion_slot_t* slot = NULL;
  mbedtls_psa_async_crypto_capability_t capability;
  mbedtls_psa_async_crypto_capability_t capabilities;
  size_t index;
  psa_status_t status;

  if (provider->hardware == NULL || provider->hardware->functions == NULL ||
      provider->hardware->functions->get_capabilities == NULL) {
    return PSA_ERROR_NOT_SUPPORTED;
  }
  capabilities = provider->hardware->functions->get_capabilities(provider->hardware->context);
  capability = request_capability(request, capabilities);
  if (capability == MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE ||
      !has_capability(capabilities, capability)) {
    return PSA_ERROR_NOT_SUPPORTED;
  }
  if (!valid_request(request)) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  for (index = 0; index < MBEDTLS_PSA_ASYNC_CRYPTO_MAX_CONCURRENT_OPERATIONS; ++index) {
    if (!provider->completion_slots[index].allocated) {
      slot = &provider->completion_slots[index];
      break;
    }
  }
  if (slot == NULL) {
    return PSA_ERROR_INSUFFICIENT_MEMORY;
  }

  memset(slot, 0, sizeof(*slot));
  slot->allocated = 1;
  slot->provider = provider;
  slot->operation = operation;
  slot->request = *request;
  slot->sequence = provider->next_sequence++;
  if (provider->next_sequence == 0) {
    provider->next_sequence = 1;
  }
  operation->state = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_IN_PROGRESS;
  operation->status = PSA_OPERATION_INCOMPLETE;
  operation->num_ops = 0;

  status = dispatch_slot(slot, 0);
  if (status != PSA_SUCCESS && status != PSA_OPERATION_INCOMPLETE) {
    if (operation->state == MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_IN_PROGRESS) {
      release_slot(slot);
      reset_operation(operation);
    }
    return status;
  }
  return PSA_SUCCESS;
#endif
}

psa_status_t mbedtls_psa_async_crypto_complete(mbedtls_psa_async_crypto_provider_t* provider,
                                               mbedtls_psa_async_crypto_operation_t* operation) {
  psa_status_t status;

  if (provider == NULL || operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->state == MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE) {
    return PSA_ERROR_BAD_STATE;
  }
  if (operation->state == MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_IN_PROGRESS) {
    dispatch_queued(provider);
    if (operation->state == MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_IN_PROGRESS) {
      operation->num_ops = 0;
      return PSA_OPERATION_INCOMPLETE;
    }
  }

  status = operation->status;
  operation->state = MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE;
  return status;
}

psa_status_t mbedtls_psa_async_crypto_abort(mbedtls_psa_async_crypto_provider_t* provider,
                                            mbedtls_psa_async_crypto_operation_t* operation) {
  size_t index;

  if (provider == NULL || operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->state == MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_IN_PROGRESS) {
    for (index = 0; index < MBEDTLS_PSA_ASYNC_CRYPTO_MAX_CONCURRENT_OPERATIONS; ++index) {
      mbedtls_psa_async_crypto_completion_slot_t* slot = &provider->completion_slots[index];
      if (slot->allocated && slot->operation == operation) {
        if (slot->queued) {
          release_slot(slot);
        } else {
          slot->operation = NULL;
        }
        break;
      }
    }
  }
  reset_operation(operation);
  return PSA_SUCCESS;
}

uint32_t
mbedtls_psa_async_crypto_get_num_ops(const mbedtls_psa_async_crypto_operation_t* operation) {
  return operation == NULL ? 0 : operation->num_ops;
}

mbedtls_psa_async_crypto_capability_t mbedtls_psa_async_crypto_get_hardware_capabilities(
    const mbedtls_psa_async_crypto_provider_t* provider) {
  if (provider == NULL || provider->hardware == NULL || provider->hardware->functions == NULL ||
      provider->hardware->functions->get_capabilities == NULL) {
    return MBEDTLS_PSA_ASYNC_CRYPTO_CAPABILITY_NONE;
  }
  return provider->hardware->functions->get_capabilities(provider->hardware->context);
}
