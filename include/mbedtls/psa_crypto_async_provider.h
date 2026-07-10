#ifndef MBEDTLS_PSA_CRYPTO_ASYNC_PROVIDER_H
#define MBEDTLS_PSA_CRYPTO_ASYNC_PROVIDER_H

#include "mbedtls/psa_crypto_async_config.h"
#include "mbedtls/psa_crypto_async_hardware.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum mbedtls_psa_async_crypto_operation_state_e {
  MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE = 0,
  MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_IN_PROGRESS = 1,
  MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_COMPLETE = 2
} mbedtls_psa_async_crypto_operation_state_t;

typedef struct mbedtls_psa_async_crypto_operation_s {
  mbedtls_psa_async_crypto_operation_state_t state;
  psa_status_t status;
  uint32_t num_ops;
} mbedtls_psa_async_crypto_operation_t;

struct mbedtls_psa_async_crypto_provider_s;

typedef struct mbedtls_psa_async_crypto_completion_slot_s {
  int allocated;
  int queued;
  int active;
  struct mbedtls_psa_async_crypto_provider_s* provider;
  mbedtls_psa_async_crypto_operation_t* operation;
  mbedtls_psa_async_crypto_hardware_completion_t completion;
  mbedtls_psa_async_crypto_request_t request;
  uint32_t sequence;
} mbedtls_psa_async_crypto_completion_slot_t;

typedef struct mbedtls_psa_async_crypto_provider_s {
  const mbedtls_psa_async_crypto_hardware_t* hardware;
  mbedtls_psa_async_crypto_completion_slot_t
      completion_slots[MBEDTLS_PSA_ASYNC_CRYPTO_MAX_CONCURRENT_OPERATIONS];
  uint32_t next_sequence;
} mbedtls_psa_async_crypto_provider_t;

#define MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INIT                                                    \
  {MBEDTLS_PSA_ASYNC_CRYPTO_OPERATION_INACTIVE, PSA_SUCCESS, 0}

void mbedtls_psa_async_crypto_provider_init(mbedtls_psa_async_crypto_provider_t* provider,
                                            const mbedtls_psa_async_crypto_hardware_t* hardware);

psa_status_t mbedtls_psa_async_crypto_bind_provider(mbedtls_psa_async_crypto_provider_t* provider);

psa_status_t
mbedtls_psa_async_crypto_unbind_provider(mbedtls_psa_async_crypto_provider_t* provider);

mbedtls_psa_async_crypto_provider_t* mbedtls_psa_async_crypto_bound_provider(void);

psa_status_t mbedtls_psa_async_crypto_start(mbedtls_psa_async_crypto_provider_t* provider,
                                            mbedtls_psa_async_crypto_operation_t* operation,
                                            const mbedtls_psa_async_crypto_request_t* request);

psa_status_t mbedtls_psa_async_crypto_complete(mbedtls_psa_async_crypto_provider_t* provider,
                                               mbedtls_psa_async_crypto_operation_t* operation);

psa_status_t mbedtls_psa_async_crypto_abort(mbedtls_psa_async_crypto_provider_t* provider,
                                            mbedtls_psa_async_crypto_operation_t* operation);

uint32_t
mbedtls_psa_async_crypto_get_num_ops(const mbedtls_psa_async_crypto_operation_t* operation);

mbedtls_psa_async_crypto_capability_t mbedtls_psa_async_crypto_get_hardware_capabilities(
    const mbedtls_psa_async_crypto_provider_t* provider);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PSA_CRYPTO_ASYNC_PROVIDER_H */
