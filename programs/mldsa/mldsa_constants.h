#ifndef TF_PSA_CRYPTO_PROGRAMS_MLDSA_CONSTANTS_H
#define TF_PSA_CRYPTO_PROGRAMS_MLDSA_CONSTANTS_H

#include <stdint.h>

#define KEY_LENGTH 87

#define MLDSA_RNDBYTES 32

// Message from tf-psa-crypto/tests/suites/test_suite_pqcp_mldsa.dilithium_py.data:
static const uint8_t message[] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
    0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x00
};
// Seed from tf-psa-crypto/tests/suites/test_suite_pqcp_mldsa.dilithium_py.data:
static const uint8_t seed[] = {
    0x54, 0x68, 0x65, 0x72, 0x65, 0x20, 0x77, 0x61,
    0x73, 0x20, 0x6F, 0x6E, 0x63, 0x65, 0x20, 0x75,
    0x70, 0x6F, 0x6E, 0x20, 0x61, 0x20, 0x74, 0x69,
    0x6D, 0x65, 0x20, 0x61, 0x20, 0x2E, 0x2E, 0x2E
};
/* Native API detail used by the existing tests for pure ML-DSA, empty context. */
static const uint8_t prefix[2] = { 0, 0 };
static const uint8_t rnd[MLDSA_RNDBYTES] = { 0 };
static const char signature_file[] = "signature.sig";
static const char pub_key_file[] = "pubkey.key";
static const char key_file[] = "key.key";
#endif /* TF_PSA_CRYPTO_PROGRAMS_MLDSA_CONSTANTS_H */
