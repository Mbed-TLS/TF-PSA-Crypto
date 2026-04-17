#include <stdio.h>

#include <tf-psa-crypto/build_info.h>

#include "wrap_mldsa_native.h"
#include "psa_crypto_mldsa.h"
#include "mbedtls/platform.h"
#include "mldsa_constants.h"
#include "asn1_file_io.h"
#include "psa/crypto.h"

int main(void)
{
#if !defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED) || \
    !defined(TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED) || \
    !defined(MBEDTLS_PSA_BUILTIN_GET_ENTROPY) || \
    !defined(MBEDTLS_ASN1_WRITE_C) || \
    defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS) || \
    defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    puts(
        "These programs require TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED MBEDTLS_ASN1_WRITE_C !MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS !MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG to be enabled in crypto_config.h");
    return 0;
#else

    unsigned char public_key[MLDSA_PUBLICKEYBYTES(KEY_LENGTH)];
    unsigned char signature[MLDSA_BYTES(KEY_LENGTH)];

    if (asn1_read_octet_string_file(signature_file, signature, sizeof(signature)) != 0 ||
        asn1_read_octet_string_file(pub_key_file, public_key, sizeof(public_key)) != 0) {
        return 1;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_crypto_init();

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
    psa_set_key_bits(&attributes, KEY_LENGTH);

    if (tf_psa_crypto_mldsa_verify_message(&attributes,
                                           public_key, MLDSA_PUBLICKEYBYTES(KEY_LENGTH),
                                           PSA_ALG_DETERMINISTIC_ML_DSA,
                                           message, sizeof(message),
                                           signature, sizeof(signature)) != PSA_SUCCESS) {
        mbedtls_printf("verify failed\n");
        return 1;
    }
#endif
}
