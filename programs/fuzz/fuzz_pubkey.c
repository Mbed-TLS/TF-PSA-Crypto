#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include <stdint.h>
#include <stdlib.h>
#include "mbedtls/pk.h"
#include "fuzz_common.h"

#define MAX_LEN 0x1000
static uint8_t out_buf[MAX_LEN];

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_PK_WRITE_C)
    int ret;
    mbedtls_pk_context pk;

    if (Size > MAX_LEN) {
        abort();
    }

    mbedtls_pk_init(&pk);
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        abort();
    }

    ret = mbedtls_pk_parse_public_key(&pk, Data, Size);
    if (ret != 0) {
        abort();
    }

    ret = mbedtls_pk_write_pubkey_der(&pk, out_buf, Size);
    if (ret <= 0) {
        abort();
    }

    mbedtls_psa_crypto_free();
    mbedtls_pk_free(&pk);
#else /* MBEDTLS_PK_PARSE_C && MBEDTLS_PK_WRITE_C */
    (void) Data;
    (void) Size;
#endif /* MBEDTLS_PK_PARSE_C && MBEDTLS_PK_WRITE_C */

    return 0;
}
