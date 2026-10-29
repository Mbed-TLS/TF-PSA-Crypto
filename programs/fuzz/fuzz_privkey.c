#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include <stdint.h>
#include <stdlib.h>
#include "mbedtls/pk.h"
#include "mbedtls/private/pk_private.h"
#include "fuzz_common.h"

#if defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_PK_WRITE_C)

#define MAX_LEN 0x1000
/* Re-encoding can be larger than the input (e.g. a SEC1 EC key gains its curve
 * OID and public point), so the round-trip buffer must not be bounded by Size. */
static uint8_t out_buf[2 * MAX_LEN];

/* A non-empty password is required to get past the pwdlen == 0 early return in
 * mbedtls_pk_parse_key(), which otherwise leaves the whole encrypted-key
 * surface (PKCS#5 PBES2/PBKDF2, PEM encryption) unreachable. Encrypted seeds
 * are generated with this same password so they decrypt. */
static const char fuzz_pwd[] = "password";

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{

    int ret;
    mbedtls_pk_context pk;

    if (Size > MAX_LEN) {
        //only work on small inputs
        Size = MAX_LEN;
    }

    dummy_init();
    mbedtls_pk_init(&pk);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    ret = mbedtls_pk_parse_key(&pk, Data, Size,
                               (const unsigned char *) fuzz_pwd,
                               sizeof(fuzz_pwd) - 1);
    if (ret == 0) {
        /* Success returns the number of bytes written, not 0. A key whose
         * re-encoding does not fit is a limit of out_buf, not a defect. */
        ret = mbedtls_pk_write_key_der(&pk, out_buf, sizeof(out_buf));
        if (ret <= 0 && ret != PSA_ERROR_BUFFER_TOO_SMALL) {
            abort();
        }
    }
exit:
    mbedtls_pk_free(&pk);
    mbedtls_psa_crypto_free();

    return 0;
}

#else /* MBEDTLS_PK_PARSE_C && MBEDTLS_PK_WRITE_C */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    (void) Data;
    (void) Size;
    return 0;
}
#endif /* MBEDTLS_PK_PARSE_C && MBEDTLS_PK_WRITE_C */
