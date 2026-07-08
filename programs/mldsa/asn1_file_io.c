#include "asn1_file_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"

#if defined(MBEDTLS_ASN1_WRITE_C) && !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

static int asn1_open_file(FILE **file, const char *path, const char *mode)
{
#if defined(_WIN32)
    return fopen_s(file, path, mode);
#else
    *file = fopen(path, mode);
    return *file == NULL ? -1 : 0;
#endif
}

static int asn1_write_len_file(FILE *file, size_t len)
{
    unsigned char encoded_len[1 + sizeof(size_t)];
    size_t encoded_len_size = 0;
    size_t i;

    if (len < 0x80) {
        encoded_len[0] = (unsigned char) len;
        encoded_len_size = 1;
    } else {
        size_t len_bytes = 0;
        size_t tmp = len;

        while (tmp != 0) {
            encoded_len[sizeof(encoded_len) - 1 - len_bytes] =
                (unsigned char) (tmp & 0xff);
            tmp >>= 8;
            len_bytes++;
        }

        encoded_len[0] = 0x80u | (unsigned char) len_bytes;
        for (i = 0; i < len_bytes; i++) {
            encoded_len[1 + i] =
                encoded_len[sizeof(encoded_len) - len_bytes + i];
        }
        encoded_len_size = 1 + len_bytes;
    }

    if (fwrite(encoded_len, 1, encoded_len_size, file) != encoded_len_size) {
        return -1;
    }

    return 0;
}

int asn1_write_octet_string_file(const char *path,
                                 const uint8_t *buffer,
                                 size_t buffer_len)
{
    unsigned char tag = MBEDTLS_ASN1_OCTET_STRING;
    FILE *file = NULL;

    if (asn1_open_file(&file, path, "wb") != 0) {
        return -1;
    }

    if (fwrite(&tag, 1, 1, file) != 1) {
        fclose(file);
        return -1;
    }

    if (asn1_write_len_file(file, buffer_len) != 0) {
        fclose(file);
        return -1;
    }

    if (fwrite(buffer, 1, buffer_len, file) != buffer_len) {
        fclose(file);
        return -1;
    }

    if (fclose(file) != 0) {
        return -1;
    }

    return 0;
}

int asn1_read_octet_string_file(const char *path,
                                uint8_t *buffer,
                                size_t buffer_len)
{
    int ret;
    long file_len_long;
    size_t file_len;
    size_t octet_len;
    unsigned char *der = NULL;
    unsigned char *p = NULL;
    FILE *file = NULL;

    if (asn1_open_file(&file, path, "rb") != 0) {
        return -1;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }

    file_len_long = ftell(file);
    if (file_len_long <= 0) {
        fclose(file);
        return -1;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }

    file_len = (size_t) file_len_long;
    der = malloc(file_len);
    if (der == NULL) {
        fclose(file);
        return -1;
    }

    if (fread(der, 1, file_len, file) != file_len) {
        fclose(file);
        free(der);
        return -1;
    }

    if (fclose(file) != 0) {
        free(der);
        return -1;
    }

    p = der;
    ret = mbedtls_asn1_get_tag(&p, der + file_len, &octet_len,
                               MBEDTLS_ASN1_OCTET_STRING);
    if (ret != 0 || octet_len != buffer_len ||
        p + octet_len != der + file_len) {
        free(der);
        return -1;
    }

    memcpy(buffer, p, buffer_len);
    free(der);
    return 0;
}

#endif /* MBEDTLS_ASN1_WRITE_C */
