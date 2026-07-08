#ifndef TF_PSA_CRYPTO_PROGRAMS_ASN1_FILE_IO_H
#define TF_PSA_CRYPTO_PROGRAMS_ASN1_FILE_IO_H

#include <stddef.h>
#include <stdint.h>

int asn1_write_octet_string_file(const char *path,
                                 const uint8_t *buffer,
                                 size_t buffer_len);

int asn1_read_octet_string_file(const char *path,
                                uint8_t *buffer,
                                size_t buffer_len);
#endif
