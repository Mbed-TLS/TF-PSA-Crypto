#!/bin/sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

. "${0%/*}/../../framework/scripts/demo_common.sh"

msg <<'EOF'
This program demonstrates the use of the PSA cryptography interface to
sign a fixed message.
EOF

depends_on TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED MBEDTLS_ASN1_WRITE_C MBEDTLS_PSA_BUILTIN_GET_ENTROPY

mldsa_export_public="${0%/*}"/mldsa_export_public
mldsa_sign="${0%/*}"/mldsa_sign
mldsa_verify="${0%/*}"/mldsa_verify
files_to_clean="$files_to_clean pubkey.key signature.sig"

"$mldsa_export_public"
"$mldsa_sign"
"$mldsa_verify"

cleanup
