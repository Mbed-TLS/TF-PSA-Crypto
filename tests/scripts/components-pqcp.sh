# components-pqcp.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### PQCP Testing
################################################################

support_test_pqcp_mldsa_native_upstream_all () {
    python3 -c 'import sys; exit(1 if sys.version_info < (3, 9) else 0)'
}

component_test_pqcp_mldsa_native_upstream_all () {
    msg "test: mldsa-native upstream all --opt ALL --examples"
     cd drivers/pqcp/mldsa-native
    ./scripts/tests all --opt ALL --examples
}
