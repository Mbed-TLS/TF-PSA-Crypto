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
    msg "test: mldsa-native upstream all --opt ALL --examples --stack"
    cd drivers/pqcp/mldsa-native
    ./scripts/tests all --opt ALL --examples --stack --alloc

    make clean

    msg "test: mldsa-native upstream all --opt ALL --stack with custom heap allocation"
    ./scripts/tests all --opt ALL --stack --no-examples --no-alloc --no-rng-fail \
        --cflags='-std=c11 -D_GNU_SOURCE -Itest -DMLD_CONFIG_FILE=\"configs/custom_heap_alloc_config.h\"'
}
