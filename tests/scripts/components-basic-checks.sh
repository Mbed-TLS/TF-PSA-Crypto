# components-basic-checks.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Basic checks
################################################################

component_tf_psa_crypto_check_files () {
    msg "Check: file sanity checks (permissions, encodings)" # < 1s
    $FRAMEWORK/scripts/check_files.py
}

components_tf_psa_crypto_check_python_files () {
    msg "Lint: Python scripts"
    $FRAMEWORK/scripts/check-python-files.sh
}
