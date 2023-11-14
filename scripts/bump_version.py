#!/usr/bin/env python3

"""
This script sets the TF-PSA-Crypto version and SO version to the specified
values.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import os
import re
import sys

# Note: This function is duplicated from scripts/mbedtls_dev/build_tree.py
# so that this script may be run in the development branch and does not rely
# on Mbed TLS. Once the TF-PSA-Crypto repository is no longer downstream from
# Mbed TLS this script should be changed to import this function from mbedtls_dev
def looks_like_tf_psa_crypto_root(path: str) -> bool:
    """Whether the given directory looks like the root of the TF-PSA-Crypto source tree."""
    return all(os.path.isdir(os.path.join(path, subdir))
               for subdir in ['include', 'core', 'drivers', 'programs', 'tests'])

def bump_versions(new_version, new_soversion):
    CMAKE_VERSION_REGEX = \
        re.compile('(set\(TF_PSA_CRYPTO_VERSION )[0-9]+\.[0-9]+\.[0-9]+(\))')
    CMAKE_SOVERSION_REGEX = re.compile('(set\(TF_PSA_CRYPTO_SOVERSION )[0-9]+(\))')
    TEST_VERSION_REGEX = re.compile('(check_compiletime_version:").*(")')

    # Bump version in CMakeLists.txt
    with open('CMakeLists.txt', 'r') as f:
        cmake = f.read()

    cmake = re.sub(CMAKE_VERSION_REGEX, '\g<1>' + new_version + '\g<2>', cmake)

    if new_soversion is not None:
        cmake = re.sub(CMAKE_SOVERSION_REGEX, '\g<1>' + new_soversion + '\g<2>', cmake)

    with open('CMakeLists.txt', 'w') as f:
        f.write(cmake)

    # Bump version in test suite
    with open('tests/suites/test_suite_tf_psa_crypto_version.data', 'r') as f:
        version_test = f.read()

    version_test = re.sub(TEST_VERSION_REGEX, '\g<1>' + new_version + '\g<2>', version_test)

    with open('tests/suites/test_suite_tf_psa_crypto_version.data', 'w') as f:
        f.write(version_test)

# Check if we are running from the project root
current_dir = os.getcwd()
if not looks_like_tf_psa_crypto_root(current_dir):
    print('Error: This script must be run from the TF-PSA-Crypto root directory')
    sys.exit(1)

# Get new version and SO version
parser = argparse.ArgumentParser()
parser.add_argument('--version', required=True,
                    help='New TF-PSA-Crypto version number, (e.g. 1.2.3)')
parser.add_argument('--so-version', required=False,
                    help='New TF-PSA-Crypto shared object version, (e.g. 5)')
args = parser.parse_args()

# Validate arguments
error_msgs = ''
if not re.fullmatch('[0-9]+\.[0-9]+\.[0-9]+', args.version):
    error_msgs += '\nError: Version number must be in the form X.Y.Z where X Y and Z are numbers'
if (args.so_version is not None) and (not re.fullmatch('[0-9]+', args.so_version)):
    error_msgs += '\nError: SO version number must be a single number'

if error_msgs != '':
    parser.print_help()
    print(error_msgs)
    sys.exit(1)

bump_versions(args.version, args.so_version)
