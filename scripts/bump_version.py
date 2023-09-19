#!/usr/bin/env python3

"""
This script sets the PSA Crypto version and SO version to the specified
values.
"""

# Copyright The PSA Crypto Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import re
import sys

def bump_versions(new_version, new_soversion):
    CMAKE_VERSION_REGEX = \
        re.compile('(set\(PSA_CRYPTO_VERSION )[0-9]+\.[0-9]+\.[0-9]+(\))')
    CMAKE_SOVERSION_REGEX = re.compile('(set\(PSA_CRYPTO_SOVERSION )[0-9]+(\))')
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
    with open('tests/suites/test_suite_psa_crypto_version.data', 'r') as f:
        version_test = f.read()

    version_test = re.sub(TEST_VERSION_REGEX, '\g<1>' + new_version + '\g<2>', version_test)

    with open('tests/suites/test_suite_psa_crypto_version.data', 'w') as f:
        f.write(version_test)


# Get new version and SO version
parser = argparse.ArgumentParser()
parser.add_argument('--version', required=True,
                    help='New PSA Crypto version number, (e.g. 1.2.3)')
parser.add_argument('--so-version', required=False,
                    help='New PSA Crypto shared object version, (e.g. 5)')
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
