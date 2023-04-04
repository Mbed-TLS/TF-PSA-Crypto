#!/usr/bin/env python3

"""PSA-Crypto repository update from Mbed TLS
"""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0
##
## Licensed under the Apache License, Version 2.0 (the "License"); you may
## not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
## WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

import argparse
import os
import re
import shutil
from distutils.dir_util import copy_tree

def copy_of_psa_headers(mbedtls_root_path, psa_crypto_root_path):
    source_path = os.path.join(mbedtls_root_path, "include", "psa")
    destination_path = os.path.join(psa_crypto_root_path, "include", "psa")
    include_files = filter(lambda file_: not re.match("build_info\.h|crypto_config\.h", file_),
                           os.listdir(source_path))
    for file_ in include_files:
        shutil.copy2(os.path.join(source_path, file_), destination_path)

def copy_of_mbedtls_headers(mbedtls_root_path, psa_crypto_root_path):
    source_path = os.path.join(mbedtls_root_path, "include", "mbedtls")
    builtin_path = os.path.join(psa_crypto_root_path, "drivers", "builtin")
    destination_path = os.path.join(builtin_path, "include", "mbedtls")

    include_files = filter(lambda file_: not re.match(
                           "x509.*|mps.*|ssl.*|\.gitignore|debug\.h|net_sockets\.h", file_),
                           os.listdir(source_path))
    for file_ in include_files:
        shutil.copy2(os.path.join(source_path, file_), destination_path)

    ## Overwrite Mbed TLS default configuration file with the PSA-Crypto
    ## repository specific one.
    shutil.copy2(os.path.join(builtin_path, "mbedtls_config.h"), destination_path)


def copy_from_library(mbedtls_root_path, psa_crypto_root_path):
    builtin_path = os.path.join(psa_crypto_root_path, "drivers", "builtin")
    library_files = filter(lambda file_: not re.match(
                           ".*\.o|x509.*|mps.*|ssl.*|\.gitignore|Makefile|CMakeLists\.txt|"\
                           "debug\.c|error\.c|net_sockets\.c"\
                           "psa_crypto_core_common\.h", file_),
                           os.listdir(os.path.join(mbedtls_root_path, "library")))

    for file_ in library_files:
        shutil.copy2(os.path.join(mbedtls_root_path, "library", file_),
                     os.path.join(builtin_path, "src"))

    psa_crypto_core_files = [ "psa_crypto.c",
                              "psa_crypto_client.c",
                              "psa_crypto_core.h",
                              "psa_crypto_invasive.h",
                              "psa_crypto_its.h",
                              "psa_crypto_random_impl.h",
                              "psa_crypto_se.c",
                              "psa_crypto_se.h",
                              "psa_crypto_slot_management.c",
                              "psa_crypto_slot_management.h",
                              "psa_crypto_storage.c",
                              "psa_crypto_storage.h",
                              "psa_its_file.c",
                              "psa_crypto_driver_wrappers.h",
                              "check_crypto_config.h" ]

    for file_ in psa_crypto_core_files:
        shutil.move(os.path.join(builtin_path, "src", file_),
                    os.path.join(psa_crypto_root_path, "core", file_))

    shutil.copy2(os.path.join(mbedtls_root_path, "library", "alignment.h"),
                 os.path.join(psa_crypto_root_path, "core"))

def copy_from_scripts(mbedtls_root_path, psa_crypto_root_path):
    source_path = os.path.join(mbedtls_root_path, "scripts")
    destination_path = os.path.join(psa_crypto_root_path, "scripts")

    copy_tree(os.path.join(source_path, "data_files", "driver_jsons"),
              os.path.join(destination_path, "data_files", "driver_jsons"))
    copy_tree(os.path.join(source_path, "data_files", "driver_templates"),
              os.path.join(destination_path, "data_files", "driver_templates"))

    shutil.copy2(os.path.join(source_path, "generate_driver_wrappers.py"), destination_path)
    shutil.copy2(os.path.join(source_path, "generate_psa_constants.py"), destination_path)

    copy_tree(os.path.join(source_path, "mbedtls_dev"),
              os.path.join(destination_path, "mbedtls_dev"))

def copy_from_tests(mbedtls_root_path, psa_crypto_root_path):
    source_path = os.path.join(mbedtls_root_path, "tests")
    destination_path = os.path.join(psa_crypto_root_path, "tests")

    shutil.copy2(os.path.join(source_path, "seedfile"), destination_path)

    copy_tree( os.path.join( source_path, "include" ),
               os.path.join( destination_path, "include" ) )

    copy_tree( os.path.join( source_path, "scripts" ),
               os.path.join( destination_path, "scripts" ) )

    copy_tree( os.path.join( source_path, "src" ),
               os.path.join( destination_path, "src" ) )

    tests_suites_files = filter(lambda file_: re.match(
                                "test_suite_psa_crypto.*|helpers\.function|"\
                                "host_test\.function|main_test\.function", file_),
                                os.listdir(os.path.join(source_path, "suites")))
    for file_ in tests_suites_files:
        shutil.copy2(os.path.join(source_path, "suites", file_),
                     os.path.join(destination_path, "suites", file_))

def copy_from_programs(mbedtls_root_path, psa_crypto_root_path):
    programs_psa_files = filter(lambda file_: not re.match("CMakeLists\.txt|Makefile", file_),
                                os.listdir(os.path.join(mbedtls_root_path, "programs", "psa")))
    for file_ in programs_psa_files:
        shutil.copy2(os.path.join(mbedtls_root_path, "programs", "psa", file_),
                     os.path.join(psa_crypto_root_path, "programs", "psa"))

def copy_from_docs(mbedtls_root_path, psa_crypto_root_path):
    source_path = os.path.join(mbedtls_root_path, "docs", "proposed")
    destination_path = os.path.join(psa_crypto_root_path, "docs", "proposed")
    shutil.copy2(os.path.join(source_path, "psa-conditional-inclusion-c.md"), destination_path)
    shutil.copy2(os.path.join(source_path, "psa-driver-interface.md"), destination_path)

def main():
    parser = argparse.ArgumentParser(
        description=(
            """This script is for copying the PSA cryptography implementation
            of Mbed TLS into the PSA-Crypto repository. Note: must be run from
            the PSA-Crypto repository root."""
        )
    )
    parser.add_argument(
        "--mbedtls", type=str, default="../mbedtls",
        help="path to the Mbed TLS root directory, default is ../mbedtls",
    )

    args = parser.parse_args()
    if not os.path.isdir(args.mbedtls):
        print("Error: {} is not an existing directory".format(args.mbedtls))
        parser.exit()

    mbedtls_root_path = os.path.abspath(args.mbedtls)

    copy_of_psa_headers(mbedtls_root_path, os.getcwd())
    copy_of_mbedtls_headers(mbedtls_root_path, os.getcwd())
    copy_from_library(mbedtls_root_path, os.getcwd())
    copy_from_scripts(mbedtls_root_path, os.getcwd())
    copy_from_tests(mbedtls_root_path, os.getcwd())
    copy_from_programs(mbedtls_root_path, os.getcwd())
    copy_from_docs(mbedtls_root_path, os.getcwd())

if __name__ == "__main__":
    main()
