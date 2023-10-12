#!/usr/bin/env python3

"""TF-PSA-Crypto repository update from Mbed TLS
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
import pathlib
import re
import shutil
import stat

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
    include_tf_psa_crypto_path = os.path.join(psa_crypto_root_path, "include", "tf_psa_crypto")

    include_files = filter(lambda file_: not re.match(
                           "x509.*|mps.*|ssl.*|padlock\.*|pkcs7.*|"\
                           "\.gitignore|debug\.h|net_sockets\.h|"\
                           "hkdf\.h", file_),
                           os.listdir(source_path))
    for file_ in include_files:
        shutil.copy2(os.path.join(source_path, file_), destination_path)

    ## Overwrite Mbed TLS default configuration file with the TF-PSA-Crypto
    ## repository specific one.
    shutil.copy2(os.path.join(builtin_path, "mbedtls_config.h"), destination_path)

    if os.path.isfile(os.path.join(source_path, "lms.h")):
        shutil.copy2(os.path.join(source_path, "lms.h"), include_tf_psa_crypto_path)

def copy_from_library(mbedtls_root_path, psa_crypto_root_path):
    builtin_path = os.path.join(psa_crypto_root_path, "drivers", "builtin")
    library_files = filter(lambda file_: not re.match(
                           ".*\.o|x509.*|mps.*|ssl.*|padlock\.*|pkcs7.*|"\
                           "\.gitignore|Makefile|CMakeLists\.txt|"\
                           "debug\.c|error\.c|net_sockets\.c|hkdf.c|"\
                           "psa_crypto_core_common\.h"\
                           "", file_),
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
                              "check_crypto_config.h" ]

    for file_ in psa_crypto_core_files:
        shutil.move(os.path.join(builtin_path, "src", file_),
                    os.path.join(psa_crypto_root_path, "core", file_))

    shutil.copy2(os.path.join(mbedtls_root_path, "library", "alignment.h"),
                 os.path.join(psa_crypto_root_path, "core"))

def copy_from_scripts(mbedtls_root_path, psa_crypto_root_path):
    source_path = os.path.join(mbedtls_root_path, "scripts")
    destination_path = os.path.join(psa_crypto_root_path, "scripts")

    shutil.copytree(os.path.join(source_path, "data_files", "driver_jsons"),
                    os.path.join(destination_path, "data_files", "driver_jsons"),
                    dirs_exist_ok=True)
    shutil.copytree(os.path.join(source_path, "data_files", "driver_templates"),
                    os.path.join(destination_path, "data_files", "driver_templates"),
                    dirs_exist_ok=True)

    shutil.copy2(os.path.join(source_path, "generate_driver_wrappers.py"), destination_path)
    shutil.copy2(os.path.join(source_path, "generate_psa_constants.py"), destination_path)
    shutil.copy2(os.path.join(source_path, "output_env.sh"), destination_path)
    shutil.copy2(os.path.join(source_path, "config.py"), destination_path)
    shutil.copy2(os.path.join(source_path, "min_requirements.py"), destination_path)

    for path in pathlib.Path(source_path).glob("*.requirements.txt"):
        shutil.copy2(str(path), destination_path)

    shutil.copytree(os.path.join(source_path, "mbedtls_dev"),
                    os.path.join(destination_path, "mbedtls_dev"), dirs_exist_ok=True)

def copy_from_tests(mbedtls_root_path, psa_crypto_root_path):
    source_path = os.path.join(mbedtls_root_path, "tests")
    destination_path = os.path.join(psa_crypto_root_path, "tests")

    ## tests/include
    include_source_path = os.path.join(source_path, "include")
    include_destination_path = os.path.join(destination_path, "include")
    if not os.path.exists(include_destination_path):
        os.mkdir(include_destination_path)

    ## tests/include/spe
    shutil.copytree(os.path.join(include_source_path, "spe"),
                    os.path.join(include_destination_path, "spe"),
                    dirs_exist_ok=True)

    ## tests/include/test
    include_test_source_path = os.path.join(include_source_path, "test")
    include_test_destination_path = os.path.join(include_destination_path, "test")
    if not os.path.exists(include_test_destination_path):
        os.mkdir(include_test_destination_path)

    include_test_files = filter(lambda file_:
                                os.path.isfile(os.path.join(include_test_source_path, file_))
                                and
                                (not re.match( ".*cert.*|.*ssl.*", file_)),
                                os.listdir(include_test_source_path))
    for file_ in include_test_files:
        shutil.copy2(os.path.join(include_test_source_path, file_),
                     os.path.join(include_test_destination_path, file_))

    ## tests/include/test/drivers
    shutil.copytree(os.path.join(include_test_source_path, "drivers"),
                    os.path.join(include_test_destination_path, "drivers"),
                    dirs_exist_ok=True)

    ## tests/scripts
    scripts_source_path = os.path.join(source_path, "scripts")
    scripts_destination_path = os.path.join(destination_path, "scripts")
    if not os.path.exists(scripts_destination_path):
        os.mkdir(scripts_destination_path)

    scripts_files = filter(lambda file_: re.match(
                           "all.sh|"\
                           "analyze_outcomes.py|"\
                           "check_test_cases.py|"\
                           "generate_bignum_tests.py|"\
                           "generate_ecp_tests.py|"\
                           "generate_psa_tests.py|"\
                           "generate_test_code.py|"\
                           "scripts_path.py|"\
                           "test_generate_test_code.py|"\
                           "test_psa_compliance.py",
                           file_), os.listdir(scripts_source_path))
    for file_ in scripts_files:
        shutil.copy2(os.path.join(scripts_source_path, file_),
                     os.path.join(scripts_destination_path, file_))

    ## tests/src
    src_source_path = os.path.join(source_path, "src")
    src_destination_path = os.path.join(destination_path, "src")
    if not os.path.exists(src_destination_path):
        os.mkdir(src_destination_path)

    src_files = filter(lambda file_: not re.match(
                       ".*cert.*|"\
                       "drivers|"\
                       ".*ssl.*|"\
                       "test_helpers",
                       file_), os.listdir(src_source_path))
    for file_ in src_files:
        shutil.copy2(os.path.join(src_source_path, file_),
                     os.path.join(src_destination_path, file_))

    ## tests/src/drivers
    shutil.copytree(os.path.join(src_source_path, "drivers"),
                    os.path.join(src_destination_path, "drivers"),
                    dirs_exist_ok=True)

    ## tests/suites
    suites_files = filter(lambda file_: not re.match(
                          "test_suite_x509.*|"\
                          "test_suite_net.*|"\
                          "test_suite_mps.*|"\
                          "test_suite_ssl.*|"\
                          "test_suite_debug.*|"\
                          "test_suite_error.*|"\
                          "test_suite_version.*|"\
                          "test_suite_timing.*|"\
                          "test_suite_platform.*|"\
                          "test_suite_pkcs7.*|"\
                          "test_suite_hkdf.*|"\
                          "test_suite_psa_crypto_se_driver.*",
                          file_), os.listdir(os.path.join(source_path, "suites")))
    for file_ in suites_files:
        shutil.copy2(os.path.join(source_path, "suites", file_),
                     os.path.join(destination_path, "suites", file_))

    ## tests/data_files
    shutil.copytree(os.path.join(source_path, "data_files"),
                    os.path.join(destination_path, "data_files"))

def copy_from_programs(mbedtls_root_path, psa_crypto_root_path):
    programs_psa_files = filter(lambda file_: not re.match("CMakeLists\.txt|Makefile", file_),
                                os.listdir(os.path.join(mbedtls_root_path, "programs", "psa")))
    for file_ in programs_psa_files:
        shutil.copy2(os.path.join(mbedtls_root_path, "programs", "psa", file_),
                     os.path.join(psa_crypto_root_path, "programs", "psa"))

def copy_from_docs(mbedtls_root_path, psa_crypto_root_path):
    source_path = os.path.join(mbedtls_root_path, "docs", "architecture")
    destination_path = os.path.join(psa_crypto_root_path, "docs", "architecture")
    shutil.copy2(os.path.join(source_path, "psa-crypto-implementation-structure.md"), destination_path)

    source_path = os.path.join(mbedtls_root_path, "docs", "proposed")
    destination_path = os.path.join(psa_crypto_root_path, "docs", "proposed")
    shutil.copy2(os.path.join(source_path, "psa-conditional-inclusion-c.md"), destination_path)
    shutil.copy2(os.path.join(source_path, "psa-driver-interface.md"), destination_path)

def replace_all_sh_components(psa_crypto_root_path):
    tests_scripts_path = os.path.join(psa_crypto_root_path, "tests", "scripts")
    shutil.move(os.path.join(tests_scripts_path, "all.sh"),
                os.path.join(tests_scripts_path, "all.sh.bak"))

    before_components = 1
    in_components = 0
    after_components = 0
    components_start = re.compile(r"#### Basic checks")
    components_end = re.compile(r"#### Termination")

    with open(os.path.join(tests_scripts_path, "all.sh"), 'x') as new_all_sh, \
         open(os.path.join(tests_scripts_path, "all.sh.bak"), 'rt') as all_sh:
        for line in all_sh:
            if before_components:
                if components_start.match(line) != None:
                    new_all_sh.write("### PSA cryptography test components\n")
                    new_all_sh.write("################################################################\n\n")

                    with open(os.path.join(psa_crypto_root_path, "tests", "all_sh_components.txt"), 'rt') as components:
                        for line in components:
                            new_all_sh.write(line)
                    before_components = 0
                    in_components = 1
                else:
                    new_all_sh.write(line)

            if in_components:
                if components_end.match(line) != None:
                    in_components = 0
                    after_components = 1
                    new_all_sh.write("\n################################################################\n")

            if after_components:
                new_all_sh.write(line)

    os.chmod(os.path.join(tests_scripts_path, "all.sh"), stat.S_IEXEC | stat.S_IREAD | stat.S_IWRITE)

def extend_config_psa(psa_crypto_root_path):
    include_mbedtls_path = os.path.join(psa_crypto_root_path, "drivers", "builtin", "include", "mbedtls")
    shutil.move(os.path.join(include_mbedtls_path, "config_psa.h"),
                os.path.join(include_mbedtls_path, "config_psa.h.bak"))

    include_mbedtls_config_adjust_legacy_from_psa = re.compile("#include \"mbedtls/config_adjust_legacy_from_psa.h\"")

    with open(os.path.join(include_mbedtls_path, "config_psa.h"), 'x') as new_config_psa, \
         open(os.path.join(include_mbedtls_path, "config_psa.h.bak"), 'rt') as config_psa:
        for line in config_psa:
            new_config_psa.write(line)
            if include_mbedtls_config_adjust_legacy_from_psa.match(line) != None:
                new_config_psa.write("#include \"mbedtls/config_adjust_mbedtls_from_tf_psa_crypto.h\"\n")

def main():
    parser = argparse.ArgumentParser(
        description=(
            """This script is for copying the PSA cryptography implementation
            of Mbed TLS into the TF-PSA-Crypto repository. Note: must be run
            from the TF-PSA-Crypto repository root."""
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
    replace_all_sh_components(os.getcwd())
    extend_config_psa(os.getcwd())

if __name__ == "__main__":
    main()
