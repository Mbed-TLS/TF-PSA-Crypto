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
import stat
import re
import shutil

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
                           "x509.*|mps.*|ssl.*|base64\.*|nist_kw\.*|pem\.*|padlock\.*|pkcs.*|"\
                           "\.gitignore|debug\.h|net_sockets\.h"\
                           "", file_),
                           os.listdir(source_path))
    for file_ in include_files:
        shutil.copy2(os.path.join(source_path, file_), destination_path)

    ## Overwrite Mbed TLS default configuration file with the PSA-Crypto
    ## repository specific one.
    shutil.copy2(os.path.join(builtin_path, "mbedtls_config.h"), destination_path)


def copy_from_library(mbedtls_root_path, psa_crypto_root_path):
    builtin_path = os.path.join(psa_crypto_root_path, "drivers", "builtin")
    library_files = filter(lambda file_: not re.match(
                           ".*\.o|x509.*|mps.*|ssl.*|base64\.*|nist_kw\.*|pem\.*|padlock\.*|pkcs.*|"\
                           "\.gitignore|Makefile|CMakeLists\.txt|"\
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

    shutil.copytree(os.path.join(source_path, "mbedtls_dev"),
                    os.path.join(destination_path, "mbedtls_dev"), dirs_exist_ok=True)

def copy_from_tests(mbedtls_root_path, psa_crypto_root_path):
    source_path = os.path.join(mbedtls_root_path, "tests")
    destination_path = os.path.join(psa_crypto_root_path, "tests")

    shutil.copy2(os.path.join(source_path, "seedfile"), destination_path)

    shutil.copytree(os.path.join(source_path, "include"),
                    os.path.join(destination_path, "include"),
                    dirs_exist_ok=True)

    shutil.copytree(os.path.join(source_path, "scripts"),
                    os.path.join(destination_path, "scripts"),
                    dirs_exist_ok=True)

    shutil.copytree(os.path.join(source_path, "src"),
                    os.path.join(destination_path, "src"),
                    dirs_exist_ok=True)

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

    if_defined_mbedtls_psa_crypto_config_file = re.compile("#if defined\(MBEDTLS_PSA_CRYPTO_CONFIG_FILE\)")
    include_mbedtls_psa_crypto_config_file = re.compile("#include MBEDTLS_PSA_CRYPTO_CONFIG_FILE")
    ext_placeholder = re.compile(".*BELOW THIS LINE - PLACEHOLDER FOR PSA-CRYPTO ADDITIONAL CONFIG OPTIONS TRANSLATION")
    endif_mbedtls_psa_crypto_config = re.compile("#endif /\* MBEDTLS_PSA_CRYPTO_CONFIG \*/")

    with open(os.path.join(include_mbedtls_path, "config_psa.h"), 'x') as new_config_psa, \
         open(os.path.join(include_mbedtls_path, "config_psa.h.bak"), 'rt') as config_psa:

        for line in config_psa:
            if if_defined_mbedtls_psa_crypto_config_file.match(line) != None:
                new_config_psa.write("#if defined(PSA_CRYPTO_CONFIG_FILE)\n")
            elif include_mbedtls_psa_crypto_config_file.match(line) != None:
                new_config_psa.write("#include PSA_CRYPTO_CONFIG_FILE\n")
            elif ext_placeholder.match(line) != None:
                break
            else:
                new_config_psa.write(line)

        with open(os.path.join(psa_crypto_root_path, "drivers", "builtin", "config_psa_ext.h"), 'rt') as ext:
            for line in ext:
                new_config_psa.write(line)

        trailer = False
        for line in config_psa:
            if endif_mbedtls_psa_crypto_config.match(line) != None:
                new_config_psa.write("\n")
                trailer = True
            if trailer:
                new_config_psa.write(line)

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
    replace_all_sh_components(os.getcwd())
    extend_config_psa(os.getcwd())

if __name__ == "__main__":
    main()
