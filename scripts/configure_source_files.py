#!/usr/bin/env python3

"""Fill in files with the version information extracted from CMakeLists.txt.

Currently only supports include/tf_psa_crypto/version.h.
"""

# Copyright The Mbed TLS Contributors
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
import os
import re
from typing import Dict, Pattern


class Configurator:
    """Populate template files in a format that's a subset of CMake's configure_file."""

    @staticmethod
    def _find_matching_line(filename: str, regex: Pattern) -> bytes:
        for line in open(filename, 'rb'):
            m = regex.match(line)
            if m:
                return m.group(1)
        raise Exception('No line matching {} found in {}'
                        .format(regex, filename))

    def __init__(self, cmakelists: str,
                 project_name: str,
                 variable_prefix: str) -> None:
        """Read information from the given CMakeLists.txt file."""
        set_version_re = re.compile(rb'\s*set\s*\(' +
                                    re.escape(project_name.encode()) +
                                    rb'_VERSION\s+(.*?)\s*\)')
        version_string = self._find_matching_line(cmakelists, set_version_re)
        numbers_re = re.compile(rb'([0-9]+)\.([0-9]+)\.([0-9]+)')
        m = numbers_re.match(version_string)
        if not m:
            raise Exception('Version string "{}" does not have the expected format'
                            .format(version_string.decode()))
        self.variables = {} #type: Dict[bytes, bytes]
        prefix = variable_prefix.encode() + b'_VERSION_'
        for suffix, value in zip((b'MAJOR', b'MINOR', b'PATCH'),
                                 m.groups()):
            self.variables[prefix + suffix] = value
        self.variable_re = re.compile(rb'@(' +
                                      rb'|'.join(self.variables.keys()) +
                                      rb')@')

    def process_file(self, source_file: str, target_file: str) -> None:
        """Fill the given templated files."""
        with open(target_file, 'wb') as out:
            for _num, line in enumerate(open(source_file, 'rb'), 1):
                line = re.sub(self.variable_re,
                              lambda m: self.variables[m.group(1)],
                              line)
                out.write(line)

    def run(self, source_root: str, target_root: str) -> None:
        """Fill templated files under source_root.

        The output goes under the target_root directory.
        """
        for path in [
                'include/tf_psa_crypto/version.h',
        ]:
            self.process_file(source_root + '/' + path + '.in',
                              target_root + '/' + path)


def main() -> None:
    """Process the command line and generate output files."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cmakelists', '-c',
                        default='CMakeLists.txt',
                        help='CMakeLists.txt containing the version information')
    parser.add_argument('--directory', '-d',
                        default=os.curdir,
                        help='Root directory of the output tree (default: current directory)')
    parser.add_argument('--project-name',
                        default='TF_PSA_CRYPTO',
                        help='Project name in CMakeLists.txt')
    parser.add_argument('--variable-prefix',
                        default='TF-PSA-Crypto',
                        help='Prefix for the variables containing version numbers')
    parser.add_argument('--source', '-s',
                        default=os.curdir,
                        help='Root directory of the source tree (default: current directory)')
    options = parser.parse_args()
    configurator = Configurator(options.cmakelists,
                                options.project_name, options.variable_prefix)
    configurator.run(options.source, options.directory)

if __name__ == '__main__':
    main()
