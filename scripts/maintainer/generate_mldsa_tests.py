#!/usr/bin/env python3
"""Generate ML-DSA test cases.
"""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import sys
from typing import List

import maintainer_scripts_path # pylint: disable=unused-import
from mbedtls_framework import test_data_generation
from mbedtls_maintainer import mldsa_test_generator


class MLDSADispatchGenerator(mldsa_test_generator.DispatchGenerator):
    """Generate dispatch tests with TF-PSA-Crypto dependencies."""

    def multipart_dependencies(self, key: mldsa_test_generator.Key,
                               type_is_pair: bool) -> List[str]:
        dependencies = super().multipart_dependencies(key, type_is_pair)

        if type_is_pair:
            dependencies.append('PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR')

        return dependencies


class MLDSATestGenerator(test_data_generation.TestGenerator):
    """Generate test cases for ML-DSA."""

    def __init__(self, settings) -> None:
        self.targets = {
            'test_suite_pqcp_mldsa.dilithium_py': mldsa_test_generator.gen_pqcp_mldsa_all,
            'test_suite_psa_crypto_mldsa.dilithium_py': \
            lambda: mldsa_test_generator.DriverGenerator(
                private_key_formats=[
                    mldsa_test_generator.PrivateKeyFormat.SEED,
                    mldsa_test_generator.PrivateKeyFormat.SEED_PLUS_EXPANDED,
                ],
            ).gen_all(
                multipart=True,
            ),
            'test_suite_dispatch_transparent.dilithium_py': \
            lambda: MLDSADispatchGenerator().gen_all(
                multipart=True,
            )
        }
        super().__init__(settings)


if __name__ == '__main__':
    test_data_generation.main(sys.argv[1:], __doc__, MLDSATestGenerator)
