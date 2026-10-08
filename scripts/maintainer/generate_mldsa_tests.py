#!/usr/bin/env python3
"""Generate ML-DSA test cases.
"""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import sys
from typing import Iterator

import maintainer_scripts_path # pylint: disable=unused-import
from mbedtls_framework import test_case, test_data_generation
from mbedtls_maintainer import mldsa_test_generator


class MLDSADispatchGenerator(mldsa_test_generator.DispatchGenerator):
    """Generate dispatch tests supported by TF-PSA-Crypto."""

    def gen_multipart(
            self, key: mldsa_test_generator.Key
    ) -> Iterator[test_case.TestCase]:
        for generated_test in super().gen_multipart(key):
            if generated_test.function == 'sign_deterministic_multipart':
                generated_test.skip_because(
                    'ML-DSA key-pair is currently unsupported'
                )
            yield generated_test


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
