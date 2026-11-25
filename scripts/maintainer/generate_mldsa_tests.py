#!/usr/bin/env python3
"""Generate ML-DSA test cases.
"""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import sys
from typing import Callable, Optional, Sequence, Tuple

import maintainer_scripts_path # pylint: disable=unused-import
from mbedtls_framework import test_case, test_data_generation
from mbedtls_maintainer import mldsa_test_generator

class DriverGenerator(mldsa_test_generator.DriverGenerator):
    """Generate driver test cases with temporary ML-DSA key-pair dependencies."""
    def one_mldsa_export_public_key(self, key: mldsa_test_generator.Key,
                                    pkf: mldsa_test_generator.PrivateKeyFormat, descr: str
                                    ) -> test_case.TestCase:
        tc = super().one_mldsa_export_public_key(key, pkf, descr)
        tc.dependencies.append('PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC')
        return tc

    def one_mldsa_sign_deterministic_pure(self, key: mldsa_test_generator.Key,
                                          pkf: mldsa_test_generator.PrivateKeyFormat,
                                          message: bytes, descr: str
                                          ) -> test_case.TestCase:
        tc = super().one_mldsa_sign_deterministic_pure(key, pkf, message, descr)
        tc.dependencies.append('PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC')
        return tc

    def one_multipart(self, function: str, key: mldsa_test_generator.Key,
                      lengths: Sequence[int],
                      pkf_described:
                      Tuple[Optional[mldsa_test_generator.PrivateKeyFormat], str] = (None, ''),
                      tweak_signature: Optional[Callable[[bytes], Tuple[bytes, str, str]]] = None
                      ) -> test_case.TestCase:
        tc = super().one_multipart(function, key, lengths, pkf_described, tweak_signature)
        if function == 'sign_deterministic':
            tc.dependencies.append('PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC')
        return tc

class DispatchGenerator(mldsa_test_generator.DispatchGenerator):
    """Generate dispatch test cases with temporary ML-DSA key-pair dependencies."""
    def one_mldsa_export_public_key(self, key: mldsa_test_generator.Key,
                                    pkf: mldsa_test_generator.PrivateKeyFormat, descr: str
                                    ) -> test_case.TestCase:
        tc = super().one_mldsa_export_public_key(key, pkf, descr)
        tc.dependencies.append('PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC')
        return tc

    def one_mldsa_sign_deterministic_pure(self, key: mldsa_test_generator.Key,
                                          pkf: mldsa_test_generator.PrivateKeyFormat,
                                          message: bytes, descr: str
                                          ) -> test_case.TestCase:
        tc = super().one_mldsa_sign_deterministic_pure(key, pkf, message, descr)
        tc.dependencies.append('PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC')
        return tc

    def one_multipart(self, function: str, key: mldsa_test_generator.Key,
                      lengths: Sequence[int],
                      pkf_described:
                      Tuple[Optional[mldsa_test_generator.PrivateKeyFormat], str] = (None, ''),
                      tweak_signature: Optional[Callable[[bytes], Tuple[bytes, str, str]]] = None
                      ) -> test_case.TestCase:
        tc = super().one_multipart(function, key, lengths, pkf_described, tweak_signature)
        if function == 'sign_deterministic':
            tc.dependencies.append('PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC')
        return tc

class MLDSATestGenerator(test_data_generation.TestGenerator):
    """Generate test cases for ML-DSA."""

    def __init__(self, settings) -> None:
        self.targets = {
            'test_suite_pqcp_mldsa.dilithium_py': mldsa_test_generator.gen_pqcp_mldsa_all,
            'test_suite_psa_crypto_mldsa.dilithium_py': \
            lambda: DriverGenerator(
                private_key_formats=[
                    mldsa_test_generator.PrivateKeyFormat.SEED,
                    mldsa_test_generator.PrivateKeyFormat.SEED_PLUS_EXPANDED,
                ],
            ).gen_all(
                multipart=True,
            ),
            'test_suite_dispatch_transparent.dilithium_py': \
            lambda: DispatchGenerator().gen_all(
                multipart=True,
            )
        }
        super().__init__(settings)


if __name__ == '__main__':
    test_data_generation.main(sys.argv[1:], __doc__, MLDSATestGenerator)
