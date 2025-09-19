#!/usr/bin/env python3

"""Generate C preprocessor code to check for bad configurations.
"""

import framework_scripts_path # pylint: disable=unused-import
from mbedtls_framework.config_checks_generator import * \
    #pylint: disable=wildcard-import,unused-wildcard-import

CRYPTO_CHECKS = BranchData(
    header_directory='core',
    header_prefix='tf_psa_crypto_',
    project_cpp_prefix='TF_PSA_CRYPTO',
    checkers=[
        Internal('MBEDTLS_MD_SOME_LEGACY'),
        Internal('MBEDTLS_MD_SOME_PSA'),
        Removed('MBEDTLS_PADLOCK_C', 'TF-PSA-Crypto 1.0'),
    ],
)

if __name__ == '__main__':
    main(CRYPTO_CHECKS)
