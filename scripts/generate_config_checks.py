#!/usr/bin/env python3

"""Generate C preprocessor code to check for bad configurations.
"""

from typing import Iterator

import framework_scripts_path # pylint: disable=unused-import
from mbedtls_framework.config_checks_generator import * \
    #pylint: disable=wildcard-import,unused-wildcard-import
from mbedtls_framework import config_history

ALWAYS_ENABLED_SINCE_1_0 = frozenset([
    'MBEDTLS_PSA_CRYPTO_CONFIG',
    'MBEDTLS_USE_PSA_CRYPTO',
])

def checkers_for_removed_options() -> Iterator[Checker]:
    """Discover removed options. Yield corresponding checkers."""
    history = config_history.ConfigHistory()
    old_public = history.options('mbedtls', '3.6')
    new_public = (history.options('tfpsacrypto', '1.0') |
                  history.options('mbedtls', '4.0'))
    internal = history.internal('tfpsacrypto', '1.0')
    for option in sorted(old_public - new_public):
        if option in ALWAYS_ENABLED_SINCE_1_0:
            continue
        if option in internal:
            yield Internal(option)
        else:
            yield Removed(option, 'TF-PSA_Crypto 1.0')

def all_checkers() -> Iterator[Checker]:
    """Yield all checkers."""
    yield from checkers_for_removed_options()

CRYPTO_CHECKS = BranchData(
    header_directory='core',
    header_prefix='tf_psa_crypto_',
    project_cpp_prefix='TF_PSA_CRYPTO',
    checkers=list(all_checkers()),
)

if __name__ == '__main__':
    main(CRYPTO_CHECKS)
