This directory contains example configuration files.

The examples are generally focused on a particular usage case (eg, support for
a restricted number of cryptographic mechanisms) and aim at minimizing resource
usage for this target. They can be used as a basis for custom configurations.

These files are complete replacements for the default crypto_config.h. To use one of
them, you can pick one of the following methods:

1. Replace the default file include/psa/crypto_config.h with the chosen one.

2. Define TF_PSA_CRYPTO_CONFIG_FILE and adjust the include path accordingly.
   For example, using cmake:

    find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
    CFLAGS="-I$PWD/configs -DCRYPTO_CONFIG_FILE='<foo.h>'" cmake .
    make

Note that the second method also works if you want to keep your custom
configuration file outside the TF-PSA-Crypto tree.
