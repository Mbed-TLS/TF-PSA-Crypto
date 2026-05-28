Features
   * PSA hash, MAC and XOF functions no longer use intermediate buffers on
     the heap for their inputs and outputs, even when
     MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS is disabled. Fixes #795.
