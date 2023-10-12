file(GLOB psa_headers "psa/*.h")
file(GLOB tf_psa_crypto_headers "tf_psa_crypto/*.h")

# Do not install the default configuration file as a specific one may have
# been defined through the TF_PSA_CRYPTO_CONFIG_FILE cached variable.
list(REMOVE_ITEM psa_headers "${CMAKE_CURRENT_SOURCE_DIR}/psa/crypto_config.h")

install(FILES ${psa_headers}
    DESTINATION include/psa
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(FILES ${tf_psa_crypto_headers}
    DESTINATION include/tf_psa_crypto
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
