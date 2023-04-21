file(GLOB psa_headers "psa/*.h")

# Do not install the default configuration file as a specific one may have
# been defined through the PSA_CRYPTO_CONFIG_FILE cached variable.
list(REMOVE_ITEM psa_headers "${CMAKE_CURRENT_SOURCE_DIR}/psa/crypto_config.h")

install(FILES ${psa_headers}
    DESTINATION include/psa
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
