file(GLOB mbedtls_headers "mbedtls/*.h")

install(FILES ${mbedtls_headers}
    DESTINATION include/mbedtls
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
