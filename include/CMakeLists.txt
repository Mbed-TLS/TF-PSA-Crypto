file(GLOB psa_headers "psa/*.h")

install(FILES ${psa_headers}
    DESTINATION include/psa
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
