if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY AND
   NOT ${CMAKE_SYSTEM_NAME} MATCHES "[Ww][Ii][Nn]")
    add_executable(dlopen "dlopen.c")
    target_include_directories(dlopen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
    target_include_directories(dlopen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../drivers/builtin/include)
    target_link_libraries(dlopen ${CMAKE_DL_LIBS})
endif()
