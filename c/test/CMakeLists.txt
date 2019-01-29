cmake_minimum_required(VERSION 3.2)

include_directories(${confidentiality_SOURCE_DIR}/src)
link_directories(${confidentiality_BINARY_DIR})

add_executable(test_authentication test.c test_authentication.c)
add_test(NAME authentication COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_authentication)

if("${confidentiality_BACKEND}" STREQUAL MBEDTLS)
    target_link_libraries(test_authentication mbedtls)
elseif("${confidentiality_BACKEND}" STREQUAL OpenSSL)
    target_link_libraries(test_authentication ssl crypto)
endif()
target_link_libraries(test_authentication libconfidentiality)