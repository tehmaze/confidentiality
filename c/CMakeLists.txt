cmake_minimum_required(VERSION 3.2)

# Modules
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(CheckFunctionExistsMayNeedLibrary)
include(Hex)

# Project
project(confidentiality VERSION 0.1.0)

# Compiler
if (CMAKE_VERSION VERSION_LESS "3.1")
  if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set (CMAKE_C_FLAGS "--std=gnu99 ${CMAKE_C_FLAGS}")
  endif()
else()
  set (CMAKE_C_STANDARD 99)
endif()

# Build options
option(STATIC          "Build static library"           OFF)
option(WITHOUT_MALLOC  "Avoid malloc() where possible"  OFF)

## Cryptography backend choice

set(CRYPTO_BACKEND
  ""
  CACHE
  STRING
  "The backend to use for cryptography: mbedTLS or OpenSSL or empty to try any available")

# Version
math(EXPR PROJECT_VERSION_NUMBER "(${PROJECT_VERSION_MAJOR} << 16) + (${PROJECT_VERSION_MINOR} << 8) + (${PROJECT_VERSION_PATCH})")
to_hex(${PROJECT_VERSION_NUMBER} PROJECT_VERSION_NUMBER 6)

# Dependancies
# If the crypto backend was given, rather than searching for the first
# we are able to find, the find_package commands must abort configuration
# and report to the user.
if(CRYPTO_BACKEND)
  set(SPECIFIC_CRYPTO_REQUIREMENT REQUIRED)
endif()

if(CRYPTO_BACKEND STREQUAL "mbedTLS" OR NOT CRYPTO_BACKEND)
    find_package(mbedTLS ${SPECIFIC_CRYPTO_REQUIREMENT})
    if(MBEDTLS_FOUND)
        set(CRYPTO_BACKEND "mbedTLS")
        set(CRYPTO_SOURCES src/backend/mbedtls.c)
        list(APPEND PRIVATE_COMPILE_DEFINITIONS CONFIDENTIALITY_USE_MBEDTLS)
        list(APPEND PRIVATE_INCLUDE_DIRECTORIES ${MBEDTLS_INCLUDE_DIR})
        list(APPEND LIBRARIES ${MBEDTLS_LIBRARIES})
        list(APPEND PC_LIBS -lmbedcrypto)
        link_directories(${MBEDTLS_LIBRARY_DIR})
    endif()
endif()

if(CRYPTO_BACKEND STREQUAL "OpenSSL" OR NOT CRYPTO_BACKEND)
    find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})
    if(OPENSSL_FOUND)
        set(CRYPTO_BACKEND "OpenSSL")
        set(CRYPTO_SOURCES src/backend/openssl.c)
        list(APPEND PRIVATE_COMPILE_DEFINITIONS CONFIDENTIALITY_USE_OPENSSL)
        list(APPEND PRIVATE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
        list(APPEND LIBRARIES ${OPENSSL_LIBRARIES})
        list(APPEND PC_REQUIRES_PRIVATE libssl libcrypto)

        # Not all OpenSSL have AES-CTR functions.
        set(SAVE_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
        set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
        check_function_exists(EVP_aes_128_ctr HAVE_EVP_AES_128_CTR)
        check_function_exists(EVP_aes_192_ctr HAVE_EVP_AES_192_CTR)
        check_function_exists(EVP_aes_256_ctr HAVE_EVP_AES_256_CTR)
        check_function_exists(EVP_aes_128_gcm HAVE_EVP_AES_128_GCM)
        check_function_exists(EVP_aes_192_gcm HAVE_EVP_AES_192_GCM)
        check_function_exists(EVP_aes_256_gcm HAVE_EVP_AES_256_GCM)
        set(CMAKE_REQUIRED_LIBRARIES ${SAVE_CMAKE_REQUIRED_LIBRARIES})
    endif()
endif()

if(NOT CRYPTO_BACKEND)
    message(FATAL_ERROR "No suitable cryptography backend found.")
endif()

string(TOUPPER ${CRYPTO_BACKEND} CRYPTO_BACKEND_UPPER)

# Additional defines
if (${WITHOUT_MALLOC})
    add_definitions(-DWITHOUT_MALLOC=1)
endif()
include_directories(${PROJECT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/src)

# Headers
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/confidentiality.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/src/confidentiality.h @ONLY)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/backend.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/src/backend.h)
    
# Library definition
set(SOURCES
    ${CRYPTO_SOURCES}
    src/internal/compare.c
    src/internal/x25519.c
    src/confidentiality.c
)

add_library(libconfidentiality SHARED ${SOURCES})
set_target_properties(libconfidentiality PROPERTIES PREFIX "")
target_compile_definitions(libconfidentiality PRIVATE ${PRIVATE_COMPILE_DEFINITIONS})
target_include_directories(libconfidentiality
  PRIVATE "${PROJECT_SOURCE_DIR}/src/" ${PRIVATE_INCLUDE_DIRECTORIES}
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>)

# Linker
if(CMAKE_VERSION VERSION_LESS "2.8.12")
  # Fall back to over-linking dependencies
  target_link_libraries(libconfidentiality ${LIBRARIES})
else()
  target_link_libraries(libconfidentiality PRIVATE ${LIBRARIES})
endif()

# Install
install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/src/confidentiality.h 
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/confidentiality.h)

# Tests
enable_testing()
add_subdirectory(test)