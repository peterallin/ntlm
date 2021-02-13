cmake_minimum_required(VERSION 3.16)
project(ntlm)

set(OPENSSL_USE_STATIC_LIBS ON )
find_package(OpenSSL REQUIRED )

set(ntlm_sources
  src/ntlm.cpp
  src/util.cpp
  include/ntlm/ntlm.h
  src/util.h
)

add_library(${PROJECT_NAME} ${ntlm_sources})

target_compile_options(${PROJECT_NAME}
    PRIVATE
        -Werror
)

target_include_directories(${PROJECT_NAME} BEFORE
    PUBLIC
        "${PROJECT_SOURCE_DIR}/include"

    PRIVATE
        "${OPENSSL_INCLUDE_DIR}"
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        "${OPENSSL_LIBRARIES}"
)


add_library(${PROJECT_NAME}_hacked_for_tests  ${ntlm_sources})
target_compile_options(${PROJECT_NAME}_hacked_for_tests PRIVATE -Werror)

target_include_directories(${PROJECT_NAME}_hacked_for_tests BEFORE
  PUBLIC
  "${PROJECT_SOURCE_DIR}/include"

  PRIVATE
  "${OPENSSL_INCLUDE_DIR}"
  )

target_link_libraries(${PROJECT_NAME}_hacked_for_tests
  PUBLIC
  "${OPENSSL_LIBRARIES}"
  )

target_compile_definitions(${PROJECT_NAME}_hacked_for_tests PRIVATE USE_HACKS_FOR_REPEATABLE_TESTS)


add_subdirectory(test)


