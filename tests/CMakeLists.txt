# Tests share loopback ports, so every test runs serially (PORTING-PLAN.md #31).

function(kcp_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE kcp::kcp)
  target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  if(MSVC)
    target_compile_options(${name} PRIVATE /W4 /permissive- /utf-8)
  else()
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES
    RUN_SERIAL TRUE
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
endfunction()

kcp_add_test(smoke_socket_test smoke_socket_test.cc)
kcp_add_test(vector_meta_test vector_meta_test.cc json_reader.cc)
target_compile_definitions(vector_meta_test PRIVATE
  KCP_VECTOR_DIR="${CMAKE_SOURCE_DIR}/tools/golden/out")

kcp_add_test(foundation_test foundation_test.cc)
kcp_add_test(entropy_test entropy_test.cc)

kcp_add_test(primitives_test primitives_test.cc json_reader.cc)
target_compile_definitions(primitives_test PRIVATE
  KCP_VECTOR_DIR="${CMAKE_SOURCE_DIR}/tools/golden/out")

kcp_add_test(aes_test aes_test.cc)
kcp_add_test(gcm_test gcm_test.cc)
kcp_add_test(salsa20_test salsa20_test.cc)

kcp_add_test(crypt_test crypt_test.cc json_reader.cc)
target_compile_definitions(crypt_test PRIVATE
  KCP_VECTOR_DIR="${CMAKE_SOURCE_DIR}/tools/golden/out")
