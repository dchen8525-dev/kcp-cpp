# Echo example / tooling binaries (PORTING-PLAN.md §2). They double as the C++ half of the
# throughput baseline (§6.3) and as the C++ side of the cross-language matrix (P7).

add_executable(echo_server echo_server.cc echo_common.cc)
add_executable(echo_client echo_client.cc echo_common.cc)

foreach(target echo_server echo_client)
  target_link_libraries(${target} PRIVATE kcp::kcp)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endforeach()
