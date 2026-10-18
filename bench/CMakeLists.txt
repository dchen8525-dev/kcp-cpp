# Throughput tools. Not part of the library and not part of ctest: these are the measuring sticks
# the P6/P7 gates quote, so they stay reproducible instead of being one-off scripts.

add_executable(aes_bench aes_bench.cc)
target_link_libraries(aes_bench PRIVATE kcp::kcp)
if(MSVC)
  target_compile_options(aes_bench PRIVATE /W4 /permissive- /utf-8)
else()
  target_compile_options(aes_bench PRIVATE -Wall -Wextra -Wpedantic)
endif()

# KCP state machine only: two instances pumped in one thread, no sockets and no threads. This is the
# attribution tool for §6.3 - when session throughput is below the Go baseline, it says whether the
# protocol engine or the I/O pipeline is responsible.
add_executable(kcp_pump kcp_pump.cc)
target_link_libraries(kcp_pump PRIVATE kcp::kcp)
if(MSVC)
  target_compile_options(kcp_pump PRIVATE /W4 /permissive- /utf-8)
else()
  target_compile_options(kcp_pump PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Platform calibration: one cross-thread datagram round trip, no KCP. Gives §6.3 the host's thread
# wake cost, which is the constant any window-limited stream is divided by.
add_executable(udp_pingpong udp_pingpong.cc)
target_link_libraries(udp_pingpong PRIVATE kcp::kcp)
if(MSVC)
  target_compile_options(udp_pingpong PRIVATE /W4 /permissive- /utf-8)
else()
  target_compile_options(udp_pingpong PRIVATE -Wall -Wextra -Wpedantic)
endif()
