cmake_minimum_required(VERSION 3.20)

project(kcp_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Keep artifacts in predictable places across generators.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Sources are listed explicitly (no GLOB): a missing file must fail the build, not be silently
# skipped. Each stage of PORTING-PLAN.md appends to this list.
set(KCP_SOURCES
  src/crypt.cc
  src/error.cc
  src/kcp.cc
  src/listener.cc
  src/udp_session.cc
  src/internal/aes.cc
  src/internal/bufferpool.cc
  src/internal/cfb.cc
  src/internal/clock.cc
  src/internal/fec.cc
  src/internal/frame.cc
  src/internal/galois.cc
  src/internal/gcm.cc
  src/internal/primitives.cc
  src/internal/rate_limiter.cc
  src/internal/rs.cc
  src/internal/salsa20.cc
  src/internal/tea.cc
  src/internal/timedsched.cc
  src/platform/entropy_backend.cc
  src/platform/profile.cc
  src/platform/socket.cc
  src/snmp.cc
)

add_library(kcp STATIC ${KCP_SOURCES})
add_library(kcp::kcp ALIAS kcp)

target_include_directories(kcp
  PUBLIC  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)

if(WIN32)
  # ws2_32: WinSock2; bcrypt: BCryptGenRandom (platform/entropy_backend).
  target_link_libraries(kcp PRIVATE ws2_32 bcrypt)
  target_compile_definitions(kcp PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(kcp PUBLIC Threads::Threads)
endif()

if(MSVC)
  target_compile_options(kcp PRIVATE /W4 /permissive- /utf-8)
  target_compile_definitions(kcp PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(kcp PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  include(CTest)
  if(BUILD_TESTING)
    add_subdirectory(tests)
  endif()
  # Echo tools (examples/) and the measuring sticks (bench/): the C++ half of the throughput
  # baseline in PORTING-PLAN.md §6.3 and the C++ side of the P7 cross-language matrix.
  add_subdirectory(examples)
  add_subdirectory(bench)
endif()
