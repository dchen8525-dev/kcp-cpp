cmake_minimum_required(VERSION 3.20)

project(kcp_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Keep artifacts in predictable places across generators.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Tooling (echo examples + throughput benchmarks) only makes sense in a standalone
# checkout; package builds (e.g. the vcpkg overlay port in kcp-proxy-cpp) and
# embedders turn it off.
option(KCP_BUILD_TOOLS "Build the examples/ echo tools and bench/ benchmarks" ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

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
          "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
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
  if(KCP_BUILD_TOOLS)
    add_subdirectory(examples)
    add_subdirectory(bench)
  endif()
endif()

# ── Install / package export ──
# Makes the library consumable via `find_package(kcp CONFIG REQUIRED)` — required
# by the vcpkg overlay port in kcp-proxy-cpp and any other embedder. The target
# keeps the name `kcp::kcp` so downstream link code needs no changes.
install(TARGETS kcp EXPORT kcpTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT kcpTargets
  FILE kcpTargets.cmake
  NAMESPACE kcp::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kcp)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/kcpConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/kcpConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kcp)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/kcpConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/kcpConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/kcpConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kcp)
