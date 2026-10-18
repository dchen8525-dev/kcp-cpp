#!/usr/bin/env bash
# Build + test on Linux (Ninja + GCC/Clang). Usage: ./build.sh [Debug|Release]
set -euo pipefail

CONFIG="${1:-Debug}"
cd "$(dirname "$0")"

if [ "$CONFIG" = "Release" ]; then
  PRESET="linux-x64-release"
  BUILD_PRESET="linux-x64-release"
  TEST_PRESET="linux-x64-release"
else
  PRESET="linux-x64"
  BUILD_PRESET="linux-x64-debug"
  TEST_PRESET="linux-x64-debug"
fi

echo "[kcp-cpp] configure + build ($CONFIG)"
cmake --preset "$PRESET"
cmake --build --preset "$BUILD_PRESET"

echo "[kcp-cpp] ctest ($CONFIG)"
ctest --preset "$TEST_PRESET"

echo "[kcp-cpp] OK"
