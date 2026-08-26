# libprot — Android native protection core (EXTENSION_PLAN A1)
# Build via NDK + CMake. 在已装 NDK 的环境构建:
#   cmake -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21 \
#         -DCMAKE_TOOLCHAIN_FILE=<ndk>/build/cmake/android.toolchain.cmake .
#   cmake --build .
cmake_minimum_required(VERSION 3.18)
project(libprot C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# libprot.so (native 核心)
add_library(prot SHARED
    libprot.c
    ../license_auth_common.c
)

# 运行时目标 (测试用, 不加 JNI)
add_executable(prot_test
    prot_test.c
    ../license_auth_common.c
)

# DER 公钥 (vmenc.py keygen --blob-out-der 生成) — 若未生成则跳过
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/prot_pubkey_der.c")
    target_sources(prot PRIVATE prot_pubkey_der.c)
endif()

target_compile_options(prot PRIVATE -fvisibility=hidden -ffunction-sections)
target_link_options(prot PRIVATE -Wl,--gc-sections)