cmake_minimum_required(VERSION 3.20)
project(CISBGuard LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find LLVM and Clang
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# 1. LLVM Pass Plugin: libCISBGuard.so
add_library(CISBGuard MODULE
    src/llvm_plugin/CISBGuardPlugin.cpp
    src/llvm_plugin/ScrubGuardPass.cpp
    src/llvm_plugin/UndefFreezePass.cpp
    src/llvm_plugin/CFGVerifyPass.cpp
)

# LLVM passes must be built with RTTI disabled if LLVM was built with -fno-rtti
target_compile_options(CISBGuard PRIVATE -fno-rtti -fPIC)

# On Linux, LLVM pass plugin symbols resolve into opt / clang at runtime
if(NOT APPLE AND NOT WIN32)
    set_target_properties(CISBGuard PROPERTIES
        PREFIX "lib"
        SUFFIX ".so"
    )
endif()

# 2. Clang Tool: ub-check-guard
add_executable(ub-check-guard
    src/clang_tool/UBCheckGuard.cpp
)

target_compile_options(ub-check-guard PRIVATE -fno-rtti)

# Link against Clang and LLVM libraries
# In modern LLVM/Clang distributions, clang-cpp and LLVM cover all tooling symbols
target_link_libraries(ub-check-guard PRIVATE
    clang-cpp
    LLVM
)
