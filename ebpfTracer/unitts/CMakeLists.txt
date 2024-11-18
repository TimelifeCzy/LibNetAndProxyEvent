cmake_minimum_required (VERSION 3.22.0)

project(ebpftrace VERSION 1.0)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

include_directories("../")
include_directories("../../include/")

LINK_DIRECTORIES("../../lib/")
LINK_DIRECTORIES("../../lib/bpf/")

# exec build bpf
add_executable (ebpftrace   "../Utiliy.h" "UnitTest.cpp" )

target_link_libraries(ebpftrace libbpf.a libebpftrace.a elf z )
target_link_libraries(ebpftrace pthread dl)

# add_definitions(-D_GLIBCXX_USE_CXX11_ABI=0)
