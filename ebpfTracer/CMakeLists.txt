cmake_minimum_required (VERSION 3.28.0)

project(ebpftrace VERSION 1.0)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

include_directories("../include/")

LINK_DIRECTORIES("../lib/")
LINK_DIRECTORIES("../lib/bpf/")

# 将源代码添加到此项目的可执行文件。
add_executable (ebpftrace "main.cpp" "Utiliy.h" )

target_link_libraries(ebpftrace libbpf.a)
target_link_libraries(ebpftrace pthread dl)

add_definitions(-D_GLIBCXX_USE_CXX11_ABI=0)
