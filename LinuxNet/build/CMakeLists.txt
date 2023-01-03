cmake_minimum_required (VERSION 3.8.2)

project(unixpory VERSION 1.0)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

include_directories("/github/libproxyevent/boost/")
LINK_DIRECTORIES("/github/libproxyevent/boost/stage/lib/")

# 将源代码添加到此项目的可执行文件。
add_executable (unixpory "../LinuxNet.cpp" "../LinuxNet.h" "../AsioService.cpp" "../AsioService.h")

target_link_libraries(unixpory libboost_system.a libboost_thread.a)
target_link_libraries(unixpory pthread dl)

add_definitions(-D_GLIBCXX_USE_CXX11_ABI=0)
