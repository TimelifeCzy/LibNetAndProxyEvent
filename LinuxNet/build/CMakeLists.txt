# CMakeList.txt: LinuxNet 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

project(unixpory VERSION 1.0)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)

include_directories("/libevent/libproxyevent/boost/")
LINK_DIRECTORIES("/libevent/libproxyevent/boost/stage/lib/")

# 将源代码添加到此项目的可执行文件。
add_executable (unixpory "../LinuxNet.cpp" "../LinuxNet.h")

target_link_libraries(unixpory libboost_system.a libboost_thread.a)
target_link_libraries(unixpory pthread)


