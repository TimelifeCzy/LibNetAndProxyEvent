cmake_minimum_required (VERSION 3.22.0)

project(ebpftrace VERSION 1.0)

# alter exec buildcore
set(DIRECTORY_PATH "/project/LibNetAndProxyEvent/ebpfTracer/buildcore/")
execute_process (COMMAND bash ${DIRECTORY_PATH}clean.sh WORKING_DIRECTORY ${DIRECTORY_PATH})
execute_process (COMMAND bash ${DIRECTORY_PATH}build.sh WORKING_DIRECTORY ${DIRECTORY_PATH})

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE "Debug")
# set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

include_directories("../include/")

LINK_DIRECTORIES("../lib/")
LINK_DIRECTORIES("../lib/bpf/")

# unit test UnitTest.cpp.
add_executable(ebpftrace 
                            "Utiliy.h"
                            "../include/traceEngin.skel.h"
                            "eBPFHlpr.h" "eBPFHlpr.cpp"
                            "eBPFTraceEngine.h" "eBPFTraceEngine.cpp"
                            "eBPFMonitor.h" "eBPFMonitor.cpp" 
                            "TaskHandler.h" "TaskHandler.cpp" 
                            "./unitts/UnitTest.cpp" 
)

# build ebpftrace.a
# add_library(ebpftrace   STATIC 
#                         "Utiliy.h"
#                         "../include/traceEngin.skel.h"
#                         "eBPFHlpr.h" "eBPFHlpr.cpp"
#                         "eBPFTraceEngine.h" "eBPFTraceEngine.cpp"
#                         "eBPFMonitor.h" "eBPFMonitor.cpp" 
#                         "./unitts/UnitTest.cpp" 
# )

# build ebpftrace.so
# add_library(ebpftrace  SHARED
#                        "Utiliy.h"
#                        "../include/traceEngin.skel.h"
#                        "eBPFHlpr.h" "eBPFHlpr.cpp"
#                        "eBPFTraceEngine.h" "eBPFTraceEngine.cpp"
#                        "eBPFMonitor.h" "eBPFMonitor.cpp" 
# )

# set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
# install(TARGETS ebpftrace LIBRARY DESTINATION /usr/local/ebpftrac/lib)
# install(FILES EbpfTraceEngine.h DESTINATION /usr/local/ebpftrace/include)

target_link_libraries(ebpftrace libbpf.a elf z)
target_link_libraries(ebpftrace pthread dl)

add_definitions(-D_GLIBCXX_USE_CXX11_ABI=0)
