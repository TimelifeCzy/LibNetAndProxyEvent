cmake_minimum_required (VERSION 3.29.0)

project(traceEngin VERSION 1.0)


include_directories("../../include/")
# set(libbpf_SOURCE_DIR ${CMAKE_BINARY_DIR}/libbpf/src/libbpf)
set(traceEngin_SOURCE_DIR ${CMAKE_SOURCE_DIR}/core)

LINK_DIRECTORIES("../../lib/bpf/")
# target_link_libraries(traceEngin libbpf.a elf z pthread)

# Fetch libbpf
# include(ExternalProject)

# ExternalProject_Add(libbpf
#     GIT_REPOSITORY https://github.com/libbpf/libbpf.git
#     GIT_TAG v1.2.2
#     PREFIX ./libbpf
#     CONFIGURE_COMMAND ""
#     BUILD_COMMAND cd ../libbpf/src && bash -c "CFLAGS=\"-g -O2 -Werror -Wall -fPIC\" make"
#     INSTALL_COMMAND ""
#     )

# set binaries and options for clang and llc
set(CLANG "clang")
set(LLC "llc")
set(CLANG_OPTIONS -Wno-unused-value
                  -Wno-pointer-sign
                  -Wno-compare-distinct-pointer-types
                  -Wno-gnu-variable-sized-type-not-at-end
                  -Wno-address-of-packed-member
                  -Wno-tautological-compare
                  -Wno-unknown-warning-option
                  -g
                  )
set(CLANG_DEFINES -D __KERNEL__
                  -D __BPF_TRACING__
                  -D __TARGET_ARCH_x86
                  -D __linux__
                  )
if (DEBUG_K)
    message("Using DEBUG_K Option...")
    list(APPEND CLANG_DEFINES -DDEBUG_K)
endif()

set(CLANG_INCLUDES
                   -I "/usr/include"
                   -I "/usr/include/x86_64-linux-gnu"
                   -I "${CMAKE_SOURCE_DIR}"
                   -I "${CMAKE_BINARY_DIR}"
                   -I "${libbpf_SOURCE_DIR}/src"
                   )

add_custom_target(traceEngin
                  DEPENDS traceEngin.o
                 )

# add_dependencies(traceEngin libbpf)

add_custom_command(OUTPUT traceEngin.o
                   COMMAND "${CLANG}" -nostdinc -isystem `gcc -print-file-name=include` ${CLANG_INCLUDES} ${CLANG_DEFINES} -O2 ${CLANG_OPTIONS} -target bpf -fno-stack-protector -c "${traceEngin_SOURCE_DIR}/traceEngin.c" -o "traceEngin.o" && bpftool gen object traceEngin.ebpf.o traceEngin.o && bpftool gen skeleton "traceEngin.ebpf.o" name "traceEngin" > "traceEngin.skel.h"
                   COMMENT "Building EBPF object traceEngin.o"
                   DEPENDS ${traceEngin_SOURCE_DIR}/traceEngin.c
                  )

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES traceEngin.ebpf.o)
