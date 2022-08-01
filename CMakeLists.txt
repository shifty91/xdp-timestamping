#
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2022 Linutronix GmbH
#
cmake_minimum_required(VERSION 3.2)
project(xdp-timestamping)

find_package(PkgConfig REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -pedantic -Wall")
set(THREADS_PREFER_PTHREAD_FLAG ON)

include_directories("src")

add_executable(xdp_timestamping src/xdp_timestamping.c)

pkg_search_module(LIBBPF libbpf REQUIRED)
pkg_search_module(LIBXDP libxdp REQUIRED)

target_link_directories(xdp_timestamping PRIVATE ${LIBBPF_LIBRARY_DIRS})
target_include_directories(xdp_timestamping PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(xdp_timestamping ${LIBBPF_LIBRARIES})
target_link_directories(xdp_timestamping PRIVATE ${LIBXDP_LIBRARY_DIRS})
target_include_directories(xdp_timestamping PRIVATE ${LIBXDP_INCLUDE_DIRS})
target_link_libraries(xdp_timestamping ${LIBXDP_LIBRARIES})

execute_process(COMMAND uname -m OUTPUT_VARIABLE BUILD_ARCH ERROR_QUIET)
string(STRIP "${BUILD_ARCH}" BUILD_ARCH)
set(ASM_INCLUDE "/usr/include/${BUILD_ARCH}-linux-gnu")
set(CLANG_FLAGS -S -target bpf -D __BPF_TRACING__ -Wall -O2 -emit-llvm -g -I ${ASM_INCLUDE})
set(LLC_FLAGS -march=bpf -filetype=obj)

add_custom_target(xdp_timestamping_prog_stage1 ALL
  COMMAND clang ${CLANG_FLAGS} -c -o xdp_kern_timestamping.ll xdp_kern_timestamping.c
  DEPENDS xdp_timestamping
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
  SOURCES src/xdp_kern_timestamping.c
)
add_custom_target(xdp_timestamping_prog_stage2 ALL
  COMMAND llc ${LLC_FLAGS} -o ${CMAKE_BINARY_DIR}/xdp_kern_timestamping.o xdp_kern_timestamping.ll
  DEPENDS xdp_timestamping_prog_stage1
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
  SOURCES src/xdp_kern_timestamping.c
)
