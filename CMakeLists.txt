cmake_minimum_required(VERSION 3.18)

set(LIB_NAME promsrv)

project(${LIB_NAME} C)

set(CMAKE_C_STANDARD 11)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
        message(STATUS "Build type is not defined, set default one")
        set(CMAKE_BUILD_TYPE "Debug")
endif()

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
        pkg_search_module(LIBEVENT_PTHREADS libevent_pthreads )
        if(!LIBEVENT_FOUND)
                message(FATAL_ERROR "libevent_pthreads is not found" )
        endif()
endif()

add_library(${LIB_NAME} promsrv.c promsrv.h)

target_compile_options(${LIB_NAME} PRIVATE -Wall)
target_compile_options(${LIB_NAME} PRIVATE -Wextra)
# target_compile_options(${LIB_NAME} PRIVATE -Wno-unused-parameter)
# target_compile_options(${LIB_NAME} PRIVATE -Wno-unused-function)

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        target_compile_options(${LIB_NAME} PRIVATE -g3)
        target_compile_options(${LIB_NAME} PRIVATE -ggdb3)
        target_compile_options(${LIB_NAME} PRIVATE -gdwarf-4)
        target_compile_options(${LIB_NAME} PRIVATE -O0)
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release")
        target_compile_options(${LIB_NAME} PRIVATE -O2)
endif()

target_link_libraries(${LIB_NAME} ${LIBEVENT_PTHREADS_LIBRARIES} pthread)
