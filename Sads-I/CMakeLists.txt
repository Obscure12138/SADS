cmake_minimum_required(VERSION 3.1)
project(SaDedup_v1)

set(CMAKE_CXX_STANDARD 11)

set(EXECUTABLE_OUTPUT_PATH ${SaDedup_v1_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${SaDedup_v1_SOURCE_DIR}/lib)

add_subdirectory(src)