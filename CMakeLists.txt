cmake_minimum_required(VERSION 3.11)
project(uvsocks5)
add_subdirectory(libuv)
set(UV_PATH libuv)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-long-long -pedantic")
include_directories(
    ${UV_PATH}/include
    ${PROJECT_SOURCE_DIR}
)

set(POLARIS_SRC
    server.c
    utils.c
    handshake.c
    palloc.c
)
add_executable(uvsocks5 ${POLARIS_SRC})
target_link_libraries(uvsocks5 uv_a)