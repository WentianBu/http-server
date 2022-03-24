cmake_minimum_required(VERSION 3.4)
set (CMAKE_C_COMPILER "clang")
set (CMAKE_CXX_COMPILER "clang++")

project (http-server)
aux_source_directory (src SRC_FILES)
set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build)

set (CMAKE_C_FLAGS "-Wall")
set (CMAKE_CXX_FLAGS "-Wall -std=c++11")

set (CMAKE_BUILD_TYPE "Debug")
set (CMAKE_C_FLAGS_DEBUG "-O0 -g")
set (CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
set (CMAKE_C_FLAGS_RELEASE "-O3")
set (CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake/modules)
find_package(OpenSSL REQUIRED)
find_package(Libevent REQUIRED)
find_package(Zlog REQUIRED)
find_package(Threads REQUIRED)
find_package(nlohmann_json REQUIRED)


add_executable (server ${SRC_FILES})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries (server OpenSSL::SSL)
target_link_libraries(server OpenSSL::Crypto)
target_link_libraries(server libevent::core)
target_link_libraries(server libevent::extra)
target_link_libraries(server libevent::openssl)
target_link_libraries(server zlog)
target_link_libraries(server Threads::Threads)
target_link_libraries(server nlohmann_json::nlohmann_json)