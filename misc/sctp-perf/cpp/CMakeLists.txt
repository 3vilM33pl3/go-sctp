cmake_minimum_required(VERSION 3.16)
project(sctp_perf CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(sctp_perf_server perf_server.cpp)
add_executable(sctp_perf_client perf_client.cpp)
