cmake_minimum_required(VERSION 3.16)
project(sctp_interop CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(sctp_cpp_server server.cpp)

add_executable(sctp_cpp_client client.cpp)
