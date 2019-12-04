cmake_minimum_required(VERSION 3.15)
project(Cryptographic_computing)

set(CMAKE_CXX_STANDARD 17)

link_directories(${LIB_PATH})
include_directories(${INCLUDE_PATH})
add_executable(Cryptographic_computing main.cpp circuit.cpp circuit.h subprotocols.h party.h party.cpp)
target_link_libraries(Cryptographic_computing cryptopp)
