cmake_minimum_required(VERSION 3.22)
project(srp6)

set(CMAKE_CXX_STANDARD 17)

add_library(srp6 SHARED libsrp6.cpp BigNum.cpp BigNum.h)
target_link_libraries(srp6 ssl crypto)
install(TARGETS srp6 DESTINATION ${CMAKE_SOURCE_DIR})
