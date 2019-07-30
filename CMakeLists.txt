cmake_minimum_required(VERSION 3.14)
project(availability_checker)

set(CMAKE_CXX_STANDARD 17)

add_executable(availability_checker main.cpp)

if(WIN32)
    target_link_libraries(availability_checker wsock32 ws2_32)
endif()