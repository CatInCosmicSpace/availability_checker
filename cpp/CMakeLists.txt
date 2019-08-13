cmake_minimum_required(VERSION 3.14)
project(availability_checker)

set(THREADS_PREFER_PTHREAD_FLAG ON)
include_directories(${CMAKE_SOURCE_DIR}/include)
link_directories(${CMAKE_SOURCE_DIR}/lib)
#find_package (Threads)
set(CMAKE_CXX_STANDARD 17)

add_executable(availability_checker main.cpp)
# ${CMAKE_THREAD_LIBS_INIT}
#set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")
#set(CMAKE_SHARED_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")
if(WIN32)
    target_link_libraries(availability_checker -static libssl.a libcrypto.a wsock32 ws2_32 )
endif()