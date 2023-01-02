cmake_minimum_required(VERSION 3.24)
project(browser)

set(CMAKE_CXX_STANDARD 20)

add_executable(browser main.cpp socket.h socket.cpp)
