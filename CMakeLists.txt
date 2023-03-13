cmake_minimum_required(VERSION 3.24)
project(browser)

set(CMAKE_CXX_STANDARD 23)

add_executable(browser socket.h main.cpp include/expected.hpp)

add_executable(example_server socket.h examples/server.cpp)
add_executable(example_talker socket.h examples/talker.cpp)
add_executable(example_listener socket.h examples/listener.cpp)
add_executable(example_client socket.h examples/client.cpp)

find_package(OpenSSL REQUIRED)

add_executable(secure socket.h secure/secure.cpp)
target_link_libraries(secure OpenSSL::SSL)