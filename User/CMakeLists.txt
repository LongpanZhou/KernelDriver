cmake_minimum_required(VERSION 3.31)
project(User)

set(CMAKE_CXX_STANDARD 23)

add_executable(User main.cpp
)

target_link_options(User PRIVATE
        -static-libstdc++     # Link libc++ statically
        -static               # Static link everything
)