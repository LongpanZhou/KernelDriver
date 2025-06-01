cmake_minimum_required(VERSION 3.22)
project(Driver)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/vendor/")
find_package(WDK REQUIRED)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

wdk_add_driver(Driver KMDF 1.00
        main.cpp
)

target_compile_options(Driver PRIVATE
        -O3
)

add_custom_command(TARGET Driver POST_BUILD
        COMMAND "C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x86/signtool.exe"
        sign /v
        /f ${CMAKE_CURRENT_SOURCE_DIR}/TestSign.pfx
        /p 1234
        /t http://timestamp.digicert.com
        /fd sha256
        "${CMAKE_BINARY_DIR}/Driver.sys"
)