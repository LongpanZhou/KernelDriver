cmake_minimum_required(VERSION 3.22)
project(Driver)

# Clang-specific size optimizations
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Oz -flto -ffunction-sections -fdata-sections -fno-exceptions -fno-rtti -fno-unwind-tables -fno-asynchronous-unwind-tables -g0 -nostdlib")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add custom module path if needed
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/vendor/")
find_package(WDK REQUIRED)

# Driver entry point
wdk_add_driver(Driver
        main.cpp
)

# Per-target compile and link options
target_compile_options(Driver PRIVATE
        -Oz                       # Optimize for size aggressively
        -flto                     # Enable Link-Time Optimization
        -ffunction-sections       # Place each function in its own section
        -fdata-sections           # Place each data item in its own section
        -fno-exceptions           # Disable exception handling (not supported in kernel)
        -fno-rtti                 # Disable RTTI (not needed)
        -fno-unwind-tables        # Don't generate unwind tables
        -fno-asynchronous-unwind-tables  # Avoid async unwind info (reduces size)
        -g0                       # No debug info
        -nostdlib                 # Don't use standard libraries
)

target_link_options(Driver PRIVATE
        -Wl,--gc-sections         # Remove unused sections
        -Wl,--strip-all           # Strip all symbol info
        -flto                     # LTO for cross-module optimization
)

# Code signing (optional)
add_custom_command(TARGET Driver POST_BUILD
        COMMAND "C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x86/signtool.exe"
        sign /v
        /f ${CMAKE_CURRENT_SOURCE_DIR}/TestSign.pfx
        /p 1234
        /t http://timestamp.digicert.com
        /fd sha256
        "${CMAKE_BINARY_DIR}/Driver.sys"
)