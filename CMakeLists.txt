﻿cmake_minimum_required(VERSION 3.12)
project(mqtt_sudh2 LANGUAGES CXX)

# Compiler options and flags
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default build type (Release if not specified)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Common compiler flags
add_compile_options(
    -Wall
    -Wextra
    -pthread
)

# Build-type specific flags
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -DDEBUG -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

# Find required dependencies
find_package(OpenSSL REQUIRED)

# Main executable source file (fix: make sure this file exists)
add_executable(${PROJECT_NAME}
    mqtt_sudh2.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)

# Installation configuration
include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Test target
add_custom_target(test
    COMMAND $<TARGET_FILE:${PROJECT_NAME}> test
    DEPENDS ${PROJECT_NAME}
    COMMENT "Running tests"
)

# Performance test target
add_custom_target(perf
    COMMAND $<TARGET_FILE:${PROJECT_NAME}> perf
    DEPENDS ${PROJECT_NAME}
    COMMENT "Running performance tests"
)

# Config target
add_custom_target(config
    COMMAND $<TARGET_FILE:${PROJECT_NAME}> config
    DEPENDS ${PROJECT_NAME}
    COMMENT "Running configuration"
)

# Valgrind target
find_program(VALGRIND valgrind)
if(VALGRIND)
    add_custom_target(valgrind
        COMMAND ${VALGRIND} --leak-check=full --show-leak-kinds=all $<TARGET_FILE:${PROJECT_NAME}>
        DEPENDS ${PROJECT_NAME}
        COMMENT "Running valgrind memory check"
    )
else()
    message(WARNING "valgrind not found - valgrind target will not be available")
endif()

# Static analysis target
find_program(CPPCHECK cppcheck)
if(CPPCHECK)
    add_custom_target(static-analysis
        COMMAND ${CPPCHECK} --enable=all --std=c++17 ${CMAKE_CURRENT_SOURCE_DIR}/mqtt_sudh2.cpp
        COMMENT "Running static analysis"
    )
else()
    message(WARNING "cppcheck not found - static-analysis target will not be available")
endif()

# Format target
find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
    add_custom_target(format
        COMMAND ${CLANG_FORMAT} -i ${CMAKE_CURRENT_SOURCE_DIR}/mqtt_sudh2.cpp
        COMMENT "Formatting source code"
    )
else()
    message(WARNING "clang-format not found - format target will not be available")
endif()

# Service file generation
add_custom_target(install-service
    COMMAND ${CMAKE_COMMAND} -E echo_append "[Unit]\nDescription=Enterprise MQTT Server\nAfter=network.target\n\n[Service]\nType=simple\nUser=mqtt\nGroup=mqtt\nWorkingDirectory=/opt/mqtt-server\nExecStart=/opt/mqtt-server/${PROJECT_NAME}\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n" > mqtt-server.service
    COMMENT "Generating systemd service file: mqtt-server.service"
)

# Clean additional files
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${EXTRA_CLEAN_FILES}")

set(EXTRA_CLEAN_FILES
    mqtt_server.conf
    users.txt
    mqtt-server.service
)

# Dependencies installation helper
add_custom_target(install-deps
    COMMAND sudo apt-get update && sudo apt-get install -y build-essential libssl-dev
    COMMENT "Installing build dependencies"
)
