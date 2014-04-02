# CMake build script for the cpslib project

# Building:
# > mkdir build && cd build
# > cmake ..
# > cmake --build .

# Install
# > cmake --build . --target install

PROJECT(cpslib)
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckSymbolExists)

CHECK_SYMBOL_EXISTS(strdup string.h HAVE_STRDUP) 
CHECK_SYMBOL_EXISTS(strdup string.h HAVE__STRDUP)
CHECK_SYMBOL_EXISTS(strcpy_s string.h HAVE_STRCPY_S)

configure_file ("${PROJECT_SOURCE_DIR}/config.h.in"
                "${PROJECT_BINARY_DIR}/config.h" )
include_directories(${PROJECT_BINARY_DIR})


string(REGEX MATCH "clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER}")

SET(src
  common.c
  driver.c
) 

IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  SET(OperatingSystem "Mac OS X")


ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  SET(OperatingSystem "Linux")
  LIST(APPEND src pslib_linux.c)

ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

IF(WIN32)
  SET(OperatingSystem "Windows")
  LIST(APPEND src pslib_windows.c)
ENDIF(WIN32)

ADD_EXECUTABLE(driver ${src})

