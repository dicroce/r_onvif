cmake_minimum_required(VERSION 3.14)
set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 1)
project(r_onvif VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH})

include(r_build.txt)
include(FetchContent)

find_package(PkgConfig)
pkg_search_module(libxml-2.0 REQUIRED IMPORTED_TARGET libxml-2.0)

FetchContent_Declare(
    r_utils
    GIT_REPOSITORY https://github.com/dicroce/r_utils.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(r_utils)

FetchContent_Declare(
    r_http
    GIT_REPOSITORY https://github.com/dicroce/r_http.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(r_http)

add_library(
    r_onvif
    include/r_onvif/r_onvif_session.h
    source/r_onvif_session.cpp
)

target_include_directories(
    r_onvif PUBLIC 
    include
    ${r_utils_SOURCE_DIR}/include
    ${r_http_SOURCE_DIR}/include
    ${libxml-2.0_STATIC_INCLUDE_DIRS}
)

target_link_directories(
    r_onvif PUBLIC 
    ${r_utils_BUILD_DIR}
    ${r_http_BUILD_DIR}
    ${libxml-2.0_STATIC_LIBRARY_DIRS}
)

target_link_libraries(
    r_onvif 
    r_http
    r_utils
    ${libxml-2.0_STATIC_LIBRARIES}
)

add_subdirectory(ut)
