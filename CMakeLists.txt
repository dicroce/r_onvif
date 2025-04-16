cmake_minimum_required(VERSION 3.28.3)
set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 1)
project(r_onvif VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH})

include(r_build.txt)
include(FetchContent)

find_package(PkgConfig)

FetchContent_Declare(
    r_utils
    GIT_REPOSITORY https://github.com/dicroce/r_utils.git
    GIT_TAG        main
    FIND_PACKAGE_ARGS NAMES r_utils
)
FetchContent_MakeAvailable(r_utils)

FetchContent_Declare(
    r_http
    GIT_REPOSITORY https://github.com/dicroce/r_http.git
    GIT_TAG        main
    FIND_PACKAGE_ARGS NAMES r_http
)
FetchContent_MakeAvailable(r_http)

FetchContent_Declare(
    pugixml
    GIT_REPOSITORY https://github.com/zeux/pugixml.git
    GIT_TAG        v1.15
)

set(PUGIXML_BUILD_SHARED OFF CACHE BOOL "")
set(PUGIXML_INSTALL OFF CACHE BOOL "Disable pugixml install target")

FetchContent_MakeAvailable(pugixml)

add_library(
    r_onvif
    include/r_onvif/r_onvif_session.h
    source/r_onvif_session.cpp
    ${pugixml_SOURCE_DIR}/src/pugixml.cpp
)

target_include_directories(
    r_onvif PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(r_onvif PRIVATE
    ${pugixml_SOURCE_DIR}/src
)

target_link_libraries(
    r_onvif PRIVATE
    r_utils
    r_http
)

option(BUILD_INSTALL_DEV_PACKAGES "Install dev packages for subprojects" OFF)

add_subdirectory(ut)

if(PROJECT_IS_TOP_LEVEL OR BUILD_INSTALL_DEV_PACKAGES)
    configure_dev_package("r_onvif" "A C++ library that does onvif camera discovery and media service discovery.")
endif()
