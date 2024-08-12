
add_executable(
    r_onvif_ut
    include/framework.h
    source/framework.cpp
    include/test_r_onvif.h
    source/test_r_onvif.cpp
)

if(MSVC)
    target_link_options(r_onvif_ut PUBLIC "/STACK:10000000")
endif()

target_include_directories(
    r_onvif_ut PUBLIC 
    include
    ../include
)
target_link_libraries(
    r_onvif_ut LINK_PUBLIC 
    r_onvif
    r_http
    r_utils
)
