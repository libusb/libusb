macro(add_libusb_example TARGET_NAME TARGET_SOURCES)
    add_executable(${TARGET_NAME} ${TARGET_SOURCES})
    target_include_directories(${TARGET_NAME} PRIVATE ../libusb)
    target_link_libraries(${TARGET_NAME} lib/libusb-1.0)
    set_target_properties(${TARGET_NAME}
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endmacro(add_libusb_example)

# HotplugTest
add_libusb_example(hotplugtest hotplugtest.c)

# building the getopt libaray
include(CheckIncludeFiles)
CHECK_INCLUDE_FILES(string.h HAVE_STRING_H)
if(HAVE_STRING_H)
    add_definitions(-DHAVE_STRING_H)
endif(HAVE_STRING_H)
add_library(getopt STATIC
    getopt/getopt.c
    getopt/getopt1.c
)

# fxload
set(FXLOAD_SOURCES 
    ezusb.c
    fxload.c
)
add_libusb_example(fxload "${FXLOAD_SOURCES}")
target_include_directories(fxload PRIVATE "getopt/")
target_link_libraries(fxload getopt)

# list dev
add_libusb_example(listdev listdevs.c)

# test libusb
add_libusb_example(testlibusb testlibusb.c)

# xusb
add_libusb_example(xusb xusb.c)
