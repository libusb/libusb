macro(add_libusb_test TARGET_NAME TARGET_SOURCES)
    add_executable(${TARGET_NAME} ${TARGET_SOURCES})
    target_include_directories(${TARGET_NAME} PRIVATE . ../libusb)
    target_link_libraries(${TARGET_NAME} LibUsb)
    set_target_properties(${TARGET_NAME}
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME} WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endmacro(add_libusb_test)

# Stress
set(STRESS_SOURCES
    stress.c
    testlib.c
)
add_libusb_test(stress "${STRESS_SOURCES}")
