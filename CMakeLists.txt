cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0079 NEW)

project(lib60870-C LANGUAGES C)

set(LIB_VERSION_MAJOR "2")
set(LIB_VERSION_MINOR "3")
set(LIB_VERSION_PATCH "5")

#================================================================================
# Global Configuration
#================================================================================

option(BUILD_EXAMPLES "Build the examples" ON)
option(BUILD_TESTS "Build the tests" ON)

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'Release' as none was specified.")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

# Force static C runtime on MSVC to prevent conflicts across all targets
if(MSVC)
  # Explicitly ignore conflicting default C runtime libraries for executables
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:LIBCMTD")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /NODEFAULTLIB:LIBCMTD")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /NODEFAULTLIB:LIBCMTD")
    set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "${CMAKE_EXE_LINKER_FLAGS_MINSIZEREL} /NODEFAULTLIB:LIBCMTD")
endif()

#================================================================================
# Check for Dependencies
#================================================================================

if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/lib60870-C/dependencies/mbedtls-2.28.8)
    set(WITH_MBEDTLS 1)
    message(STATUS "mbedtls 2.28.8 found, TLS support will be enabled.")
else()
    message(STATUS "NOTE: mbedtls 2.28.8 not found. TLS support will be disabled.")
endif()

#================================================================================
# Build mbedtls Static Library
#================================================================================

if(WITH_MBEDTLS)
    file(GLOB MBEDTLS_SOURCES "${CMAKE_SOURCE_DIR}/lib60870-C/dependencies/mbedtls-2.28.8/library/*.c")
    add_library(mbedtls_static STATIC ${MBEDTLS_SOURCES})

    # For older CMake versions, we set properties on the target.
    # This ensures the include directories are used when compiling this target.
    target_include_directories(mbedtls_static PUBLIC
        "${CMAKE_SOURCE_DIR}/lib60870-C/config"
        "${CMAKE_SOURCE_DIR}/lib60870-C/dependencies/mbedtls-2.28.8/include"
    )

    target_compile_definitions(mbedtls_static PUBLIC
        "MBEDTLS_CONFIG_FILE=<mbedtls/config.h>"
    )
endif()

#================================================================================
# Build lib60870 Library
#================================================================================

set(IEC60870_SOURCES
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/file-service/file_server.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/apl/cpXXtime2a.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs101/cs101_asdu.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs101/cs101_bcr.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs101/cs101_information_objects.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs101/cs101_master_connection.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs101/cs101_master.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs101/cs101_queue.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs101/cs101_slave.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs104/cs104_connection.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs104/cs104_frame.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs104/cs104_slave.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/security/62351-5/aprofile.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/link_layer/buffer_frame.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/link_layer/link_layer.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/link_layer/serial_transceiver_ft_1_2.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/frame.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/lib60870_common.c
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/common/linked_list.c
)

set(HAL_SOURCES
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/memory/lib_memory.c
)

if(WIN32)
    list(APPEND HAL_SOURCES ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/socket/win32/socket_win32.c)
    list(APPEND HAL_SOURCES ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/thread/win32/thread_win32.c)
    list(APPEND HAL_SOURCES ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/time/win32/time.c)
    list(APPEND HAL_SOURCES ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/serial/win32/serial_port_win32.c)
else() # For Linux/BSD/macOS
    list(APPEND HAL_SOURCES ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/socket/bsd/socket_bsd.c)
    list(APPEND HAL_SOURCES ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/thread/linux/thread_linux.c)
    list(APPEND HAL_SOURCES ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/time/unix/time.c)
    list(APPEND HAL_SOURCES ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/serial/linux/serial_port_linux.c)
endif()

if(WITH_MBEDTLS)
    list(APPEND HAL_SOURCES ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/tls/mbedtls/tls_mbedtls.c)
endif()

add_library(lib60870-shared SHARED ${IEC60870_SOURCES} ${HAL_SOURCES})

set_target_properties(lib60870-shared PROPERTIES
    OUTPUT_NAME "lib60870"
)

add_library(lib60870 STATIC ${IEC60870_SOURCES} ${HAL_SOURCES})

target_include_directories(lib60870-shared PUBLIC
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api"
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/common/inc"
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/inc"
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/file-service"
    "${CMAKE_SOURCE_DIR}/lib60870-C/config"
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/link_layer"
)

target_include_directories(lib60870-shared PRIVATE "${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/internal")

target_include_directories(lib60870 PUBLIC
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api"
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/common/inc"
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/inc"
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/file-service"
    "${CMAKE_SOURCE_DIR}/lib60870-C/config"
    "${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/link_layer"
)

target_include_directories(lib60870 PRIVATE "${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/internal")

if(WITH_MBEDTLS)
    target_compile_definitions(lib60870-shared PUBLIC -DLIB60870_HAS_TLS_SUPPORT=1 -DCONFIG_CS104_SUPPORT_TLS=1)
    target_compile_definitions(lib60870-shared PRIVATE -DCONFIG_IEC60870_HAS_SECURITY=1 -DCONFIG_CS104_APROFILE=1)
    target_compile_definitions(lib60870 PUBLIC -DLIB60870_HAS_TLS_SUPPORT=1 -DCONFIG_CS104_SUPPORT_TLS=1)
    target_compile_definitions(lib60870 PRIVATE -DCONFIG_IEC60870_HAS_SECURITY=1 -DCONFIG_CS104_APROFILE=1)
endif()

#================================================================================
# Link system libraries
#================================================================================
if(WIN32)
    target_link_libraries(lib60870-shared
        PUBLIC mbedtls_static
        PRIVATE ws2_32 iphlpapi bcrypt
        INTERFACE legacy_stdio_definitions
        PRIVATE user32 advapi32 shell32 ole32 oleaut32 uuid gdi32 comdlg32 winmm msvcrt
    )
    target_link_libraries(lib60870
        PUBLIC mbedtls_static
        PRIVATE ws2_32 iphlpapi bcrypt
        INTERFACE legacy_stdio_definitions
        PRIVATE user32 advapi32 shell32 ole32 oleaut32 uuid gdi32 comdlg32 winmm msvcrt
    )
else()
    target_link_libraries(lib60870-shared PUBLIC mbedtls_static PRIVATE pthread m rt)
    target_link_libraries(lib60870 PUBLIC mbedtls_static PRIVATE pthread m rt)
endif()

#================================================================================
# Add platform specific libraries for mbedtls
#================================================================================
if(WITH_MBEDTLS AND WIN32)
    target_link_libraries(mbedtls_static PUBLIC advapi32 PRIVATE msvcrt)
endif()

#================================================================================
# Build Examples
#================================================================================

if(BUILD_EXAMPLES)
    add_subdirectory(${CMAKE_SOURCE_DIR}/lib60870-C/examples)
    if(WIN32)
        # Link all example executables to msvcrt and legacy_stdio_definitions
        foreach(example cs101_master_balanced cs101_master_unbalanced cs101_slave cs101_slave_files cs104_client_async cs104_redundancy_server cs104_server cs104_server_files cs104_server_no_threads multi_client_server simple_client tls_client tls_server)
            if(TARGET ${example})
                target_link_libraries(${example} msvcrt legacy_stdio_definitions)
            endif()
        endforeach()
    endif()
endif()

#================================================================================
# Build Tests
#================================================================================

if(BUILD_TESTS)
    enable_testing()

    add_executable(tests
        "${CMAKE_SOURCE_DIR}/lib60870-C/tests/all_tests.c"
        "${CMAKE_SOURCE_DIR}/lib60870-C/tests/unity/unity.c"
    )

    target_include_directories(tests PRIVATE
        "${CMAKE_SOURCE_DIR}/lib60870-C/tests/unity"
        "${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/internal"
        "${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/cs104"
        "${CMAKE_SOURCE_DIR}/lib60870-C/src/iec60870/link_layer"
    )

    target_link_libraries(tests PRIVATE lib60870 msvcrt legacy_stdio_definitions)

    if(WIN32)
        # This block was causing C files to be compiled as C++, leading to errors.
        # It is now commented out to ensure correct compilation.
        # set_source_files_properties(...)
    endif()

    add_test(NAME all_tests COMMAND tests)

endif()

#================================================================================
# Installation and Packaging
#================================================================================

set(API_HEADERS
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/inc/hal_time.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/inc/hal_thread.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/inc/hal_socket.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/inc/hal_serial.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/inc/hal_base.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/inc/tls_config.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/hal/inc/tls_ciphers.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/common/inc/linked_list.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/cs101_master.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/cs101_slave.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/cs104_slave.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/iec60870_master.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/iec60870_slave.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/iec60870_common.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/cs101_information_objects.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/cs104_connection.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/cs104_security.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/inc/api/link_layer_parameters.h
    ${CMAKE_SOURCE_DIR}/lib60870-C/src/file-service/cs101_file_service.h
)

install(TARGETS lib60870-shared lib60870
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${API_HEADERS} DESTINATION include/lib60870)

if(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
    include(InstallRequiredSystemLibraries)
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "IEC 60870-5-101/104 master/slave library")
    set(CPACK_PACKAGE_VENDOR "MZ Automation GmbH")
    set(CPACK_PACKAGE_CONTACT "info@mz-automation.de")
    set(CPACK_PACKAGE_VERSION_MAJOR "${LIB_VERSION_MAJOR}")
    set(CPACK_PACKAGE_VERSION_MINOR "${LIB_VERSION_MINOR}")
    set(CPACK_PACKAGE_VERSION_PATCH "${LIB_VERSION_PATCH}")
    set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${LIB_VERSION_MAJOR}.${LIB_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}_${CMAKE_SYSTEM_PROCESSOR}")
    set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${LIB_VERSION_MAJOR}.${LIB_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
    set(CPACK_COMPONENTS_ALL Libraries Development Applications)
    include(CPack)
endif()