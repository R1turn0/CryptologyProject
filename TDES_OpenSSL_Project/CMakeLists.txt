cmake_minimum_required(VERSION 3.24)
project(TDES_OpenSSL_Project)

set(CMAKE_CXX_STANDARD 17)

# set output directory
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

# set platform
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLATFORM x64)
else()
    set(PLATFORM x86)
endif()

set(ROOTDIR ${CMAKE_SOURCE_DIR})

link_directories(${CMAKE_SOURCE_DIR}/lib/${PLATFORM})
#link_directories(${CMAKE_SOURCE_DIR}/lib)

add_executable(TDES_OpenSSL_Project main.cpp)

target_include_directories(TDES_OpenSSL_Project PRIVATE ${PROJECT_SOURCE_DIR}/inc)

target_link_libraries(TDES_OpenSSL_Project
    PRIVATE
        libcrypto
		libssl
)

# Custom Target Copy
# $<TARGET_RUNTIME_DLLS:TDES_OpenSSL_Project>
add_custom_command(TARGET TDES_OpenSSL_Project POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${PROJECT_SOURCE_DIR}/lib/${PLATFORM}/libcrypto-3-x64.dll $<TARGET_FILE_DIR:TDES_OpenSSL_Project>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${PROJECT_SOURCE_DIR}/lib/${PLATFORM}/libssl-3-x64.dll $<TARGET_FILE_DIR:TDES_OpenSSL_Project>
        COMMAND_EXPAND_LISTS
)
