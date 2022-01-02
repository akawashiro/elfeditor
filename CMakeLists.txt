cmake_minimum_required(VERSION 3.4)
project(phdr_editor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(third-party)

get_third_party(glog)
set(WITH_GFLAGS
    OFF
    CACHE INTERNAL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/glog
                 ${CMAKE_CURRENT_BINARY_DIR}/glog EXCLUDE_FROM_ALL)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/glog
                    ${CMAKE_CURRENT_BINARY_DIR}/glog/src)
add_definitions(-DC10_USE_GLOG=1)

get_third_party(nlohmann_json)
add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/nlohmann_json)

add_executable(phdr_editor elf_binary.cc utils.cc phdr_editor_main.cc)
target_link_libraries(phdr_editor PRIVATE glog nlohmann_json::nlohmann_json)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/CTestCustom.cmake
               ${CMAKE_CURRENT_BINARY_DIR})
include(CTest)

# TODO(akawashiro): Use file command
# file(COPY tests DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_custom_target(copy_test ALL COMMAND "rsync" "-au" "${CMAKE_CURRENT_SOURCE_DIR}/tests" "${CMAKE_CURRENT_BINARY_DIR}")

if(BUILD_TESTING)
  add_test(
    NAME bash_no_edit
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/tests/bash_no_edit.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()
