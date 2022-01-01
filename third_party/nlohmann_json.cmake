cmake_minimum_required(VERSION 3.4)
project(nlohmann_json-download NONE)

include(ExternalProject)
ExternalProject_Add(nlohmann_json
    GIT_REPOSITORY    https://github.com/nlohmann/json
    GIT_TAG           v3.10.4
    SOURCE_DIR        "${CMAKE_CURRENT_BINARY_DIR}/nlohmann_json"
    BINARY_DIR        ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
    CMAKE_ARGS
    -DCMAKE_INSTALL_MESSAGE=LAZY
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    )
