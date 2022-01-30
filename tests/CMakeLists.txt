# TODO(akawashiro): Use file command file(COPY tests DESTINATION
# ${CMAKE_CURRENT_BINARY_DIR})
add_custom_target(
  copy_test ALL COMMAND "rsync" "-au" "${CMAKE_CURRENT_SOURCE_DIR}/"
                        "${CMAKE_CURRENT_BINARY_DIR}")

add_executable(hello hello.c)
