cmake_minimum_required(VERSION 3.7)

project(ra-net)

set(CMAKE_CXX_STANDARD 11)
option(USE_COMMON "use ra-common lib?" ON)

file(GLOB SRC src/*.cpp)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

if(USE_COMMON)
    add_subdirectory(common)
endif()

add_subdirectory(contrib/event2)
add_subdirectory(contrib/lua)

add_library(ra-net ${SRC})

target_link_libraries(ra-net event2 ra-common lua)
target_link_directories(ra-net PUBLIC include)