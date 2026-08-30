cmake_minimum_required(VERSION 3.20)

project(rawpdb_analyzer LANGUAGES CXX)

include(FetchContent)

set(RAWPDB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  raw_pdb
  GIT_REPOSITORY https://github.com/MolecularMatters/raw_pdb.git
  GIT_TAG 43cc59b7037238ad84e1d5abe10711a06d998fa0
)
FetchContent_MakeAvailable(raw_pdb)

add_executable(rawpdb_analyzer src/main.cpp)
target_link_libraries(rawpdb_analyzer PRIVATE raw_pdb)
target_compile_features(rawpdb_analyzer PRIVATE cxx_std_17)

if(MSVC)
  target_compile_options(rawpdb_analyzer PRIVATE /W4 /O2 /permissive-)
else()
  target_compile_options(rawpdb_analyzer PRIVATE -Wall -Wextra -O3)
endif()

set_target_properties(rawpdb_analyzer PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/RelWithDebInfo"
)
