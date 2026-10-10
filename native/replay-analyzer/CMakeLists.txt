cmake_minimum_required(VERSION 3.24)
project(sb_replay_analyzer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
# Keep multi-config Windows builds in the same location as single-config builds.
foreach(config DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config} "${CMAKE_BINARY_DIR}/bin")
endforeach()
if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
  add_compile_options(/bigobj)
endif()

include(FetchContent)
find_package(Git REQUIRED)
find_package(ZLIB REQUIRED)
FetchContent_Declare(openbw
  GIT_REPOSITORY https://github.com/OpenBW/openbw.git
  GIT_TAG 8265ec449b903e0752060a00ed5f930a3656bf00
  GIT_CONFIG core.autocrlf=false
  UPDATE_DISCONNECTED TRUE
  PATCH_COMMAND "${GIT_EXECUTABLE}" apply --whitespace=nowarn "${CMAKE_CURRENT_SOURCE_DIR}/openbw-scr-support.patch"
)
FetchContent_Declare(openbw_bwapi
  GIT_REPOSITORY https://github.com/OpenBW/bwapi.git
  GIT_TAG 48124ba8ed1b4d52b3dfd52acbaf34afb9a37fe2
  GIT_CONFIG core.autocrlf=false
  UPDATE_DISCONNECTED TRUE
  PATCH_COMMAND "${GIT_EXECUTABLE}" apply --whitespace=nowarn "${CMAKE_CURRENT_SOURCE_DIR}/bwapi-scr-support.patch"
  SOURCE_SUBDIR unused
)
FetchContent_MakeAvailable(openbw openbw_bwapi)
set(OPENBW_DIR "${openbw_SOURCE_DIR}" CACHE PATH "OpenBW source" FORCE)
set(OPENBW_BWAPI_DIR "${openbw_bwapi_SOURCE_DIR}")
set(verify_args
  "-DGIT_EXECUTABLE:FILEPATH=${GIT_EXECUTABLE}"
  "-DOPENBW_DIR:PATH=${OPENBW_DIR}"
  "-DOPENBW_BWAPI_DIR:PATH=${OPENBW_BWAPI_DIR}"
  "-DOPENBW_PATCH:FILEPATH=${CMAKE_CURRENT_SOURCE_DIR}/openbw-scr-support.patch"
  "-DBWAPI_PATCH:FILEPATH=${CMAKE_CURRENT_SOURCE_DIR}/bwapi-scr-support.patch"
  -P "${CMAKE_CURRENT_SOURCE_DIR}/verify-dependency-patches.cmake"
)
execute_process(COMMAND "${CMAKE_COMMAND}" ${verify_args} COMMAND_ERROR_IS_FATAL ANY)
add_custom_target(verify-replay-dependencies
  COMMAND "${CMAKE_COMMAND}" ${verify_args}
  VERBATIM
)

set(USE_OPENBW ON CACHE BOOL "Use OpenBW" FORCE)
set(OPENBW_ENABLE_UI OFF CACHE BOOL "Headless analyzer" FORCE)
set(OPENBWAPI_BUILD_STATIC_LIBS ON CACHE BOOL "Link OpenBW libraries into the analyzer" FORCE)
add_subdirectory("${OPENBW_BWAPI_DIR}/bwapi" "${CMAKE_BINARY_DIR}/bwapi" EXCLUDE_FROM_ALL)
target_link_libraries(OpenBWData ZLIB::ZLIB)

add_executable(sb-replay-analyzer main.cpp)
add_dependencies(sb-replay-analyzer verify-replay-dependencies)
target_include_directories(sb-replay-analyzer PRIVATE
  "${OPENBW_DIR}"
  "${OPENBW_BWAPI_DIR}/bwapi/include"
  "${OPENBW_BWAPI_DIR}/bwapi/Util/Source"
  "${OPENBW_BWAPI_DIR}/bwapi/BWAPI/Source/BWAPI"
  "${OPENBW_BWAPI_DIR}/bwapi/BWAPI/Source"
  "${OPENBW_BWAPI_DIR}/bwapi/OpenBWData"
  "${OPENBW_BWAPI_DIR}/bwapi/BWAPICore"
  "${OPENBW_BWAPI_DIR}/bwapi/Shared"
)
target_link_libraries(sb-replay-analyzer PRIVATE BWAPI ZLIB::ZLIB ${CMAKE_DL_LIBS})

include(CTest)
if(BUILD_TESTING)
  add_executable(replay-format-test tests/replay-format.cpp)
  add_dependencies(replay-format-test verify-replay-dependencies)
  target_include_directories(replay-format-test PRIVATE "${OPENBW_DIR}")
  target_link_libraries(replay-format-test PRIVATE ZLIB::ZLIB)
  add_test(NAME replay-format COMMAND replay-format-test)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_test(NAME analyzer-cli COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.py" "$<TARGET_FILE:sb-replay-analyzer>")
endif()
