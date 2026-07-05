cmake_minimum_required(VERSION 3.20)
project(NeuralGuard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
  message(FATAL_ERROR "NeuralGuard targets Windows only.")
endif()

if(MSVC)
  add_compile_options(/W4 /permissive- /EHsc)
endif()

# --- Phase 0 spike: ngmon ---------------------------------------------------
# User-mode WFP net-event monitor with process attribution. No driver, no
# external dependencies (system libs only) so the first build is friction-free.
add_executable(ngmon src/ngmon/main.cpp)
target_compile_definitions(ngmon PRIVATE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(ngmon PRIVATE
  fwpuclnt   # Windows Filtering Platform user-mode API
  ws2_32     # InetNtop / address helpers
)
