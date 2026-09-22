cmake_minimum_required(VERSION 3.20)
project(WinDbgLite LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    # Use static CRT: /MTd for Debug, /MT for non-Debug.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# --------------------------------------------------------------------------------------------------
# Zydis disassembler engine (replaces udis86). Zydis depends on Zycore, which is vendored under
# third_party/Zydis/dependencies/zycore. We build both as a single static library.
# --------------------------------------------------------------------------------------------------
set(ZYDIS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/Zydis")
set(ZYCORE_ROOT "${ZYDIS_ROOT}/dependencies/zycore")

file(GLOB ZYDIS_SOURCES CONFIGURE_DEPENDS
    "${ZYDIS_ROOT}/src/*.c")
file(GLOB ZYCORE_SOURCES CONFIGURE_DEPENDS
    "${ZYCORE_ROOT}/src/*.c"
    "${ZYCORE_ROOT}/src/API/*.c")

add_library(Zydis STATIC ${ZYDIS_SOURCES} ${ZYCORE_SOURCES})
set_target_properties(Zydis PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON)
target_compile_definitions(Zydis PUBLIC
    ZYDIS_STATIC_BUILD
    ZYCORE_STATIC_BUILD)
target_include_directories(Zydis PUBLIC
    "${ZYDIS_ROOT}/include"
    "${ZYCORE_ROOT}/include"
    "${ZYDIS_ROOT}/src")

# WinDbgLite now uses Zydis as its disassembly backend.

set(WINDBGLITE_ICON_STYLE "classic" CACHE STRING "Icon style for WinDbgLite executables: classic|minimal|alert")
set_property(CACHE WINDBGLITE_ICON_STYLE PROPERTY STRINGS classic minimal alert)
option(WINDBGLITE_USE_MINIMAL_ICON "Deprecated: use WINDBGLITE_ICON_STYLE=minimal instead" OFF)

string(TOLOWER "${WINDBGLITE_ICON_STYLE}" WINDBGLITE_ICON_STYLE_NORMALIZED)
if (WINDBGLITE_USE_MINIMAL_ICON AND WINDBGLITE_ICON_STYLE_NORMALIZED STREQUAL "classic")
    set(WINDBGLITE_ICON_STYLE_NORMALIZED "minimal")
endif()

set(WINDBGLITE_ICON_RESOURCE "src/WinDbgLiteWin32UI/Win32UiResources.rc")
if (WINDBGLITE_ICON_STYLE_NORMALIZED STREQUAL "minimal")
    set(WINDBGLITE_ICON_RESOURCE "src/WinDbgLiteWin32UI/Win32UiResourcesMinimal.rc")
elseif (WINDBGLITE_ICON_STYLE_NORMALIZED STREQUAL "alert")
    set(WINDBGLITE_ICON_RESOURCE "src/WinDbgLiteWin32UI/Win32UiResourcesAlert.rc")
elseif (NOT WINDBGLITE_ICON_STYLE_NORMALIZED STREQUAL "classic")
    message(FATAL_ERROR "Unsupported WINDBGLITE_ICON_STYLE='${WINDBGLITE_ICON_STYLE}'. Expected classic, minimal, or alert.")
endif()

add_executable(WinDbgLite
    src/WinDbgLite/main.cpp
    src/WinDbgLite/Debugger.cpp
    src/Common/WinApiDynamic.cpp
    ${WINDBGLITE_ICON_RESOURCE}
)

add_executable(WinDbgLiteWin32UI WIN32
    src/WinDbgLiteWin32UI/Win32UiMain.cpp
    src/WinDbgLiteWin32UI/CustomListControl.cpp
    src/WinDbgLite/Debugger.cpp
    src/Common/WinApiDynamic.cpp
    ${WINDBGLITE_ICON_RESOURCE}
)

add_executable(Z0BDbgCli
    src/WinDbgLiteCli/main.cpp
    src/WinDbgLiteCli/CliConsole.cpp
    src/WinDbgLiteCli/LineEditor.cpp
    src/WinDbgLiteCli/PythonBridge.cpp
    src/WinDbgLiteCli/WinDbgLiteCli.rc
    src/WinDbgLite/Debugger.cpp
    src/Common/WinApiDynamic.cpp
)

target_sources(Z0BDbgCli PRIVATE
    src/WinDbgLiteCli/PythonBridge.h
)

add_library(WinDbgLiteApi SHARED
    src/WinDbgLiteApi/WinDbgLiteApi.cpp
    src/WinDbgLite/Debugger.cpp
    src/Common/WinApiDynamic.cpp
)

target_compile_definitions(Z0BDbgCli PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

target_compile_definitions(WinDbgLiteApi PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(Z0BDbgCli PRIVATE
    Zydis
    dbghelp
    psapi
)

target_link_libraries(WinDbgLiteApi PRIVATE
    Zydis
    dbghelp
    psapi
)

target_include_directories(Z0BDbgCli PRIVATE
    src/Common
    src/WinDbgLite
    src/WinDbgLiteCli
)

target_include_directories(WinDbgLiteApi PRIVATE
    src/Common
    src/WinDbgLite
    src/WinDbgLiteApi
)

set_target_properties(Z0BDbgCli PROPERTIES
    OUTPUT_NAME "Z0BDbgCli"
)

set_target_properties(WinDbgLiteApi PROPERTIES
    OUTPUT_NAME "WinDbgLiteApi"
)

add_executable(McpDemoServer
    src/McpDemoServer/McpDemoServer.cpp
)

add_library(WinDbgLiteSamplePlugin SHARED
    plugins/SamplePlugin.cpp
)

add_library(WinDbgLiteMcpPlugin SHARED
    plugins/McpPlugin.cpp
)

target_compile_definitions(WinDbgLite PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

target_compile_definitions(WinDbgLiteWin32UI PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

target_compile_definitions(McpDemoServer PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

target_compile_definitions(WinDbgLiteSamplePlugin PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

target_compile_definitions(WinDbgLiteMcpPlugin PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(WinDbgLite PRIVATE
    Zydis
    dbghelp
    psapi
)

target_link_libraries(WinDbgLiteWin32UI PRIVATE
    Zydis
    dbghelp
    psapi
    comdlg32
    comctl32
    shell32
    ole32
    version
)

target_include_directories(WinDbgLite PRIVATE
    src/Common
    src/WinDbgLite
)

target_include_directories(WinDbgLiteWin32UI PRIVATE
    src/Common
    src/WinDbgLite
    src/WinDbgLiteWin32UI
)

target_include_directories(WinDbgLiteSamplePlugin PRIVATE
    src/Common
)

target_include_directories(WinDbgLiteMcpPlugin PRIVATE
    src/Common
)

set_target_properties(WinDbgLiteSamplePlugin PROPERTIES
    OUTPUT_NAME "SamplePlugin"
)

set_target_properties(WinDbgLiteMcpPlugin PROPERTIES
    OUTPUT_NAME "McpPlugin"
)
