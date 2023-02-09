cmake_minimum_required(VERSION 3.13.0.0)
project(sqlite3mc)

# Helper macro
macro(_Enable_MT _target)
    target_compile_options(${_target} PRIVATE
        $<$<CONFIG:Release>:/MT>$<$<CONFIG:Debug>:/MTd>
    )
endmacro()

# Only generate Debug and Release configuration types.
set(CMAKE_CONFIGURATION_TYPES Debug Release)

set(SQLITE3MC_BASE_SRCS
    src/sqlite3mc.c
    src/cipher_common.h
    src/cipher_config.h
    src/fastpbkdf2.h
    src/mystdint.h
    src/rijndael.h
    src/sha1.h
    src/sha2.h
    src/sqlite3.h
    src/sqlite3ext.h
    src/sqlite3mc.h
    src/sqlite3mc_vfs.h
    src/sqlite3userauth.h
    src/test_windirent.h
)
set(SQLITE3MC_DLLRES_SRCS
    src/sqlite3mc.def
    src/sqlite3mc.rc
)
set(SQLITE3MC_SHELL_SRCS
    src/sqlite3.h
    src/shell.c
    src/sqlite3mc_shell.rc
)
set(SQLITE3MC_BASE_DEFINITIONS
    CODEC_TYPE=CODEC_TYPE_CHACHA20
    SQLITE_ENABLE_DEBUG=0
    SQLITE_THREADSAFE=1
    SQLITE_DQS=0
    SQLITE_MAX_ATTACHED=10
    SQLITE_ENABLE_EXPLAIN_COMMENTS=1
    SQLITE_SOUNDEX=1
    SQLITE_ENABLE_COLUMN_METADATA=1
    SQLITE_SECURE_DELETE=1
    SQLITE_ENABLE_DESERIALIZE=1
    SQLITE_ENABLE_FTS3=1
    SQLITE_ENABLE_FTS3_PARENTHESIS=1
    SQLITE_ENABLE_FTS4=1
    SQLITE_ENABLE_FTS5=1
    SQLITE_ENABLE_JSON1=1
    SQLITE_ENABLE_RTREE=1
    SQLITE_ENABLE_GEOPOLY=1
    SQLITE_CORE=1
    SQLITE_ENABLE_EXTFUNC=1
    SQLITE_ENABLE_CSV=1
    SQLITE_ENABLE_CARRAY=1
    #SQLITE_ENABLE_SERIES=1
    SQLITE_ENABLE_UUID=1
    #SQLITE_ENABLE_REGEXP=1
    SQLITE_TEMP_STORE=2
    SQLITE_USE_URI=1
    SQLITE_USER_AUTHENTICATION=1
    SQLITE_ENABLE_DBPAGE_VTAB=1
    SQLITE_ENABLE_DBSTAT_VTAB=1
    SQLITE_ENABLE_STMTVTAB=1
    SQLITE_ENABLE_UNKNOWN_SQL_FUNCTION=1
)
set(SQLITE3MC_SHELL_DEFINITIONS
    SQLITE_SHELL_IS_UTF8=1
    SQLITE_USER_AUTHENTICATION=1
)
set(SQLITE3MC_INCLUDEDIRS
    src
)

set(SQLITE3MC_LINK_LIBRARIES )

set(SQLITE3MC_DLL_DEFINITIONS )

set(SQLITE3MC_COMPILE_OPTIONS )

set(SQLTE3MC_SHELL_SYSTEM_LINKS )

if(MSVC)
set(SQLITE3MC_COMPILE_OPTIONS
    # Debug Information Format: Program Database
    /Zi
    # Enable String Pooling
    /GF
    # Enable C++ Exceptions
    /EHsc
    # Enable Function-Level Linking
    /Gy
    # Full Optimize for Release
    $<$<CONFIG:Release>:/Ox>
    # Enable Intrinsic Functions for Release
    $<$<CONFIG:Release>:/Oi>
)
set(SQLITE3MC_DLL_DEFINITIONS
    _USRDLL
)

set(SQLTE3MC_SHELL_SYSTEM_LINKS
    kernel32.lib
    user32.lib
    gdi32.lib
    winspool.lib
    comdlg32.lib
    advapi32.lib
    shell32.lib
    ole32.lib
    oleaut32.lib
    uuid.lib
    odbc32.lib
    odbccp32.lib
)

set(SQLITE3MC_BASE_DEFINITIONS 
    ${SQLITE3MC_BASE_DEFINITIONS}
    SQLITE_ENABLE_PREUPDATE_HOOK=1
)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
set(SQLITE3MC_LINK_LIBRARIES
    pthread
    m
)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
set(SQLITE3MC_LINK_LIBRARIES
    pthread
    m
)
endif()

set(_LIB_DIFINITIONS
    _LIB
)

set(_DEFAULT_DEFINITIONS
    _CRT_SECURE_NO_WARNINGS
    _CRT_SECURE_NO_DEPRECATE
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_NONSTDC_NO_DEPRECATE
    _UNICODE
    UNICODE
)

# MD Lib project
add_library(sqlite3mc_lib STATIC
    ${SQLITE3MC_BASE_SRCS}
)
target_include_directories(sqlite3mc_lib PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(sqlite3mc_lib PRIVATE
    ${_LIB_DIFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
)
target_link_libraries(sqlite3mc_lib PRIVATE
        ${SQLITE3MC_LINK_LIBRARIES}
)
# MT Lib project
add_library(sqlite3mc_lib_mt STATIC
    ${SQLITE3MC_BASE_SRCS}
)
target_include_directories(sqlite3mc_lib_mt PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(sqlite3mc_lib_mt PRIVATE
    ${_LIB_DIFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
)
target_link_libraries(sqlite3mc_lib_mt PRIVATE
        ${SQLITE3MC_LINK_LIBRARIES}
)
_Enable_MT(sqlite3mc_lib_mt)

# MD Dll project
add_library(sqlite3mc_dll SHARED
    ${SQLITE3MC_BASE_SRCS}
    ${SQLITE3MC_DLLRES_SRCS}
)
target_include_directories(sqlite3mc_dll PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(sqlite3mc_dll PRIVATE
    ${SQLITE3MC_DLL_DEFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
)
target_link_libraries(sqlite3mc_dll PRIVATE
        ${SQLITE3MC_LINK_LIBRARIES}
)
# MT Dll project
add_library(sqlite3mc_dll_mt SHARED
    ${SQLITE3MC_BASE_SRCS}
    ${SQLITE3MC_DLLRES_SRCS}
)
target_include_directories(sqlite3mc_dll_mt PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(sqlite3mc_dll_mt PRIVATE
    ${SQLITE3MC_DLL_DEFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
)
target_link_libraries(sqlite3mc_dll_mt PRIVATE
        ${SQLITE3MC_LINK_LIBRARIES}
)
_Enable_MT(sqlite3mc_dll_mt)

# Shell Executable project
add_executable(sqlite3mc_shell
    ${SQLITE3MC_SHELL_SRCS}
)
target_include_directories(sqlite3mc_shell PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(sqlite3mc_shell PRIVATE
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_SHELL_DEFINITIONS}
)
target_link_libraries(sqlite3mc_shell PRIVATE
    sqlite3mc_lib_mt
    ${SQLTE3MC_SHELL_SYSTEM_LINKS}
)
target_link_libraries(sqlite3mc_shell PRIVATE
        ${SQLITE3MC_LINK_LIBRARIES}
)
_Enable_MT(sqlite3mc_shell)

if(${WITH_ICU})



set(SQLITE3MC_ICU_DEFINITIONS
    SQLITE_ENABLE_ICU=1
)
set(SQLITE3MC_ICU_LINK_LIBRARIES
    icuuc
    icuio
    icudata
    icui18n
)
set(SQLITE3MC_ICU_INCLUDE_DIRS )
set(SQLITE3MC_ICU_LIB_DIRS )

if(MSVC)
    set(SQLITE3MC_ICU_INCLUDE_DIRS
        ${WITH_ICU}\include
    )
    if(${CMAKE_GENERATOR_PLATFORM} STREQUAL "x64")
        set(SQLITE3MC_ICU_LIB_DIRS
            ${WITH_ICU}\lib64
        )
    else(
        set(SQLITE3MC_ICU_LIB_DIRS
            ${WITH_ICU}\lib
        )
    )
    endif()
endif()

# MD icu Lib project
add_library(sqlite3mc_libicu STATIC
    ${SQLITE3MC_BASE_SRCS}
    ${SQLITE3MC_DLLRES_SRCS}
)
target_include_directories(sqlite3mc_libicu PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
    ${SQLITE3MC_ICU_INCLUDE_DIRS}
)
target_compile_definitions(sqlite3mc_libicu PRIVATE
    ${SQLITE3MC_DLL_DEFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
    ${SQLITE3MC_ICU_DEFINITIONS}
)
target_link_directories(sqlite3mc_libicu PRIVATE 
    ${SQLITE3MC_IC_LIB_DIRS}
)
target_link_libraries(sqlite3mc_libicu PRIVATE
    ${SQLITE3MC_LINK_LIBRARIES}
    ${SQLITE3MC_ICU_LINK_LIBRARIES}
)

# MT icu Lib project
add_library(sqlite3mc_libicu_mt STATIC
    ${SQLITE3MC_BASE_SRCS}
)
target_include_directories(sqlite3mc_libicu_mt PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
    ${SQLITE3MC_ICU_INCLUDE_DIRS}
)
target_compile_definitions(sqlite3mc_libicu_mt PRIVATE
    ${_LIB_DIFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
    ${SQLITE3MC_ICU_DEFINITIONS}
)
target_link_directories(sqlite3mc_libicu_mt PRIVATE 
    ${SQLITE3MC_ICU_LIB_DIRS}
)
target_link_libraries(sqlite3mc_libicu_mt PRIVATE
    ${SQLITE3MC_LINK_LIBRARIES}
    ${SQLITE3MC_ICU_LINK_LIBRARIES}
)
_Enable_MT(sqlite3mc_libicu_mt)

# MD Dll icu project
add_library(sqlite3mc_dllicu SHARED
    ${SQLITE3MC_BASE_SRCS}
    ${SQLITE3MC_DLLRES_SRCS}
)
target_include_directories(sqlite3mc_dllicu PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
    ${SQLITE3MC_ICU_INCLUDE_DIRS}
)
target_compile_definitions(sqlite3mc_dllicu PRIVATE
    ${SQLITE3MC_DLL_DEFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
    ${SQLITE3MC_ICU_DEFINITIONS}
)
target_link_directories(sqlite3mc_dllicu PRIVATE 
    ${SQLITE3MC_ICU_LIB_DIRS}
)
target_link_libraries(sqlite3mc_dllicu PRIVATE
    ${SQLITE3MC_LINK_LIBRARIES}
    ${SQLITE3MC_ICU_LINK_LIBRARIES}
)

# MT Dll icu project
add_library(sqlite3mc_dllicu_mt SHARED
    ${SQLITE3MC_BASE_SRCS}
    ${SQLITE3MC_DLLRES_SRCS}
)
target_include_directories(sqlite3mc_dllicu_mt PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
    ${SQLITE3MC_ICU_INCLUDE_DIRS}
)
target_compile_definitions(sqlite3mc_dllicu_mt PRIVATE
    ${SQLITE3MC_DLL_DEFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
    ${SQLITE3MC_ICU_DEFINITIONS}
)
target_link_directories(sqlite3mc_dllicu_mt PRIVATE 
    ${SQLITE3MC_ICU_LIB_DIRS}
)
target_link_libraries(sqlite3mc_dllicu_mt PRIVATE
    ${SQLITE3MC_LINK_LIBRARIES}
    ${SQLITE3MC_ICU_LINK_LIBRARIES}
)
_Enable_MT(sqlite3mc_dllicu_mt)

#Shell Executable icu project
add_executable(sqlite3mc_shellicu
    ${SQLITE3MC_SHELL_SRCS}
)
target_include_directories(sqlite3mc_shellicu PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
    ${SQLITE3MC_ICU_INCLUDE_DIRS}
)
target_compile_definitions(sqlite3mc_shellicu PRIVATE
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_SHELL_DEFINITIONS}
)
target_link_directories(sqlite3mc_shellicu PRIVATE 
    ${SQLITE3MC_ICU_LIB_DIRS}
)
target_link_libraries(sqlite3mc_shellicu PRIVATE
    sqlite3mc_libicu_mt
    ${SQLTE3MC_SHELL_SYSTEM_LINKS}
    ${SQLITE3MC_LINK_LIBRARIES}
    ${SQLITE3MC_ICU_LINK_LIBRARIES}
)
_Enable_MT(sqlite3mc_shellicu)
endif()