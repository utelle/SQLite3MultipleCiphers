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

# Globle settings
add_compile_options(
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

set(_LIB_DIFINITIONS
    _LIB
)
set(_DLL_DIFINITIONS
    _USRDLL
)
set(_DEFAULT_DEFINITIONS
    _CRT_SECURE_NO_WARNINGS
    _CRT_SECURE_NO_DEPRECATE
    _CRT_NONSTDC_NO_WARNINGS
    _CRT_NONSTDC_NO_DEPRECATE
    _UNICODE
    UNICODE
)

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
    SQLITE_ENABLE_SERIES=1
    SQLITE_ENABLE_UUID=1
    SQLITE_ENABLE_REGEXP=1
    SQLITE_TEMP_STORE=2
    SQLITE_USE_URI=1
    SQLITE_USER_AUTHENTICATION=1
    SQLITE_ENABLE_DBPAGE_VTAB=1
    SQLITE_ENABLE_DBSTAT_VTAB=1
    SQLITE_ENABLE_STMTVTAB=1
    SQLITE_ENABLE_UNKNOWN_SQL_FUNCTION=1
)
set(SQLITE3MC_ICU_DEFINITIONS
    SQLITE_ENABLE_ICU=1
)
set(SQLITE3MC_SHELL_DEFINITIONS
    SQLITE_SHELL_IS_UTF8=1
    SQLITE_USER_AUTHENTICATION=1
)
set(SQLITE3MC_INCLUDEDIRS
    src
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
_Enable_MT(sqlite3mc_lib_mt)

# MT icu Lib project
add_library(sqlite3mc_libicu_mt STATIC
    ${SQLITE3MC_BASE_SRCS}
)
target_include_directories(sqlite3mc_libicu_mt PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(sqlite3mc_libicu_mt PRIVATE
    ${_LIB_DIFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
    ${SQLITE3MC_ICU_DEFINITIONS}
)
_Enable_MT(sqlite3mc_libicu_mt)

# MD Dll project
add_library(sqlite3mc_dll SHARED
    ${SQLITE3MC_BASE_SRCS}
    ${SQLITE3MC_DLLRES_SRCS}
)
target_include_directories(sqlite3mc_dll PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(sqlite3mc_dll PRIVATE
    ${_DLL_DIFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
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
    ${_DLL_DIFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
)
_Enable_MT(sqlite3mc_dll_mt)

# MT Dll icu project
add_library(sqlite3mc_dllicu_mt SHARED
    ${SQLITE3MC_BASE_SRCS}
    ${SQLITE3MC_DLLRES_SRCS}
)
target_include_directories(sqlite3mc_dllicu_mt PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(sqlite3mc_dllicu_mt PRIVATE
    ${_DLL_DIFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
    ${SQLITE3MC_ICU_DEFINITIONS}
)
_Enable_MT(sqlite3mc_dllicu_mt)

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
_Enable_MT(sqlite3mc_shell)

# Shell Executable icu project
add_executable(sqlite3mc_shellicu
    ${SQLITE3MC_SHELL_SRCS}
)
target_include_directories(sqlite3mc_shellicu PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(sqlite3mc_shellicu PRIVATE
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_SHELL_DEFINITIONS}
)
target_link_libraries(sqlite3mc_shellicu PRIVATE
    sqlite3mc_libicu_mt
    ${SQLTE3MC_SHELL_SYSTEM_LINKS}
)
_Enable_MT(sqlite3mc_shellicu)

# pthreads4w project
add_library(pthreads4w SHARED
    pthreads4w/_ptw32.h
    pthreads4w/config.h
    pthreads4w/context.h
    pthreads4w/implement.h
    pthreads4w/need_errno.h
    pthreads4w/pthread.h
    pthreads4w/sched.h
    pthreads4w/semaphore.h
    pthreads4w/pthread.c
    pthreads4w/version.rc
)
target_include_directories(pthreads4w PRIVATE
    pthreads4w
)
target_compile_definitions(pthreads4w PRIVATE
    ${_DEFAULT_DEFINITIONS}
    ${_DLL_DIFINITIONS}
    HAVE_CONFIG_H
    __PTW32_RC_MSC
    __PTW32_ARCHX86
    __PTW32_CLEANUP_SEH
)

# speedtest1 project
add_executable(speedtest1
    tests/speedtest1.c
)
target_include_directories(speedtest1 PRIVATE
    pthreads4w
    src
)
target_compile_definitions(speedtest1 PRIVATE
    ${_DEFAULT_DEFINITIONS}
    __PTW32_CLEANUP_SEH
)
target_link_libraries(speedtest1 PRIVATE
    pthreads4w
    sqlite3mc_dll_mt
)

# threadtest2 project
add_executable(threadtest2
    tests/threadtest2.c
)
target_include_directories(threadtest2 PRIVATE
    pthreads4w
    src
)
target_compile_definitions(threadtest2 PRIVATE
    ${_DEFAULT_DEFINITIONS}
    __PTW32_CLEANUP_SEH
)
target_link_libraries(threadtest2 PRIVATE
    pthreads4w
    sqlite3mc_dll_mt
)

# threadtest3 project
add_executable(threadtest3
    tests/threadtest3.c
    tests/test_multiplex.c
)
target_include_directories(threadtest3 PRIVATE
    pthreads4w
    src
)
target_compile_definitions(threadtest3 PRIVATE
    ${_DEFAULT_DEFINITIONS}
    __PTW32_CLEANUP_SEH
)
target_link_libraries(threadtest3 PRIVATE
    pthreads4w
    sqlite3mc_dll_mt
)

# threadtest4 project
add_executable(threadtest4
    tests/threadtest4.c
)
target_include_directories(threadtest4 PRIVATE
    pthreads4w
    src
)
target_compile_definitions(threadtest4 PRIVATE
    ${_DEFAULT_DEFINITIONS}
    __PTW32_CLEANUP_SEH
)
target_link_libraries(threadtest4 PRIVATE
    pthreads4w
    sqlite3mc_dll_mt
)
