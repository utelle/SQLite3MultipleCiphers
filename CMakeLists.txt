cmake_minimum_required(VERSION 3.13.0.0)
project(sqlite3mc)

OPTION(SQLITE3MC_STATIC_RUNTIME_LINK "Link the c++ runtime statically" OFF)
OPTION(SQLITE3MC_STATIC "Build SQLITE3MC as a static library" OFF)
OPTION(SQLITE3MC_BUILD_SHELL "Builds the SQLITE3MC Shell" ON)
OPTION(SQLITE3MC_WITH_ICU "Builds SQLITE3MC with the ICU library. Will use the FindICU function to locate the library. (https://cmake.org/cmake/help/latest/module/FindICU.html)" OFF)

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
    src/shell.c
    src/sqlite3mc.c
    src/sqlite3mc_shell.rc
)
set(SQLITE3MC_BASE_DEFINITIONS
    CODEC_TYPE=CODEC_TYPE_SQLCIPHER
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
set(SQLITE3MC_SHELL_DEFINITIONS
    SQLITE_SHELL_IS_UTF8=1
    SQLITE_USER_AUTHENTICATION=1
)
set(SQLITE3MC_INCLUDEDIRS
    src
)

set(SQLITE3MC_LINK_LIBRARIES )

set(SQLITE3MC_DLL_DEFINITIONS )

set(SQLTE3MC_SHELL_SYSTEM_LINKS )

if(MSVC)
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

if(SQLITE3MC_WITH_ICU)
find_package(ICU REQUIRED COMPONENTS data i18n io uc)
if(ICU_FOUND)
set(SQLITE3MC_ICU_DEFINITIONS
    SQLITE_ENABLE_ICU=1
)
else()
message("ICU not found.")
endif()
endif()


if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse4.2 -maes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse4.2 -maes")
set(SQLITE3MC_LINK_LIBRARIES
    pthread
    m
)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse4.2 -maes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse4.2 -maes")
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

set(SQLITE3MC_TARGET "sqlite3mc")
set(SQLIT3MC_SHELL_TARGET "sqlite3mc_shell")

set(SQLITE3MC_LINK "SHARED")

if(SQLITE3MC_STATIC)
set(SQLITE3MC_LINK "STATIC")
set(SQLITE3MC_TARGET "sqlite3mc_static")
endif()



#Lib Project
add_library(${SQLITE3MC_TARGET} ${SQLITE3MC_LINK}
    ${SQLITE3MC_BASE_SRCS}
)
target_include_directories(${SQLITE3MC_TARGET} PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(${SQLITE3MC_TARGET} PRIVATE
    ${_LIB_DIFINITIONS}
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_BASE_DEFINITIONS}
)
target_link_libraries(${SQLITE3MC_TARGET} PRIVATE
    ${SQLITE3MC_LINK_LIBRARIES}
)

if(SQLITE3MC_WITH_ICU)
target_compile_definitions(${SQLITE3MC_TARGET} PRIVATE
    ${SQLITE3MC_ICU_DEFINITIONS}
)
target_include_directories(${SQLITE3MC_TARGET} PRIVATE 
    ${ICU_INCLUDE_DIRS}
)
target_link_libraries(${SQLITE3MC_TARGET} PRIVATE
    ${ICU_LIBRARIES}
)
message("Will build ${SQLITE3MC_TARGET} with ICU")
endif()

if(SQLITE3MC_STATIC_RUNTIME_LINK)
message("Will build ${SQLITE3MC_TARGET} with static runtime link")
_Enable_MT(${SQLITE3MC_TARGET})
endif()
message("Will build ${SQLITE3MC_TARGET} as ${SQLITE3MC_LINK}")

if(SQLITE3MC_BUILD_SHELL)

# Shell Executable project
add_executable(${SQLIT3MC_SHELL_TARGET}
    ${SQLITE3MC_SHELL_SRCS}
)
target_include_directories(${SQLIT3MC_SHELL_TARGET} PRIVATE
    ${SQLITE3MC_INCLUDEDIRS}
)
target_compile_definitions(${SQLIT3MC_SHELL_TARGET} PRIVATE
    ${_DEFAULT_DEFINITIONS}
    ${SQLITE3MC_SHELL_DEFINITIONS}
)
target_link_libraries(${SQLIT3MC_SHELL_TARGET} PRIVATE
    ${SQLITE3MC_TARGET}
    ${SQLTE3MC_SHELL_SYSTEM_LINKS}
    ${SQLITE3MC_LINK_LIBRARIES}
)

if(SQLITE3MC_WITH_ICU)
target_compile_definitions(${SQLIT3MC_SHELL_TARGET} PRIVATE
    ${SQLITE3MC_ICU_DEFINITIONS}
)
target_include_directories(${SQLIT3MC_SHELL_TARGET} PRIVATE 
    ${ICU_INCLUDE_DIRS}
)
target_link_libraries(${SQLIT3MC_SHELL_TARGET} PRIVATE
    ${ICU_LIBRARIES}
)
message("Will build ${SQLIT3MC_SHELL_TARGET} with ICU")
endif()

if(SQLITE3MC_RUNTIME_LINK)
message("Will build ${SQLIT3MC_SHELL_TARGET} with static runtime")
_Enable_MT(${SQLIT3MC_SHELL_TARGET})
endif()
message("Will build ${SQLIT3MC_SHELL_TARGET}")
endif()