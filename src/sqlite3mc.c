/*
** Name:        sqlite3mc.c
** Purpose:     Amalgamation of the SQLite3 Multiple Ciphers encryption extension for SQLite
** Author:      Ulrich Telle
** Created:     2020-02-28
** Copyright:   (c) 2006-2021 Ulrich Telle
** License:     MIT
*/

/*
** Enable SQLite debug assertions if requested
*/
#ifndef SQLITE_DEBUG
#if defined(SQLITE_ENABLE_DEBUG) && (SQLITE_ENABLE_DEBUG == 1)
#define SQLITE_DEBUG 1
#endif
#endif

/*
** Define function for extra initialization and extra shutdown
**
** The extra initialization function registers an extension function
** which will be automatically executed for each new database connection.
**
** The extra shutdown function will be executed on the invocation of sqlite3_shutdown.
** All created multiple ciphers VFSs will be unregistered and destroyed.
*/

#define SQLITE_EXTRA_INIT sqlite3mc_initialize
#define SQLITE_EXTRA_SHUTDOWN sqlite3mc_shutdown

int sqlite3mc_initialize(const char* arg);
void sqlite3mc_shutdown(void);

/*
** To enable the extension functions define SQLITE_ENABLE_EXTFUNC on compiling this module
** To enable the reading CSV files define SQLITE_ENABLE_CSV on compiling this module
** To enable the SHA3 support define SQLITE_ENABLE_SHA3 on compiling this module
** To enable the CARRAY support define SQLITE_ENABLE_CARRAY on compiling this module
** To enable the FILEIO support define SQLITE_ENABLE_FILEIO on compiling this module
** To enable the SERIES support define SQLITE_ENABLE_SERIES on compiling this module
** To enable the UUID support define SQLITE_ENABLE_UUID on compiling this module
*/

/*
** Enable the user authentication feature
*/
#if !SQLITE_USER_AUTHENTICATION
/* Option not defined or explicitly disabled */
#ifndef SQLITE_USER_AUTHENTICATION
/* Option not defined, therefore enable by default */
#define SQLITE_USER_AUTHENTICATION 1
#else
/* Option defined and disabled, therefore undefine option */
#undef SQLITE_USER_AUTHENTICATION
#endif
#endif

#if defined(_WIN32) || defined(WIN32)

#ifndef SQLITE3MC_USE_RAND_S
#define SQLITE3MC_USE_RAND_S 1
#endif

#if SQLITE3MC_USE_RAND_S
/* Force header stdlib.h to define rand_s() */
#if !defined(_CRT_RAND_S)
#define _CRT_RAND_S
#endif
#endif

#ifndef SQLITE_API
#define SQLITE_API
#endif

#include <windows.h>

/* SQLite functions only needed on Win32 */
extern SQLITE_API void sqlite3_win32_write_debug(const char*, int);
extern SQLITE_API char *sqlite3_win32_unicode_to_utf8(LPCWSTR);
extern SQLITE_API char *sqlite3_win32_mbcs_to_utf8(const char*);
extern SQLITE_API char *sqlite3_win32_mbcs_to_utf8_v2(const char*, int);
extern SQLITE_API char *sqlite3_win32_utf8_to_mbcs(const char*);
extern SQLITE_API char *sqlite3_win32_utf8_to_mbcs_v2(const char*, int);
extern SQLITE_API LPWSTR sqlite3_win32_utf8_to_unicode(const char*);
#endif

/*
** Include SQLite3 amalgamation
*/
#include "sqlite3patched.c"

/*
** Include SQLite3MultiCipher components 
*/
#include "sqlite3mc_config.h"
#include "sqlite3mc.h"

SQLITE_API const char*
sqlite3mc_version()
{
  static const char* version = SQLITE3MC_VERSION_STRING;
  return version;
}

SQLITE_PRIVATE void
sqlite3mcVersion(sqlite3_context* context, int argc, sqlite3_value** argv)
{
  assert(argc == 0);
  sqlite3_result_text(context, sqlite3mc_version(), -1, 0);
}

/*
** Crypto algorithms
*/
#include "md5.c"
#include "sha1.c"
#include "sha2.c"

#if HAVE_CIPHER_CHACHA20 || HAVE_CIPHER_SQLCIPHER
#include "fastpbkdf2.c"

/* Prototypes for several crypto functions to make pedantic compilers happy */
void chacha20_xor(void* data, size_t n, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);
void poly1305(const uint8_t* msg, size_t n, const uint8_t key[32], uint8_t tag[16]);
int poly1305_tagcmp(const uint8_t tag1[16], const uint8_t tag2[16]);
void chacha20_rng(void* out, size_t n);

#include "chacha20poly1305.c"
#endif

#ifdef SQLITE_USER_AUTHENTICATION
#include "userauth.c"
#endif

/*
** Declare function prototype for registering the codec extension functions
*/
static int
mcRegisterCodecExtensions(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);

/*
** Codec implementation
*/
#if HAVE_CIPHER_AES_128_CBC || HAVE_CIPHER_AES_256_CBC || HAVE_CIPHER_SQLCIPHER
#include "rijndael.c"
#endif
#include "codec_algos.c"

#include "cipher_wxaes128.c"
#include "cipher_wxaes256.c"
#include "cipher_chacha20.c"
#include "cipher_sqlcipher.c"
#include "cipher_sds_rc4.c"
#include "cipher_common.c"
#include "cipher_config.c"

#include "codecext.c"

/*
** Extension functions
*/
#ifdef SQLITE_ENABLE_EXTFUNC
/* Prototype for initialization function of EXTENSIONFUNCTIONS extension */
int RegisterExtensionFunctions(sqlite3* db);
#include "extensionfunctions.c"
#endif

/*
** CSV import
*/
#ifdef SQLITE_ENABLE_CSV
/* Prototype for initialization function of CSV extension */
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_csv_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);
#include "csv.c"
#endif

/*
** VSV import
*/
#ifdef SQLITE_ENABLE_VSV
/* Prototype for initialization function of VSV extension */
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_vsv_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);
#include "vsv.c"
#endif

/*
** SHA3
*/
#ifdef SQLITE_ENABLE_SHA3
/* Prototype for initialization function of SHA3 extension */
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_shathree_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);
#include "shathree.c"
#endif

/*
** CARRAY
*/
#ifdef SQLITE_ENABLE_CARRAY
/* Prototype for initialization function of CARRAY extension */
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_carray_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);
#include "carray.c"
#endif

/*
** FILEIO
*/
#ifdef SQLITE_ENABLE_FILEIO
/* Prototype for initialization function of FILEIO extension */
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_fileio_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);

/* MinGW specifics */
#if (!defined(_WIN32) && !defined(WIN32)) || defined(__MINGW32__)
# include <unistd.h>
# include <dirent.h>
# if defined(__MINGW32__)
#  define DIRENT dirent
#  ifndef S_ISLNK
#   define S_ISLNK(mode) (0)
#  endif
# endif
#endif

#include "test_windirent.c"
#include "fileio.c"
#endif

/*
** SERIES
*/
#ifdef SQLITE_ENABLE_SERIES
/* Prototype for initialization function of SERIES extension */
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_series_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);
#include "series.c"
#endif

/*
** UUID
*/
#ifdef SQLITE_ENABLE_UUID
/* Prototype for initialization function of UUID extension */
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_uuid_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);
#include "uuid.c"
#endif

/*
** REGEXP
*/
#ifdef SQLITE_ENABLE_REGEXP
/* Prototype for initialization function of REGEXP extension */
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_regexp_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);
#include "regexp.c"
#endif

/*
** Multi cipher VFS
*/
#include "sqlite3mc_vfs.c"

static int
mcRegisterCodecExtensions(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi)
{
  int rc = SQLITE_OK;
  CodecParameter* codecParameterTable = NULL;

  if (sqlite3FindFunction(db, "sqlite3mc_config_table", 1, SQLITE_UTF8, 0) != NULL)
  {
    /* Return if codec extension functions are already defined */
    return rc;
  }

  /* Generate copy of global codec parameter table */
  codecParameterTable = sqlite3mcCloneCodecParameterTable();
  rc = (codecParameterTable != NULL) ? SQLITE_OK : SQLITE_NOMEM;
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_create_function_v2(db, "sqlite3mc_config_table", 0, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                    codecParameterTable, sqlite3mcConfigTable, 0, 0, (void(*)(void*)) sqlite3mcFreeCodecParameterTable);
  }

  rc = (codecParameterTable != NULL) ? SQLITE_OK : SQLITE_NOMEM;
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_create_function(db, "sqlite3mc_config", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                 codecParameterTable, sqlite3mcConfigParams, 0, 0);
  }
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_create_function(db, "sqlite3mc_config", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                 codecParameterTable, sqlite3mcConfigParams, 0, 0);
  }
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_create_function(db, "sqlite3mc_config", 3, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                 codecParameterTable, sqlite3mcConfigParams, 0, 0);
  }
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_create_function(db, "sqlite3mc_codec_data", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                 NULL, sqlite3mcCodecDataSql, 0, 0);
  }
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_create_function(db, "sqlite3mc_codec_data", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                 NULL, sqlite3mcCodecDataSql, 0, 0);
  }
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_create_function(db, "sqlite3mc_version", 0, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                 NULL, sqlite3mcVersion, 0, 0);
  }
  return rc;
}

#ifdef SQLITE_ENABLE_EXTFUNC
static int
sqlite3_extfunc_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi)
{
  return RegisterExtensionFunctions(db);
}
#endif

int
sqlite3mc_initialize(const char* arg)
{
  int rc = SQLITE_OK;

  /*
  ** Initialize and register MultiCipher VFS as default VFS
  ** if it isn't already registered
  */
  rc = sqlite3mc_vfs_create(NULL, 1);

  /*
  ** Register Multi Cipher extension
  */
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) mcRegisterCodecExtensions);
  }
#ifdef SQLITE_ENABLE_EXTFUNC
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) sqlite3_extfunc_init);
  }
#endif
#ifdef SQLITE_ENABLE_CSV
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) sqlite3_csv_init);
  }
#endif
#ifdef SQLITE_ENABLE_VSV
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) sqlite3_vsv_init);
  }
#endif
#ifdef SQLITE_ENABLE_SHA3
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) sqlite3_shathree_init);
  }
#endif
#ifdef SQLITE_ENABLE_CARRAY
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) sqlite3_carray_init);
  }
#endif
#ifdef SQLITE_ENABLE_FILEIO
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) sqlite3_fileio_init);
  }
#endif
#ifdef SQLITE_ENABLE_SERIES
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) sqlite3_series_init);
  }
#endif
#ifdef SQLITE_ENABLE_UUID
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) sqlite3_uuid_init);
  }
#endif
#ifdef SQLITE_ENABLE_REGEXP
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_auto_extension((void(*)(void)) sqlite3_regexp_init);
  }
#endif
  return rc;
}

void
sqlite3mc_shutdown(void)
{
  sqlite3mc_vfs_shutdown();
}

/*
** TCL/TK Shell
*/
#ifdef TCLSH
#define BUILD_tcl
#include "tclsqlite.c"
#endif
