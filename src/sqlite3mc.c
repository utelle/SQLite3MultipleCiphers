/*
** Name:        sqlite3mc.c
** Purpose:     Amalgamation of the SQLite3 Multiple Ciphers encryption extension for SQLite
** Author:      Ulrich Telle
** Created:     2020-02-28
** Copyright:   (c) 2006-2020 Ulrich Telle
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
** Define function for extra initilization
**
** The extra initialization function registers an extension function
** which will be automatically executed for each new database connection.
*/

#define SQLITE_EXTRA_INIT sqlite3mc_initialize
#define SQLITE_EXTRA_SHUTDOWN sqlite3mc_terminate

int sqlite3mc_initialize(const char* arg);
void sqlite3mc_terminate(void);

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
#ifndef SQLITE_USER_AUTHENTICATION
#define SQLITE_USER_AUTHENTICATION 1
#endif

#if defined(_WIN32) || defined(WIN32)
#include <windows.h>

/* SQLite functions only needed on Win32 */
extern void sqlite3_win32_write_debug(const char *, int);
extern char *sqlite3_win32_unicode_to_utf8(LPCWSTR);
extern char *sqlite3_win32_mbcs_to_utf8(const char *);
extern char *sqlite3_win32_mbcs_to_utf8_v2(const char *, int);
extern char *sqlite3_win32_utf8_to_mbcs(const char *);
extern char *sqlite3_win32_utf8_to_mbcs_v2(const char *, int);
extern LPWSTR sqlite3_win32_utf8_to_unicode(const char *);
#endif

/*
** Include SQLite3 amalgamation
*/
#include "sqlite3patched.c"

/*
** Include SQLite3MultiCipher components 
*/
#include "sqlite3mc.h"

/*
** Crypto algorithms
*/
#include "md5.c"
#include "sha1.c"
#include "sha2.c"

#if HAVE_CIPHER_SQLCIPHER || HAVE_CIPHER_SQLCIPHER
#include "fastpbkdf2.c"

/* Prototypes for several crypto functions to make pedantic compilers happy */
void chacha20_xor(void* data, size_t n, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);
void poly1305(const uint8_t* msg, size_t n, const uint8_t key[32], uint8_t tag[16]);
int poly1305_tagcmp(const uint8_t tag1[16], const uint8_t tag2[16]);
void chacha20_rng(void* out, size_t n);

#include "chacha20poly1305.c"
#endif

#ifdef SQLITE_USER_AUTHENTICATION
#include "sqlite3userauth.h"
#include "userauth.c"
#endif

/*
** Declare function prototype for registering the codec extension functions
*/
static int
mcRegisterCodecExtensions(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);

/*
** Codec implementation
*/
#include "rijndael.c"
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
int RegisterExtensionFunctions(sqlite3 *db);
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
int sqlite3_csv_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);
#include "csv.c"
#endif

/*
** SHA3
*/
#ifdef SQLITE_ENABLE_SHA3
/* Prototype for initialization function of SHA3 extension */
#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_shathree_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);
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
int sqlite3_carray_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);
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
int sqlite3_fileio_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);

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
int sqlite3_series_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);
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
int sqlite3_uuid_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi);
#include "uuid.c"
#endif

/*
** Multi cipher VFS
*/
#include "sqlite3mc_vfs.c"

static int
mcRegisterCodecExtensions(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi)
{
  int rc = SQLITE_OK;
#if 0
  CodecParameter* codecParameterTable = sqlite3mcGetCodecParams(db);
#endif
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
  if (sqlite3_vfs_find(sqlite3mc_vfs_name()) == NULL)
  {
    sqlite3_vfs* vfsDefault = sqlite3_vfs_find(NULL);
    rc = sqlite3mc_vfs_initialize(vfsDefault, 1);
  }

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
  return rc;
}

void
sqlite3mc_terminate(void)
{
  sqlite3mc_vfs_terminate();
}
