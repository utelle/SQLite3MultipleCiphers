/*
** Name:        sqlite3mc.h
** Purpose:     Header file for SQLite3 Multiple Ciphers support
** Author:      Ulrich Telle
** Created:     2020-03-01
** Copyright:   (c) 2020 Ulrich Telle
** License:     MIT
*/

#ifndef SQLITE3MC_H_
#define SQLITE3MC_H_

#include "sqlite3.h"

/*
** Symbols for ciphers
*/
#define CODEC_TYPE_UNKNOWN   0
#define CODEC_TYPE_AES128    1
#define CODEC_TYPE_AES256    2
#define CODEC_TYPE_CHACHA20  3
#define CODEC_TYPE_SQLCIPHER 4
#define CODEC_TYPE_RC4       5
#define CODEC_TYPE_MAX       5

/*
** Definitions of supported ciphers
*/

/*
** Compatibility with wxSQLite3
*/
#ifdef WXSQLITE3_HAVE_CIPHER_AES_128_CBC
#define HAVE_CIPHER_AES_128_CBC WXSQLITE3_HAVE_CIPHER_AES_128_CBC
#endif

#ifdef WXSQLITE3_HAVE_CIPHER_AES_256_CBC
#define HAVE_CIPHER_AES_256_CBC WXSQLITE3_HAVE_CIPHER_AES_256_CBC
#endif

#ifdef WXSQLITE3_HAVE_CIPHER_CHACHA20
#define HAVE_CIPHER_CHACHA20 WXSQLITE3_HAVE_CIPHER_CHACHA20
#endif

#ifdef WXSQLITE3_HAVE_CIPHER_SQLCIPHER
#define HAVE_CIPHER_SQLCIPHER WXSQLITE3_HAVE_CIPHER_SQLCIPHER
#endif

#ifdef WXSQLITE3_HAVE_CIPHER_RC4
#define HAVE_CIPHER_RC4 WXSQLITE3_HAVE_CIPHER_RC4
#endif

/*
** Actual definitions of supported ciphers
*/
#ifndef HAVE_CIPHER_AES_128_CBC
#define HAVE_CIPHER_AES_128_CBC 1
#endif

#ifndef HAVE_CIPHER_AES_256_CBC
#define HAVE_CIPHER_AES_256_CBC 1
#endif

#ifndef HAVE_CIPHER_CHACHA20
#define HAVE_CIPHER_CHACHA20 1
#endif

#ifndef HAVE_CIPHER_SQLCIPHER
#define HAVE_CIPHER_SQLCIPHER 1
#endif

#ifndef HAVE_CIPHER_RC4
#define HAVE_CIPHER_RC4 1
#endif

/*
** Check that at least one cipher is be supported
*/
#if HAVE_CIPHER_AES_128_CBC == 0 &&  \
    HAVE_CIPHER_AES_256_CBC == 0 &&  \
    HAVE_CIPHER_CHACHA20    == 0 &&  \
    HAVE_CIPHER_SQLCIPHER   == 0 &&  \
    HAVE_CIPHER_RC4         == 0
#error Enable at least one cipher scheme!
#endif

/*
** Definition of API functions
*/

/*
** Define Windows specific SQLite API functions (not defined in sqlite3.h)
*/
#if SQLITE_VERSION_NUMBER >= 3007014
#if SQLITE_OS_WIN == 1
#ifdef __cplusplus
extern "C" {
#endif
#if SQLITE_VERSION_NUMBER >= 3024000
SQLITE_API int sqlite3_win32_set_directory(unsigned long type, void* zValue);
#else
SQLITE_API int sqlite3_win32_set_directory(DWORD type, LPCWSTR zValue);
#endif
#ifdef __cplusplus
}
#endif
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
** Specify the key for an encrypted database.
** This routine should be called right after sqlite3_open().
**
** Arguments:
**   db       - Database to be encrypted
**   zDbName  - Name of the database (e.g. "main")
**   pKey     - Passphrase
**   nKey     - Length of passphrase
*/
SQLITE_API int sqlite3_key(sqlite3* db, const void* pKey, int nKey);
SQLITE_API int sqlite3_key_v2(sqlite3* db, const char* zDbName, const void* pKey, int nKey);

/*
** Change the key on an open database.
** If the current database is not encrypted, this routine will encrypt
** it.  If pNew==0 or nNew==0, the database is decrypted.
**
** Arguments:
**   db       - Database to be encrypted
**   zDbName  - Name of the database (e.g. "main")
**   pKey     - Passphrase
**   nKey     - Length of passphrase
*/
SQLITE_API int sqlite3_rekey(sqlite3* db, const void* pKey, int nKey);
SQLITE_API int sqlite3_rekey_v2(sqlite3* db, const char* zDbName, const void* pKey, int nKey);

/*
** Specify the activation key for a SEE database.
** Unless activated, none of the SEE routines will work.
**
** Arguments:
**   zPassPhrase  - Activation phrase
**
** Note: Provided only for API compatibility with SEE.
** Encryption support of SQLite3 Multi Cipher is always enabled.
*/
SQLITE_API void sqlite3_activate_see(const char* zPassPhrase);

/*
** Define functions for the configuration of the wxSQLite3 encryption extension
*/
SQLITE_API int sqlite3mc_config(sqlite3* db, const char* paramName, int newValue);
SQLITE_API int sqlite3mc_config_cipher(sqlite3* db, const char* cipherName, const char* paramName, int newValue);
SQLITE_API unsigned char* sqlite3mc_codec_data(sqlite3* db, const char* zDbName, const char* paramName);

#ifdef SQLITE3MC_WXSQLITE3_COMPATIBLE
SQLITE_API int wxsqlite3_config(sqlite3* db, const char* paramName, int newValue);
SQLITE_API int wxsqlite3_config_cipher(sqlite3* db, const char* cipherName, const char* paramName, int newValue);
SQLITE_API unsigned char* wxsqlite3_codec_data(sqlite3* db, const char* zDbName, const char* paramName);
#endif

#ifdef __cplusplus
}
#endif

#endif
