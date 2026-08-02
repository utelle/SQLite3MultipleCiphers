/*
** Name:        sqlite3mc.h
** Purpose:     Header file for SQLite3 Multiple Ciphers support
** Author:      Ulrich Telle
** Created:     2020-03-01
** Copyright:   (c) 2019-2026 Ulrich Telle
** License:     MIT
*/

#ifndef SQLITE3MC_H_
#define SQLITE3MC_H_

/*
** Define SQLite3 Multiple Ciphers version information
*/
#include "sqlite3mc_version.h"

/*
** Define SQLite3 API
*/
#include "sqlite3.h"

#ifdef SQLITE_USER_AUTHENTICATION
#undef SQLITE_USER_AUTHENTICATION
#endif

/*
** Symbols for ciphers
*/
#define CODEC_TYPE_UNKNOWN     0
#define CODEC_TYPE_AES128      1
#define CODEC_TYPE_AES256      2
#define CODEC_TYPE_CHACHA20    3
#define CODEC_TYPE_SQLCIPHER   4
#define CODEC_TYPE_RC4         5
#define CODEC_TYPE_ASCON128    6
#define CODEC_TYPE_AEGIS       7
#define CODEC_TYPE_MAX_BUILTIN 7

/*
** Definition of API functions
*/

/*
** Define Windows specific SQLite API functions (not defined in sqlite3.h)
*/
#if SQLITE_OS_WIN == 1

#ifdef __cplusplus
extern "C" {
#endif

SQLITE_API int sqlite3_win32_set_directory(unsigned long type, void* zValue);

#ifdef __cplusplus
}
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
SQLITE_API int sqlite3mc_cipher_count();
SQLITE_API int sqlite3mc_cipher_index(const char* cipherName);
SQLITE_API const char* sqlite3mc_cipher_name(int cipherIndex);
SQLITE_API int sqlite3mc_cipher_name_copy(int cipherIndex, char* cipherName, int maxCipherNameSize);
SQLITE_API int sqlite3mc_config(sqlite3* db, const char* paramName, int newValue);
SQLITE_API int sqlite3mc_config_cipher(sqlite3* db, const char* cipherName, const char* paramName, int newValue);
SQLITE_API unsigned char* sqlite3mc_codec_data(sqlite3* db, const char* zDbName, const char* paramName);
SQLITE_API const char* sqlite3mc_version();

#ifdef SQLITE3MC_WXSQLITE3_COMPATIBLE
SQLITE_API int wxsqlite3_config(sqlite3* db, const char* paramName, int newValue);
SQLITE_API int wxsqlite3_config_cipher(sqlite3* db, const char* cipherName, const char* paramName, int newValue);
SQLITE_API unsigned char* wxsqlite3_codec_data(sqlite3* db, const char* zDbName, const char* paramName);
#endif

/*
** Structures and functions to dynamically register a cipher
*/

/*
** Structure for a single cipher configuration parameter
**
** Components:
**   m_name      - name of parameter (1st char = alpha, rest = alphanumeric or underscore, max 63 characters)
**   m_value     - current/transient parameter value
**   m_default   - default parameter value
**   m_minValue  - minimum valid parameter value
**   m_maxValue  - maximum valid parameter value
*/
typedef struct _CipherParams
{
  const char* m_name;
  int   m_value;
  int   m_default;
  int   m_minValue;
  int   m_maxValue;
} CipherParams;

/*
** Structure for a cipher API
**
** Components:
**   m_name            - name of cipher (1st char = alpha, rest = alphanumeric or underscore, max 63 characters)
**   m_allocateCipher  - Function pointer for function AllocateCipher
**   m_freeCipher      - Function pointer for function FreeCipher
**   m_cloneCipher     - Function pointer for function CloneCipher
**   m_getLegacy       - Function pointer for function GetLegacy
**   m_getPageSize     - Function pointer for function GetPageSize
**   m_getReserved     - Function pointer for function GetReserved
**   m_getSalt         - Function pointer for function GetSalt
**   m_generateKey     - Function pointer for function GenerateKey
**   m_encryptPage     - Function pointer for function EncryptPage
**   m_decryptPage     - Function pointer for function DecryptPage
*/

typedef struct BtShared BtSharedMC;

typedef void* (*AllocateCipher_t)(sqlite3* db);
typedef void  (*FreeCipher_t)(void* cipher);
typedef void  (*CloneCipher_t)(void* cipherTo, void* cipherFrom);
typedef int   (*GetLegacy_t)(void* cipher);
typedef int   (*GetPageSize_t)(void* cipher);
typedef int   (*GetReserved_t)(void* cipher);
typedef unsigned char* (*GetSalt_t)(void* cipher);
typedef void  (*GenerateKey_t)(void* cipher, char* userPassword, int passwordLength, int rekey, unsigned char* cipherSalt);
typedef int   (*EncryptPage_t)(void* cipher, int page, unsigned char* data, int len, int reserved);
typedef int   (*DecryptPage_t)(void* cipher, int page, unsigned char* data, int len, int reserved, int hmacCheck);

typedef struct _CipherDescriptor
{
  const char*      m_name;
  AllocateCipher_t m_allocateCipher;
  FreeCipher_t     m_freeCipher;
  CloneCipher_t    m_cloneCipher;
  GetLegacy_t      m_getLegacy;
  GetPageSize_t    m_getPageSize;
  GetReserved_t    m_getReserved;
  GetSalt_t        m_getSalt;
  GenerateKey_t    m_generateKey;
  EncryptPage_t    m_encryptPage;
  DecryptPage_t    m_decryptPage;
} CipherDescriptor;

/*
** Register a cipher
**
** Arguments:
**   desc         - Cipher descriptor structure
**   params       - Cipher configuration parameter table
**   makeDefault  - flag whether to make the cipher the default cipher
**
** Returns:
**   SQLITE_OK     - the cipher could be registered successfully
**   SQLITE_ERROR  - the cipher could not be registered
*/
SQLITE_API int sqlite3mc_register_cipher(const CipherDescriptor* desc, const CipherParams* params, int makeDefault);

#ifdef __cplusplus
}
#endif

/*
** Define public SQLite3 Multiple Ciphers VFS interface
*/
#include "sqlite3mc_vfs.h"

/*
** Dispatch table support
*/

#ifdef SQLITE3MC_USE_DISPATCH_TABLE

/*
** Instead of making the SQLite symbols public dispatch tables can be
** used. In that case only the pointers to the dispatch tables are
** made public, hiding all other SQLite symbols. This is useful for
** modules which want to use an embedded SQLite version without
** conflicts with other SQLite implementation.
**
** The only rule to obey is that such an embedded SQLite instance
** should not access the same database files as a separate SQLite
** instance within the same process, because that could lead to
** database corruption.
**
** Define symbol SQLITE3MC_USE_DISPATCH_TABLE to activate the use of
** dispatch tables.
**
** Define symbol SQLITE3MC_API_TABLE_PREFIX to specify your own
** global symbols for the dispatch tables to avoid name clashes.
**
** Example: #define SQLITE3MC_API_TABLE_PREFIX MyApplication
**
** The default prefix is "sqlite3mc".
*/

#ifndef SQLITE3MC_API_TABLE_PREFIX
#define SQLITE3MC_API_TABLE_PREFIX  sqlite3mc
#endif

#define SQLITE3MC_CONCAT(A,B) SQLITE3MC_CONCAT_(A,B)
#define SQLITE3MC_CONCAT_(A,B) A##B
#define SQLITE3MC_API_TABLE(name) SQLITE3MC_CONCAT(SQLITE3MC_API_TABLE_PREFIX,SQLITE3MC_CONCAT(_,name))

#define SQLITE3MC_API_TABLE_EXT  SQLITE3MC_API_TABLE(api_ext)
#define SQLITE3MC_API_TABLE_CORE SQLITE3MC_API_TABLE(api_core)
#define SQLITE3MC_API_TABLE_MC   SQLITE3MC_API_TABLE(api_mc)

/* Define the dispatch table name for sqlite3ext.h */
#define sqlite3_api SQLITE3MC_API_TABLE_EXT

#include "sqlite3ext.h"

struct sqlite3mc_core_routines {
  int (*initialize)(void);
  int (*shutdown)(void);
  int (*config)(int, ...);
  int (*enable_load_extension)(sqlite3*, int);
  int (*memory_alarm)(void(*)(void*, sqlite3_int64, int), void*, sqlite3_int64);
  int (*mutex_held)(sqlite3_mutex*);
  int (*mutex_notheld)(sqlite3_mutex*);
  int (*os_init)(void);
  int (*os_end)(void);
  int (*preupdate_blobwrite)(sqlite3*);
  int (*preupdate_count)(sqlite3*);
  int (*preupdate_depth)(sqlite3*);
  void* (*preupdate_hook)(sqlite3*,
                          void(*xPreUpdate)(void*, sqlite3*, int, char const*, char const*, sqlite3_int64, sqlite3_int64),
                          void*);
  int (*preupdate_old)(sqlite3*, int, sqlite3_value**);
  int (*preupdate_new)(sqlite3*, int, sqlite3_value**);

  int (*snapshot_cmp)(sqlite3_snapshot*, sqlite3_snapshot*);
  void (*snapshot_free)(sqlite3_snapshot*);
  int (*snapshot_get)(sqlite3*, const char*, sqlite3_snapshot**);
  int (*snapshot_open)(sqlite3*, const char*, sqlite3_snapshot*);
  int (*snapshot_recover)(sqlite3*, const char*);

  int (*stmt_scanstatus)(sqlite3_stmt*, int, int, void*);
  int (*stmt_scanstatus_v2)(sqlite3_stmt*, int, int, int, void*);
  void (*stmt_scanstatus_reset)(sqlite3_stmt*);

  int (*win32_set_directory)(unsigned long type, void* zValue);
  int (*win32_set_directory8)(unsigned long type, const char* zValue);
  int (*win32_set_directory16)(unsigned long type, const void* zValue);
};

struct sqlite3mc_api_routines {
    void (*activate_see)(const char* zPassPhrase);
    int (*key)(sqlite3* db, const void* pKey, int nKey);
    int (*key_v2)(sqlite3*, const char* zDbName, const void* pKey, int nKey);
    int (*rekey)(sqlite3*, const void* pKey, int nKey);
    int (*rekey_v2)(sqlite3*, const char* zDbName, const void* pKey, int nKey);

    const char* (*mc_version)();
    int (*mc_cipher_count)();
    int (*mc_cipher_index)(const char* cipherName);
    const char* (*mc_cipher_name)(int cipherIndex);
    int (*mc_cipher_name_copy)(int cipherIndex, char* cipherName, int maxCipherNameSize);
    int (*mc_config)(sqlite3* db, const char* paramName, int newValue);
    int (*mc_config_cipher)(sqlite3* db, const char* cipherName, const char* paramName, int newValue);
    unsigned char* (*mc_codec_data)(sqlite3* db, const char* zDbName, const char* paramName);

    int (*mc_vfs_create)(const char* zVfsReal, int makeDefault);
    void (*mc_vfs_destroy)(const char* zName);
    void (*mc_vfs_shutdown)();
};

typedef struct sqlite3mc_core_routines sqlite3mc_core_routines;
typedef struct sqlite3mc_api_routines sqlite3mc_api_routines;

#ifndef SQLITE3MC_DISPATCH_API
#if defined(_WIN32)
#define SQLITE3MC_DISPATCH_API __declspec(dllexport)
#else
#define SQLITE3MC_DISPATCH_API
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

SQLITE3MC_DISPATCH_API extern const sqlite3_api_routines*    SQLITE3MC_API_TABLE_EXT;
SQLITE3MC_DISPATCH_API extern const sqlite3mc_core_routines* SQLITE3MC_API_TABLE_CORE;
SQLITE3MC_DISPATCH_API extern const sqlite3mc_api_routines*  SQLITE3MC_API_TABLE_MC;

#ifdef __cplusplus
}  /* End of the 'extern "C"' block */
#endif

#if !defined(SQLITE_CORE)

/* SQLite core API - not defined in sqlite3ext.h */

#define sqlite3_initialize            SQLITE3MC_API_TABLE_CORE->initialize
#define sqlite3_shutdown              SQLITE3MC_API_TABLE_CORE->shutdown
#define sqlite3_config                SQLITE3MC_API_TABLE_CORE->config
#define sqlite3_enable_load_extension SQLITE3MC_API_TABLE_CORE->enable_load_extension
#define sqlite3_memory_alarm          SQLITE3MC_API_TABLE_CORE->memory_alarm
#define sqlite3_mutex_held            SQLITE3MC_API_TABLE_CORE->mutex_held
#define sqlite3_mutex_notheld         SQLITE3MC_API_TABLE_CORE->mutex_notheld
#define sqlite3_os_init               SQLITE3MC_API_TABLE_CORE->os_init
#define sqlite3_os_end                SQLITE3MC_API_TABLE_CORE->os_end
#define sqlite3_preupdate_blobwrite   SQLITE3MC_API_TABLE_CORE->preupdate_blobwrite
#define sqlite3_preupdate_count       SQLITE3MC_API_TABLE_CORE->preupdate_count
#define sqlite3_preupdate_depth       SQLITE3MC_API_TABLE_CORE->preupdate_depth
#define sqlite3_preupdate_hook        SQLITE3MC_API_TABLE_CORE->preupdate_hook
#define sqlite3_preupdate_old         SQLITE3MC_API_TABLE_CORE->preupdate_old
#define sqlite3_preupdate_new         SQLITE3MC_API_TABLE_CORE->preupdate_new

#define sqlite3_snapshot_cmp          SQLITE3MC_API_TABLE_CORE->snapshot_cmp
#define sqlite3_snapshot_free         SQLITE3MC_API_TABLE_CORE->snapshot_free
#define sqlite3_snapshot_get          SQLITE3MC_API_TABLE_CORE->snapshot_get
#define sqlite3_snapshot_open         SQLITE3MC_API_TABLE_CORE->snapshot_open
#define sqlite3_snapshot_recover      SQLITE3MC_API_TABLE_CORE->snapshot_recover

#define sqlite3_stmt_scanstatus       SQLITE3MC_API_TABLE_CORE->stmt_scanstatus
#define sqlite3_stmt_scanstatus_v2    SQLITE3MC_API_TABLE_CORE->stmt_scanstatus_v2
#define sqlite3_stmt_scanstatus_reset SQLITE3MC_API_TABLE_CORE->stmt_scanstatus_reset

#define sqlite3_win32_set_directory   SQLITE3MC_API_TABLE_CORE->win32_set_directory
#define sqlite3_win32_set_directory8  SQLITE3MC_API_TABLE_CORE->win32_set_directory8
#define sqlite3_win32_set_directory16 SQLITE3MC_API_TABLE_CORE->win32_set_directory16

/* SQLite3 Multiple Ciphers API */

#define sqlite3_activate_see        SQLITE3MC_API_TABLE_MC->activate_see
#define sqlite3_key                 SQLITE3MC_API_TABLE_MC->key
#define sqlite3_key_v2              SQLITE3MC_API_TABLE_MC->key_v2
#define sqlite3_rekey               SQLITE3MC_API_TABLE_MC->rekey
#define sqlite3_rekey_v2            SQLITE3MC_API_TABLE_MC->rekey_v2

#define sqlite3mc_version           SQLITE3MC_API_TABLE_MC->mc_version
#define sqlite3mc_cipher_count      SQLITE3MC_API_TABLE_MC->mc_cipher_count
#define sqlite3mc_cipher_index      SQLITE3MC_API_TABLE_MC->mc_cipher_index
#define sqlite3mc_cipher_name       SQLITE3MC_API_TABLE_MC->mc_cipher_name
#define sqlite3mc_cipher_name_copy  SQLITE3MC_API_TABLE_MC->mc_cipher_name_copy
#define sqlite3mc_config            SQLITE3MC_API_TABLE_MC->mc_config
#define sqlite3mc_config_cipher     SQLITE3MC_API_TABLE_MC->mc_config_cipher
#define sqlite3mc_codec_data        SQLITE3MC_API_TABLE_MC->mc_codec_data

#define sqlite3mc_vfs_create        SQLITE3MC_API_TABLE_MC->mc_vfs_create
#define sqlite3mc_vfs_destroy       SQLITE3MC_API_TABLE_MC->mc_vfs_destroy
#define sqlite3mc_vfs_shutdown      SQLITE3MC_API_TABLE_MC->mc_vfs_shutdown

#endif /* !SQLITE_CORE */

#endif /* SQLITE3MC_USE_DISPATCH_TABLE */

#endif /* SQLITE3MC_H_ */
