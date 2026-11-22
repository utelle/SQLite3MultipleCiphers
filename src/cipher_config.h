/*
** Name:        cipher_config.h
** Purpose:     Header for the cipher configuration of SQLite3 Multiple Ciphers
** Author:      Ulrich Telle
** Created:     2020-03-10
** Copyright:   (c) 2006-2020 Ulrich Telle
** License:     MIT
*/

#ifndef CIPHER_CONFIG_H_
#define CIPHER_CONFIG_H_

#include "sqlite3mc.h"

SQLITE_PRIVATE void sqlite3mcConfigTable(sqlite3_context* context, int argc, sqlite3_value** argv);
SQLITE_PRIVATE CodecParameter* sqlite3mcGetCodecParams(sqlite3* db);

/* Forward declaration */
SQLITE_PRIVATE unsigned char* sqlite3mcGetSaltWriteCipher(Codec* codec);

SQLITE_PRIVATE void sqlite3mcCodecDataSql(sqlite3_context* context, int argc, sqlite3_value** argv);
SQLITE_PRIVATE void sqlite3mcConfigParams(sqlite3_context* context, int argc, sqlite3_value** argv);
SQLITE_PRIVATE int sqlite3mcConfigureFromUri(sqlite3* db, const char *zDbName, int configDefault);

SQLITE_PRIVATE int sqlite3mcFileControlPragma(sqlite3* db, const char* zDbName, int op, void* pArg);
SQLITE_PRIVATE int sqlite3mcCodecQueryParameters(sqlite3* db, const char* zDb, const char* zUri, int* rc);
SQLITE_PRIVATE int sqlite3mcHandleAttachKey(sqlite3* db, const char* zName, const char* zPath, sqlite3_value* pKey, char** zErrDyn);
SQLITE_PRIVATE int sqlite3mcHandleMainKey(sqlite3* db, const char* zPath);

/*
** Unified access to the configuration parameters of the ciphers
**
** All ways to configure the parameters (C API, SQL function, URI parameters,
** PRAGMAs) are translated into a CipherConfigRequest and executed by the one
** function sqlite3mcConfigExec. The ways only differ in how their input is
** parsed and how the result or an error is reported.
*/

typedef enum _CipherParamScope
{
  CIPHER_PARAM_SCOPE_GLOBAL = 0, /* parameter common to all ciphers */
  CIPHER_PARAM_SCOPE_CIPHER,     /* parameter of the cipher named in zCipher */
  CIPHER_PARAM_SCOPE_AUTO        /* common parameter first, then parameter of the current cipher (PRAGMA) */
} CipherParamScope;

typedef enum _CipherParamValueType
{
  CIPHER_PARAM_VALUE_NONE = 0,
  CIPHER_PARAM_VALUE_INT,
  CIPHER_PARAM_VALUE_TEXT        /* text: alias name or number */
} CipherParamValueType;

enum
{
  CIPHER_CONFIG_OK = 0,
  CIPHER_CONFIG_ERR_NODB,            /* change requested without a database connection */
  CIPHER_CONFIG_ERR_NOTABLE,         /* parameter table of the connection not available */
  CIPHER_CONFIG_ERR_UNKNOWN_CIPHER,
  CIPHER_CONFIG_ERR_UNKNOWN_PARAM,
  CIPHER_CONFIG_ERR_SLOT_READONLY,   /* write to min: or max: */
  CIPHER_CONFIG_ERR_BAD_VALUE,       /* not a number, unknown alias, wrong type */
  CIPHER_CONFIG_ERR_RANGE,           /* outside the valid range or not an available enumeration value */
  CIPHER_CONFIG_ERR_CONSTRAINT       /* rejected by a flag or by the check function of the parameter */
};

typedef struct _CipherConfigRequest
{
  sqlite3*             db;           /* NULL: process wide table, read only */
  CipherParamScope     eScope;
  const char*          zCipher;      /* only for CIPHER_PARAM_SCOPE_CIPHER */
  const char*          zParam;       /* parameter name WITHOUT prefix */
  CipherParamValueSlot eSlot;
  int                  isSet;        /* 0 = get, 1 = set */
  CipherParamValueType eValueType;
  sqlite3_int64        iValue;
  const char*          zValue;
  int                  strictNames;  /* integers are not accepted for parameters with flag NAME_ONLY (SQL function) */
  int                  dryRun;       /* set: check the value (conversion, range, constraints), but change nothing */
} CipherConfigRequest;

typedef struct _CipherConfigResult
{
  int                    eErr;            /* CIPHER_CONFIG_OK or CIPHER_CONFIG_ERR_* */
  int                    iValue;          /* content of the addressed slot after the call (also after a rejected
                                          ** set); -1 if the parameter was not found */
  const CipherParams*    pParam;          /* resolved parameter, or NULL */
  const char*            zCipher;         /* resolved cipher name or "global" */
  int                    defaultIgnored;  /* set of the default value was not allowed, only transient value changed */
} CipherConfigResult;

/* Parameter name with optional prefix "default:", "min:" or "max:" */
typedef struct _CipherParamSpec
{
  CipherParamValueSlot eSlot;
  const char*          zName;
} CipherParamSpec;

SQLITE_PRIVATE int sqlite3mcConfigExec(const CipherConfigRequest* request, CipherConfigResult* result);
SQLITE_PRIVATE int sqlite3mcParseParamSpec(const char* zSpec, CipherParamSpec* spec);
SQLITE_PRIVATE char* sqlite3mcConfigErrorMsg(const CipherConfigRequest* request, const CipherConfigResult* result);
SQLITE_PRIVATE int sqlite3mcPragmaConfig(sqlite3* db, int dbIndex, const char* zName, const char* zValue, char** pzOut);

#endif
