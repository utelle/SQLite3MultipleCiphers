/*
** Name:        cipher_config.c
** Purpose:     Configuration of SQLite codecs
** Author:      Ulrich Telle
** Created:     2020-03-02
** Copyright:   (c) 2006-2026 Ulrich Telle
** License:     MIT
*/

#include "cipher_common.h"
#include "cipher_config.h"

/* --- Codec --- */

SQLITE_PRIVATE int
sqlite3mcGetGlobalCipherCount();

SQLITE_PRIVATE Codec*
sqlite3mcGetCodec(sqlite3* db, const char* zDbName);

SQLITE_PRIVATE void
sqlite3mcConfigTable(sqlite3_context* context, int argc, sqlite3_value** argv)
{
  CodecParameter* codecParams = (CodecParameter*) sqlite3_user_data(context);
  assert(argc == 0);
  sqlite3_result_pointer(context, codecParams, "sqlite3mc_codec_params", 0);
}

SQLITE_PRIVATE CodecParameter*
sqlite3mcGetCodecParams(sqlite3* db)
{
  CodecParameter* codecParams = (db->mcConfig != NULL) ? ((CodecConfig*)db->mcConfig)->m_globalConfigTable : NULL;
  return codecParams;
}

/*
** Unified parameter configuration
*/

/*
** Overview
**
** The configuration parameters can be accessed in four ways:
**   1) C API:         sqlite3mc_config, sqlite3mc_config_cipher
**   2) SQL function:  sqlite3mc_config with 1 to 3 arguments
**   3) URI parameters
**   4) PRAGMAs
** Every way translates its input into a CipherConfigRequest. The request is
** executed by sqlite3mcConfigExec, which contains all the logic (locking,
** resolving cipher and parameter, converting and validating the value, setting
** or getting the addressed slot). A way only decides how its input is parsed and
** how the result or an error is reported.
**
** Parameters have 4 slots (see CipherParamValueSlot). Prefixes "default:", "min:"
** and "max:" of a parameter name are only parsed by the textual interfaces of the
** C API and the SQL function. PRAGMA and URI choose the slot directly.
**
** Additional properties of a parameter (text aliases for values, validation,
** behaviour flags) are part of the structure CipherParams (m_flags, m_aliases, m_ops).
*/

/* --- Helpers --- */

static int
cipherCfgMaxValue(const CipherParams* param)
{
  /* The upper bound can be dynamic (e.g. number of compiled in ciphers) */
  if (param->m_ops != NULL && param->m_ops->m_count != NULL)
  {
    return param->m_ops->m_count();
  }
  return param->m_maxValue;
}

static int
cipherCfgSlotValue(const CipherParams* param, CipherParamValueSlot eSlot)
{
  switch (eSlot)
  {
    case CIPHER_PARAM_SLOT_DEFAULT: return param->m_default;
    case CIPHER_PARAM_SLOT_MIN:     return param->m_minValue;
    case CIPHER_PARAM_SLOT_MAX:     return cipherCfgMaxValue(param);
    default:                        return param->m_value;
  }
}

/* Find a parameter in a parameter table */
static CipherParams*
cipherCfgFindParam(CipherParams* table, const char* zName)
{
  for (; table != NULL && table->m_name[0] != 0; ++table)
  {
    if (sqlite3_stricmp(zName, table->m_name) == 0)
      return table;
  }
  return NULL;
}

/* Index 0 of the codec table holds the common parameters; ciphers start at index 1 */
static CodecParameter*
cipherCfgFindCipherTable(CodecParameter* codecParams, const char* zCipher)
{
  int j;
  for (j = 1; codecParams[j].m_name[0] != 0; ++j)
  {
    if (sqlite3_stricmp(zCipher, codecParams[j].m_name) == 0) return &codecParams[j];
  }
  return NULL;
}

static CodecParameter*
cipherCfgFindCipherTableById(CodecParameter* codecParams, int id)
{
  int j;
  for (j = 1; codecParams[j].m_name[0] != 0; ++j)
  {
    if (codecParams[j].m_id == id)
      return &codecParams[j];
  }
  return NULL;
}

/* Decimal or hexadecimal ("0x...") integer; the whole string must be consumed */
static int
cipherCfgParseInt(const char* z, sqlite3_int64* pValue)
{
  sqlite3_int64 value = 0;
  int negative = 0;
  int base = 10;
  int nDigits = 0;
  if (z == NULL)
    return 0;
  if (*z == '-')
  {
    negative = 1;
    ++z;
  }
  if (z[0] == '0' && (z[1] == 'x' || z[1] == 'X'))
  {
    base = 16;
    z += 2;
  }
  for (; *z != 0; ++z)
  {
    int digit;
    if (*z >= '0' && *z <= '9')
      digit = *z - '0';
    else if (base == 16 && *z >= 'a' && *z <= 'f')
      digit = *z - 'a' + 10;
    else if (base == 16 && *z >= 'A' && *z <= 'F')
      digit = *z - 'A' + 10;
    else
      return 0;
    /* Clamp on overflow; the range check rejects such values anyway */
    if (value > (LARGEST_INT64 - digit) / base)
      value = LARGEST_INT64;
    else
      value = value * base + digit;
    ++nDigits;
  }
  if (nDigits == 0) return 0;
  *pValue = negative ? -value : value;
  return 1;
}

/* At most ONE prefix: "default:", "min:" or "max:" */
SQLITE_PRIVATE int
sqlite3mcParseParamSpec(const char* zSpec, CipherParamSpec* spec)
{
  spec->eSlot = CIPHER_PARAM_SLOT_VALUE;
  spec->zName = "";
  if (zSpec == NULL) return 0;
  if (sqlite3_strnicmp(zSpec, "default:", 8) == 0)  { spec->eSlot = CIPHER_PARAM_SLOT_DEFAULT; zSpec += 8; }
  else if (sqlite3_strnicmp(zSpec, "min:", 4) == 0) { spec->eSlot = CIPHER_PARAM_SLOT_MIN;     zSpec += 4; }
  else if (sqlite3_strnicmp(zSpec, "max:", 4) == 0) { spec->eSlot = CIPHER_PARAM_SLOT_MAX;     zSpec += 4; }
  spec->zName = zSpec;
  return zSpec[0] != 0;
}

/* --- Text <-> value (aliases) --- */

static const char*
cipherCfgValueToName(const CipherParams* param, int iValue)
{
  const CipherParamAlias* alias;
  if (param == NULL)
    return NULL;
  if (param->m_ops != NULL && param->m_ops->m_valueToName != NULL)
    return param->m_ops->m_valueToName(iValue);
  for (alias = param->m_aliases; alias != NULL && alias->m_name != NULL; ++alias)
  {
    if (alias->m_value == iValue)
      return alias->m_name;
  }
  return NULL;
}

static int
cipherCfgNameToValue(const CipherParams* param, const char* zName, sqlite3_int64* pValue)
{
  const CipherParamAlias* alias;
  if (param == NULL) return 0;
  if (param->m_ops != NULL && param->m_ops->m_nameToValue != NULL)
  {
    int value = param->m_ops->m_nameToValue(zName);
    if (value >= 0)
    {
      *pValue = value;
      return 1;
    }
  }
  for (alias = param->m_aliases; alias != NULL && alias->m_name != NULL; ++alias)
  {
    if (sqlite3_stricmp(zName, alias->m_name) == 0)
    {
      *pValue = alias->m_value;
      return 1;
    }
  }
  return 0;
}

/* Comma separated list of the textual values of a parameter or NULL; must be freed with sqlite3_free */
static char*
cipherCfgAllowedValues(const CipherParams* param)
{
  char* zList = NULL;
  int value;
  int maxValue = cipherCfgMaxValue(param);
  if (param == NULL)
    return NULL;
  if (param->m_ops != NULL && param->m_ops->m_valueToName != NULL)
  {
    for (value = param->m_minValue; value <= maxValue; ++value)
    {
      const char* zName = param->m_ops->m_valueToName(value);
      if (zName != NULL && zName[0] != 0)
      {
        char* zNew = sqlite3_mprintf("%s%s%s", zList ? zList : "", zList ? ", " : "", zName);
        sqlite3_free(zList);
        zList = zNew;
      }
    }
  }
  else
  {
    const CipherParamAlias* alias;
    for (alias = param->m_aliases; alias != NULL && alias->m_name != NULL; ++alias)
    {
      char* zNew = sqlite3_mprintf("%s%s%s", zList ? zList : "", zList ? ", " : "", alias->m_name);
      sqlite3_free(zList);
      zList = zNew;
    }
  }
  return zList;
}

/* Value as text, in the way the text based interfaces show it; the result must be freed with sqlite3_free */
static char*
cipherCfgFormatValue(const CipherParams* param, unsigned int nameFlag, int iValue)
{
  const char* zName = (param != NULL && (param->m_flags & nameFlag) != 0) ? cipherCfgValueToName(param, iValue) : NULL;
  return (zName != NULL) ? sqlite3_mprintf("%s", zName) : sqlite3_mprintf("%d", iValue);
}

/* --- Error messages --- */

SQLITE_PRIVATE char*
sqlite3mcConfigErrorMsg(const CipherConfigRequest* request, const CipherConfigResult* result)
{
  char zValue[48];
  const char* zParam = (request->zParam != NULL) ? request->zParam : "";
  char* zOf = (result->zCipher != NULL && strcmp(result->zCipher, "global") != 0 && result->pParam != NULL)
              ? sqlite3_mprintf(" of cipher '%s'", result->zCipher) : sqlite3_mprintf("");
  char* zMsg = NULL;

  if (request->eValueType == CIPHER_PARAM_VALUE_TEXT)
  {
    sqlite3_snprintf((int) sizeof(zValue), zValue, "%.40s", (request->zValue != NULL) ? request->zValue : "");
  }
  else
  {
    sqlite3_snprintf((int) sizeof(zValue), zValue, "%lld", (long long) request->iValue);
  }

  switch (result->eErr)
  {
    case CIPHER_CONFIG_OK:
      break;
    case CIPHER_CONFIG_ERR_NODB:
      zMsg = sqlite3_mprintf("changing parameter '%s' requires a database connection", zParam);
      break;
    case CIPHER_CONFIG_ERR_NOTABLE:
      zMsg = sqlite3_mprintf("codec parameter table not found");
      break;
    case CIPHER_CONFIG_ERR_UNKNOWN_CIPHER:
      zMsg = sqlite3_mprintf("unknown cipher '%s'", (request->zCipher != NULL) ? request->zCipher : "");
      break;
    case CIPHER_CONFIG_ERR_UNKNOWN_PARAM:
      zMsg = sqlite3_mprintf("unknown parameter '%s'%s", zParam,
                             (request->eScope == CIPHER_PARAM_SCOPE_CIPHER && request->zCipher != NULL) ? " for the given cipher" : "");
      break;
    case CIPHER_CONFIG_ERR_SLOT_READONLY:
      zMsg = sqlite3_mprintf("only the current value and the default value of parameter '%s' can be changed", zParam);
      break;
    case CIPHER_CONFIG_ERR_BAD_VALUE:
    {
      char* zAllowed = (result->pParam != NULL) ? cipherCfgAllowedValues(result->pParam) : NULL;
      zMsg = sqlite3_mprintf("invalid value '%s' for parameter '%s'%s%s%s%s",
                             zValue, zParam, zOf,
                             (zAllowed != NULL) ? " (allowed: " : "", (zAllowed != NULL) ? zAllowed : "", (zAllowed != NULL) ? ")" : "");
      sqlite3_free(zAllowed);
      break;
    }
    case CIPHER_CONFIG_ERR_RANGE:
      zMsg = sqlite3_mprintf("value %s for parameter '%s'%s out of range [%d..%d]", zValue, zParam, zOf,
                             (result->pParam != NULL) ? result->pParam->m_minValue : 0,
                             (result->pParam != NULL) ? cipherCfgMaxValue(result->pParam) : 0);
      break;
    case CIPHER_CONFIG_ERR_CONSTRAINT:
      zMsg = sqlite3_mprintf("value %s for parameter '%s'%s does not satisfy constraints", zValue, zParam, zOf);
      break;
    default:
      zMsg = sqlite3_mprintf("configuration error %d", result->eErr);
      break;
  }
  sqlite3_free(zOf);
  return zMsg;
}

/* --- The core --- */

static int
cipherCfgConvertValue(const CipherParams* param, const CipherConfigRequest* request, sqlite3_int64* pValue)
{
  int nameOnly = ((param->m_flags & CIPHER_PARAM_FLAG_NAME_ONLY) != 0);
  if (request->eValueType == CIPHER_PARAM_VALUE_INT)
  {
    /* Integers are not accepted for name-only parameters in the SQL function */
    if (nameOnly && request->strictNames)
      return CIPHER_CONFIG_ERR_BAD_VALUE;
    *pValue = request->iValue;
    return CIPHER_CONFIG_OK;
  }
  if (request->eValueType == CIPHER_PARAM_VALUE_TEXT && request->zValue != NULL)
  {
    if (cipherCfgNameToValue(param, request->zValue, pValue))
      return CIPHER_CONFIG_OK;
    if (!nameOnly && cipherCfgParseInt(request->zValue, pValue))
      return CIPHER_CONFIG_OK;
  }
  return CIPHER_CONFIG_ERR_BAD_VALUE;
}

static int
cipherCfgApplySet(const CipherConfigRequest* request, CipherParamValueSlot eSlot,
                  CipherParams* param, const char* zCipher, CipherConfigResult* result)
{
  sqlite3_int64 value = 0;
  int rc;

  if (eSlot == CIPHER_PARAM_SLOT_MIN || eSlot == CIPHER_PARAM_SLOT_MAX)
    return CIPHER_CONFIG_ERR_SLOT_READONLY;
  rc = cipherCfgConvertValue(param, request, &value);
  if (rc != CIPHER_CONFIG_OK)
    return rc;

  if (value < param->m_minValue || value > cipherCfgMaxValue(param))
    return CIPHER_CONFIG_ERR_RANGE;
  if ((param->m_flags & CIPHER_PARAM_FLAG_ENABLE_ONLY) != 0 && value == 0)
    return CIPHER_CONFIG_ERR_CONSTRAINT;
  if (param->m_ops != NULL)
  {
    /* Dynamic enumeration: the value must exist in this build (e.g. cipher compiled in) */
    if (param->m_ops->m_valueToName != NULL && param->m_ops->m_valueToName((int) value) == NULL)
      return CIPHER_CONFIG_ERR_RANGE;
    if (param->m_ops->m_check != NULL && !param->m_ops->m_check(zCipher, value))
      return CIPHER_CONFIG_ERR_CONSTRAINT;
  }

  /* Commit */
  if (eSlot == CIPHER_PARAM_SLOT_DEFAULT)
  {
    if ((param->m_flags & CIPHER_PARAM_FLAG_DEFAULT_LOCKED) != 0)
      result->defaultIgnored = 1;
    else
      param->m_default = (int) value;
  }
  param->m_value = (int) value;

  if (param->m_ops != NULL && param->m_ops->m_apply != NULL)
  {
    param->m_ops->m_apply(request->db, zCipher, eSlot, (int) value);
  }
  return CIPHER_CONFIG_OK;
}

/*
** Core of the configuration logic WITHOUT locking.
** The caller must hold the mutex of the connection (db->mutex), or the static main mutex if db == NULL.
** This is the only function that may be used by parameter hooks (CipherParamOps) to change parameters.
*/
static int
cipherCfgExecLocked(const CipherConfigRequest* request, CipherConfigResult* result)
{
  CodecParameter* codecParams;
  CodecParameter* cipherTable = NULL;
  CipherParams* param = NULL;
  int eErr = CIPHER_CONFIG_OK;

  memset(result, 0, sizeof(*result));
  result->iValue = -1;
  result->zCipher = "global";

  if (request->zParam == NULL || request->zParam[0] == 0)
  {
    result->eErr = CIPHER_CONFIG_ERR_UNKNOWN_PARAM;
    return result->eErr;
  }
  /* The process wide table can be read, but not be changed */
  if (request->isSet && request->db == NULL)
  {
    result->eErr = CIPHER_CONFIG_ERR_NODB;
    return result->eErr;
  }
  codecParams = (request->db != NULL) ? sqlite3mcGetCodecParams(request->db) : globalCodecParameterTable;
  if (codecParams == NULL)
  {
    result->eErr = CIPHER_CONFIG_ERR_NOTABLE;
    return result->eErr;
  }

  /* Resolve scope and parameter */
  switch (request->eScope)
  {
    case CIPHER_PARAM_SCOPE_GLOBAL:
      param = cipherCfgFindParam(codecParams[0].m_params, request->zParam);
      break;
    case CIPHER_PARAM_SCOPE_CIPHER:
      cipherTable = (request->zCipher != NULL) ? cipherCfgFindCipherTable(codecParams, request->zCipher) : NULL;
      if (cipherTable == NULL)
        eErr = CIPHER_CONFIG_ERR_UNKNOWN_CIPHER;
      else
        param = cipherCfgFindParam(cipherTable->m_params, request->zParam);
      break;
    case CIPHER_PARAM_SCOPE_AUTO:
    default:
      /*
      ** PRAGMA style: common parameter first, otherwise parameter of the "current" cipher.
      ** The current cipher is the cipher that would be used for the next key setup, that is
      ** its current (transient) value. The value is not consumed here.
      */
      param = cipherCfgFindParam(codecParams[0].m_params, request->zParam);
      if (param == NULL)
      {
        CipherParams* cipherParam = cipherCfgFindParam(codecParams[0].m_params, "cipher");
        if (cipherParam != NULL)
        {
          cipherTable = cipherCfgFindCipherTableById(codecParams, cipherParam->m_value);
          if (cipherTable != NULL)
            param = cipherCfgFindParam(cipherTable->m_params, request->zParam);
        }
      }
      break;
  }
  if (eErr == CIPHER_CONFIG_OK && param == NULL)
    eErr = CIPHER_CONFIG_ERR_UNKNOWN_PARAM;
  if (cipherTable != NULL)
    result->zCipher = cipherTable->m_name;

  /* Get or set */
  if (eErr == CIPHER_CONFIG_OK)
  {
    CipherParamValueSlot eSlot = request->eSlot;
    /*
    ** A PRAGMA on the main database addresses the default value. A parameter whose default value
    ** can not be changed (e.g. hmac_check) is addressed by its current value instead.
    */
    if (request->eScope == CIPHER_PARAM_SCOPE_AUTO && eSlot == CIPHER_PARAM_SLOT_DEFAULT &&
        (param->m_flags & CIPHER_PARAM_FLAG_DEFAULT_LOCKED) != 0)
    {
      eSlot = CIPHER_PARAM_SLOT_VALUE;
    }
    result->pParam = param;
    if (request->isSet)
      eErr = cipherCfgApplySet(request, eSlot, param, result->zCipher, result);
    /* Always report the actual state after the call */
    result->iValue = cipherCfgSlotValue(param, eSlot);
  }

  result->eErr = eErr;
  return eErr;
}

SQLITE_PRIVATE int
sqlite3mcConfigExec(const CipherConfigRequest* request, CipherConfigResult* result)
{
  sqlite3_mutex* mutex = (request->db != NULL) ? request->db->mutex : sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MAIN);
  int rc;
  sqlite3_mutex_enter(mutex);
  rc = cipherCfgExecLocked(request, result);
  sqlite3_mutex_leave(mutex);
  return rc;
}

/*
** Set an integer parameter of a cipher for a connection from within a parameter hook.
** The mutex of the connection is already held by the caller, therefore no locking is done.
** eSlot is CIPHER_PARAM_SLOT_VALUE or CIPHER_PARAM_SLOT_DEFAULT.
** Returns CIPHER_CONFIG_OK or an error code CIPHER_CONFIG_ERR_*.
*/
SQLITE_PRIVATE int
sqlite3mcConfigSetIntLocked(sqlite3* db, const char* zCipher, const char* zParam, CipherParamValueSlot eSlot, int value)
{
  CipherConfigRequest request;
  CipherConfigResult result;
  memset(&request, 0, sizeof(request));
  request.db = db;
  request.eScope = CIPHER_PARAM_SCOPE_CIPHER;
  request.zCipher = zCipher;
  request.zParam = zParam;
  request.eSlot = eSlot;
  request.isSet = 1;
  request.eValueType = CIPHER_PARAM_VALUE_INT;
  request.iValue = value;
  return cipherCfgExecLocked(&request, &result);
}

/* --- Request builders and logging --- */

static void
cipherCfgInitRequest(CipherConfigRequest* request, sqlite3* db, CipherParamScope eScope, const char* zCipher, const CipherParamSpec* spec)
{
  memset(request, 0, sizeof(*request));
  request->db = db;
  request->eScope = eScope;
  request->zCipher = zCipher;
  request->zParam = spec->zName;
  request->eSlot = spec->eSlot;
}

static void
cipherCfgSetInt(CipherConfigRequest* request, sqlite3_int64 iValue)
{
  request->isSet = 1;
  request->eValueType = CIPHER_PARAM_VALUE_INT;
  request->iValue = iValue;
}

static void
cipherCfgSetText(CipherConfigRequest* request, const char* zValue)
{
  request->isSet = 1;
  request->eValueType = CIPHER_PARAM_VALUE_TEXT;
  request->zValue = zValue;
}

static void
cipherCfgLogError(const char* zFunction, const CipherConfigRequest* request, const CipherConfigResult* result)
{
  char* zMsg = sqlite3mcConfigErrorMsg(request, result);
  if (zMsg != NULL)
  {
    sqlite3_log(SQLITE_WARNING, "%s: %s", zFunction, zMsg);
    sqlite3_free(zMsg);
  }
}

/*
** 1) C API
*/

/*
** A negative new value means "get". The return value is the content of the addressed
** slot after the call (the unchanged value, if a new value was rejected) or -1 if the
** parameter was not found.
*/

SQLITE_API int
sqlite3mc_config(sqlite3* db, const char* paramName, int newValue)
{
  CipherParamSpec spec;
  CipherConfigRequest request;
  CipherConfigResult result;

#ifndef SQLITE_OMIT_AUTOINIT
  if (sqlite3_initialize()) return -1;
#endif

  if (paramName == NULL || !sqlite3mcParseParamSpec(paramName, &spec))
    return -1;
  cipherCfgInitRequest(&request, db, CIPHER_PARAM_SCOPE_GLOBAL, NULL, &spec);
  if (newValue >= 0)
    cipherCfgSetInt(&request, newValue);
  sqlite3mcConfigExec(&request, &result);
  if (result.eErr != CIPHER_CONFIG_OK && result.eErr != CIPHER_CONFIG_ERR_UNKNOWN_PARAM)
  {
    cipherCfgLogError("sqlite3mc_config", &request, &result);
  }
  return result.iValue;
}

SQLITE_API int
sqlite3mc_cipher_count()
{
#ifndef SQLITE_OMIT_AUTOINIT
  if (sqlite3_initialize()) return 0;
#endif
  return sqlite3mcGetGlobalCipherCount();
}

SQLITE_API int
sqlite3mc_cipher_index(const char* cipherName)
{
  int count;
  int j;
#ifndef SQLITE_OMIT_AUTOINIT
  if (sqlite3_initialize()) return -1;
#endif
  count = sqlite3mcGetGlobalCipherCount();
  j = 0;
  for (j = 0; j < count && globalCodecDescriptorTable[j].m_name[0] != 0; ++j)
  {
    if (sqlite3_stricmp(cipherName, globalCodecDescriptorTable[j].m_name) == 0) break;
  }
  return (j < count && globalCodecDescriptorTable[j].m_name[0] != 0) ? j + 1 : -1;
}

static const char*
sqlite3mcFindCipherName(int cipherIndex)
{
  const char* cipherName = NULL;
  int count;
  int j;
#ifndef SQLITE_OMIT_AUTOINIT
  if (sqlite3_initialize()) return NULL;
#endif
  count = sqlite3mcGetGlobalCipherCount();
  j = 0;
  if (cipherIndex > 0 && cipherIndex <= count)
  {
    for (j = 0; j < count && globalCodecDescriptorTable[j].m_name[0] != 0; ++j)
    {
      if (cipherIndex == j + 1) break;
    }
    if (j < count && globalCodecDescriptorTable[j].m_name[0] != 0)
    {
      cipherName = globalCodecDescriptorTable[j].m_name;
    }
  }
  return cipherName;
}

SQLITE_API const char*
sqlite3mc_cipher_name(int cipherIndex)
{
  static char cipherName[CIPHER_NAME_MAXLEN] = "";
  const char* globalCipherName = sqlite3mcFindCipherName(cipherIndex);
  if (globalCipherName)
  {
    strncpy(cipherName, globalCipherName, CIPHER_NAME_MAXLEN - 1);
    cipherName[CIPHER_NAME_MAXLEN - 1] = '\0';
  }
  else
  {
    cipherName[0] = '\0';
  }
  return cipherName;
}

SQLITE_API int
sqlite3mc_cipher_name_copy(int cipherIndex, char* cipherName, int maxCipherNameSize)
{
  int ok = 1;
  const char* globalCipherName = sqlite3mcFindCipherName(cipherIndex);
  if (globalCipherName)
  {
    int cipherNameLen = (int)strlen(globalCipherName) + 1;
    if (cipherName != NULL && maxCipherNameSize >= cipherNameLen)
    {
      strncpy(cipherName, globalCipherName, maxCipherNameSize - 1);
      cipherName[maxCipherNameSize - 1] = '\0';
    }
    else
    {
      /* Buffer too small or NULL, return negative value of minimum required buffer length */
      ok = -cipherNameLen;
    }
  }
  else
  {
    /* Invalid index */
    if (cipherName != NULL && maxCipherNameSize >= 1)
    {
      cipherName[0] = '\0';
    }
    ok = 0;
  }
  return ok;
}

SQLITE_API int
sqlite3mc_config_cipher(sqlite3* db, const char* cipherName, const char* paramName, int newValue)
{
  CipherParamSpec spec;
  CipherConfigRequest request;
  CipherConfigResult result;

#ifndef SQLITE_OMIT_AUTOINIT
  if (sqlite3_initialize()) return -1;
#endif

  if (cipherName == NULL || paramName == NULL || !sqlite3mcParseParamSpec(paramName, &spec))
  {
    sqlite3_log(SQLITE_WARNING,
                "sqlite3mc_config_cipher: cipher name ('%s') or parameter ('%s') missing",
                (cipherName == NULL) ? "" : cipherName, (paramName == NULL) ? "" : paramName);
    return -1;
  }
  cipherCfgInitRequest(&request, db, CIPHER_PARAM_SCOPE_CIPHER, cipherName, &spec);
  if (newValue >= 0) cipherCfgSetInt(&request, newValue);
  sqlite3mcConfigExec(&request, &result);
  if (result.eErr != CIPHER_CONFIG_OK && (newValue != -1 || result.eErr == CIPHER_CONFIG_ERR_UNKNOWN_CIPHER))
  {
    cipherCfgLogError("sqlite3mc_config_cipher", &request, &result);
  }
  return result.iValue;
}

SQLITE_API unsigned char*
sqlite3mc_codec_data(sqlite3* db, const char* zDbName, const char* paramName)
{
  unsigned char* result = NULL;
#ifndef SQLITE_OMIT_AUTOINIT
  if (sqlite3_initialize()) return NULL;
#endif
  if (db != NULL && paramName != NULL)
  {
    int toRaw = 0;
    int iDb;
    sqlite3_mutex_enter(db->mutex);
    iDb = (zDbName != NULL) ? sqlite3FindDbName(db, zDbName) : 0;
    if (sqlite3_strnicmp(paramName, "raw:", 4) == 0)
    {
      toRaw = 1;
      paramName += 4;
    }
    if ((sqlite3_stricmp(paramName, "cipher_salt") == 0) && (iDb >= 0))
    {
      /* Check whether database is encrypted */
      Codec* codec = sqlite3mcGetCodec(db, zDbName);
      if (codec != NULL && sqlite3mcIsEncrypted(codec) && sqlite3mcHasWriteCipher(codec))
      {
        unsigned char* salt = sqlite3mcGetSaltWriteCipher(codec);
        if (salt != NULL)
        {
          if (!toRaw)
          {
            int j;
            result = sqlite3_malloc(32 + 1);
            if (result != NULL)
            {
              for (j = 0; j < 16; ++j)
              {
                result[j * 2] = hexdigits[(salt[j] >> 4) & 0x0F];
                result[j * 2 + 1] = hexdigits[(salt[j]) & 0x0F];
              }
              result[32] = '\0';
            }
          }
          else
          {
            result = sqlite3_malloc(16 + 1);
            if (result != NULL)
            {
              memcpy(result, salt, 16);
              result[16] = '\0';
            }
          }
        }
      }
    }
    sqlite3_mutex_leave(db->mutex);
  }
  return result;
}

SQLITE_PRIVATE void
sqlite3mcCodecDataSql(sqlite3_context* context, int argc, sqlite3_value** argv)
{
  const char* nameParam1 = NULL;
  const char* nameParam2 = NULL;

  assert(argc == 1 || argc == 2);
  /* NULL values are not allowed for the first 2 arguments */
  if (SQLITE_NULL == sqlite3_value_type(argv[0]) || (argc > 1 && SQLITE_NULL == sqlite3_value_type(argv[1])))
  {
    sqlite3_result_null(context);
    return;
  }

  /* Determine parameter name */
  nameParam1 = (const char*) sqlite3_value_text(argv[0]);

  /* Determine schema name if given */
  if (argc == 2)
  {
    nameParam2 = (const char*) sqlite3_value_text(argv[1]);
  }

  /* Check for known parameter name(s) */
  if (sqlite3_stricmp(nameParam1, "cipher_salt") == 0)
  {
    /* Determine key salt */
    sqlite3* db = sqlite3_context_db_handle(context);
    const char* salt = (const char*) sqlite3mc_codec_data(db, nameParam2, "cipher_salt");
    if (salt != NULL)
    {
      sqlite3_result_text(context, salt, -1, sqlite3_free);
    }
    else
    {
      sqlite3_result_null(context);
    }
  }
  else
  {
    sqlite3_result_null(context);
  }
}

/*
** 2) SQL function sqlite3mc_config
*/

/*
**   sqlite3mc_config(common)                 get common parameter
**   sqlite3mc_config(common, value)          set common parameter
**   sqlite3mc_config(cipher)                 list the parameters of the cipher
**   sqlite3mc_config(cipher, param)          get cipher parameter
**   sqlite3mc_config(cipher, param, value)   set cipher parameter
** The value is an integer or text (alias name or number). Prefixes "default:", "min:"
** and "max:" are allowed for parameter names, but not for cipher names.
*/

static int
cipherCfgSetFromSqlValue(CipherConfigRequest* request, sqlite3_value* value)
{
  switch (sqlite3_value_type(value))
  {
    case SQLITE_INTEGER:
      cipherCfgSetInt(request, sqlite3_value_int64(value));
      return 1;
    case SQLITE_TEXT:
      cipherCfgSetText(request, (const char*) sqlite3_value_text(value));
      return 1;
    default:
      return 0;
  }
}

static void
cipherCfgSqlResult(sqlite3_context* context, const CipherConfigRequest* request, const CipherConfigResult* result)
{
  if (result->eErr != CIPHER_CONFIG_OK)
  {
    char* zMsg = sqlite3mcConfigErrorMsg(request, result);
    sqlite3_result_error(context, (zMsg != NULL) ? zMsg : "configuration error", -1);
    sqlite3_free(zMsg);
  }
  else
  {
    const CipherParams* param = result->pParam;
    const char* zName = (param != NULL && (param->m_flags & CIPHER_PARAM_FLAG_NAMED_SQL) != 0)
                      ? cipherCfgValueToName(param, result->iValue) : NULL;
    if (zName != NULL)
      sqlite3_result_text(context, zName, -1, SQLITE_TRANSIENT);
    else
      sqlite3_result_int(context, result->iValue);
  }
}

static void
cipherCfgSqlListParams(sqlite3_context* context, const CipherParams* table)
{
  char* zList = NULL;
  int j;
  for (j = 0; table != NULL && table[j].m_name[0] != 0; ++j)
  {
    char* zNew = sqlite3_mprintf("%s%s%s", zList ? zList : "", zList ? "," : "", table[j].m_name);
    if (zNew == NULL)
    {
      sqlite3_free(zList);
      sqlite3_result_error_nomem(context);
      return;
    }
    sqlite3_free(zList);
    zList = zNew;
  }
  if (zList != NULL)
    sqlite3_result_text(context, zList, -1, sqlite3_free);
  else
    sqlite3_result_null(context);
}

SQLITE_PRIVATE void
sqlite3mcConfigParams(sqlite3_context* context, int argc, sqlite3_value** argv)
{
  sqlite3* db = sqlite3_context_db_handle(context);
  CodecParameter* codecParams = sqlite3mcGetCodecParams(db);
  CipherParamSpec spec1;
  CipherParamSpec spec2;
  CipherConfigRequest request;
  CipherConfigResult result;
  CodecParameter* cipherTable = NULL;

  assert(argc == 1 || argc == 2 || argc == 3);
  /* NULL values are not allowed for the first 2 arguments */
  if (SQLITE_NULL == sqlite3_value_type(argv[0]) || (argc > 1 && SQLITE_NULL == sqlite3_value_type(argv[1])))
  {
    sqlite3_result_null(context);
    return;
  }

  /*
  ** The configuration is looked up via the connection, not via the user data
  ** of the function: the configuration is destroyed when the connection is
  ** closed, while the function can still be called by statements that are
  ** finalized later (sqlite3_close_v2).
  */
  codecParams = sqlite3mcGetCodecParams(sqlite3_context_db_handle(context));
  if (codecParams == NULL)
  {
    sqlite3_result_error(context, "Cipher configuration not available", -1);
    return;
  }

  sqlite3mcParseParamSpec((const char*) sqlite3_value_text(argv[0]), &spec1);
  if (cipherCfgFindParam(codecParams[0].m_params, spec1.zName) != NULL)
  {
    /* First argument is the name of a common parameter */
    if (argc > 2)
    {
      sqlite3_result_error(context, "Too many arguments for a common parameter", -1);
      return;
    }
    cipherCfgInitRequest(&request, db, CIPHER_PARAM_SCOPE_GLOBAL, NULL, &spec1);
    if (argc == 2 && !cipherCfgSetFromSqlValue(&request, argv[1]))
    {
      sqlite3_result_error(context, "Invalid parameter value type", -1);
      return;
    }
  }
  else
  {
    /* First argument has to be a cipher name; a prefix is not allowed for cipher names */
    if (spec1.eSlot == CIPHER_PARAM_SLOT_VALUE && spec1.zName[0] != 0)
    {
      cipherTable = cipherCfgFindCipherTable(codecParams, spec1.zName);
    }
    if (cipherTable == NULL)
    {
      sqlite3_result_error(context, "Cipher name not found", -1);
      return;
    }
    if (argc == 1)
    {
      cipherCfgSqlListParams(context, cipherTable->m_params);
      return;
    }
    sqlite3mcParseParamSpec((const char*) sqlite3_value_text(argv[1]), &spec2);
    cipherCfgInitRequest(&request, db, CIPHER_PARAM_SCOPE_CIPHER, cipherTable->m_name, &spec2);
    if (argc == 3 && !cipherCfgSetFromSqlValue(&request, argv[2]))
    {
      sqlite3_result_error(context, "Invalid parameter value type", -1);
      return;
    }
  }
  request.strictNames = 1;
  sqlite3mcConfigExec(&request, &result);
  cipherCfgSqlResult(context, &request, &result);
}

/*
** 3) URI parameters
*/

/*
** configDefault = 1: main database           -> default values are configured
** configDefault = 0: attached database       -> only the current (transient) values are configured
**
** Invalid values are logged and ignored, except for parameters which select the cipher
** scheme (flag SELECTOR): an invalid value there makes opening the database fail.
*/

static int
cipherCfgUriApply(sqlite3* db, CipherParamScope eScope, const char* zCipher, const CipherParams* param,
                  CipherParamValueSlot eSlot, const char* zValue)
{
  CipherParamSpec spec;
  CipherConfigRequest request;
  CipherConfigResult result;
  spec.eSlot = eSlot;
  spec.zName = param->m_name;
  cipherCfgInitRequest(&request, db, eScope, zCipher, &spec);
  cipherCfgSetText(&request, zValue);
  sqlite3mcConfigExec(&request, &result);
  if (result.eErr == CIPHER_CONFIG_OK) return SQLITE_OK;
  if (result.pParam != NULL && (result.pParam->m_flags & CIPHER_PARAM_FLAG_SELECTOR) != 0)
  {
    char* zMsg = sqlite3mcConfigErrorMsg(&request, &result);
    sqlite3ErrorWithMsg(db, SQLITE_ERROR, "%s", (zMsg != NULL) ? zMsg : "invalid cipher configuration");
    sqlite3_free(zMsg);
    return SQLITE_ERROR;
  }
  /* Do not complain, if a flag is explicitly switched off, which can only be switched on */
  if (!(result.eErr == CIPHER_CONFIG_ERR_CONSTRAINT && result.pParam != NULL &&
        (result.pParam->m_flags & CIPHER_PARAM_FLAG_ENABLE_ONLY) != 0))
  {
    cipherCfgLogError("URI parameter", &request, &result);
  }
  return SQLITE_OK;
}

SQLITE_PRIVATE int
sqlite3mcConfigureFromUri(sqlite3* db, const char* zDbName, int configDefault)
{
  int rc = SQLITE_OK;

  /* Check URI parameters if database filename is available */
  const char* dbFileName = zDbName;
  if (dbFileName != NULL)
  {
    CipherParamValueSlot eSlot = (configDefault) ? CIPHER_PARAM_SLOT_DEFAULT : CIPHER_PARAM_SLOT_VALUE;
    CodecParameter* codecParams = sqlite3mcGetCodecParams(db);
    CodecParameter* cipherTable;
    CipherParams* param;
    int pass;

    /* Handle ChaCha20 hardware acceleration option */
    const char* chacha20HwAccelOption = sqlite3_uri_parameter(dbFileName, "mc_chacha20_hwaccel");
    if (chacha20HwAccelOption != NULL && chacha20HwAccelOption[0] != 0)
    {
      const char* option = chacha20HwAccelOption;
      option = sqlite3mcChaCha20HwConfig(option);
      /* Invalid option values are ignored here. */
    }

    if (codecParams == NULL) return SQLITE_OK;

    /* Common parameters; "cipher" is the first one and therefore known before the cipher parameters are processed */
    for (param = codecParams[0].m_params; param->m_name[0] != 0; ++param)
    {
      const char* zValue = sqlite3_uri_parameter(dbFileName, param->m_name);
      if (zValue != NULL && zValue[0] != 0)
      {
        rc = cipherCfgUriApply(db, CIPHER_PARAM_SCOPE_GLOBAL, NULL, param, eSlot, zValue);
        if (rc != SQLITE_OK) return rc;
      }
    }

    /* Parameters of the effective cipher: the one given in the URI or, if not given, the default cipher */
    {
      CipherParams* cipherParam = cipherCfgFindParam(codecParams[0].m_params, "cipher");
      if (cipherParam == NULL) return SQLITE_OK;
      cipherTable = cipherCfgFindCipherTableById(codecParams, (configDefault) ? cipherParam->m_default : cipherParam->m_value);
      if (cipherTable == NULL) return SQLITE_OK;
    }

    /* Pass 0: presets (e.g. SQLCipher "legacy"); pass 1: all other parameters, so that individual values win */
    for (pass = 0; pass < 2; ++pass)
    {
      for (param = cipherTable->m_params; param->m_name[0] != 0; ++param)
      {
        int isPreset = ((param->m_flags & CIPHER_PARAM_FLAG_APPLY_FIRST) != 0);
        const char* zValue;
        if ((pass == 0) != isPreset) continue;
        zValue = sqlite3_uri_parameter(dbFileName, param->m_name);
        if (zValue != NULL && zValue[0] != 0)
        {
          rc = cipherCfgUriApply(db, CIPHER_PARAM_SCOPE_CIPHER, cipherTable->m_name, param, eSlot, zValue);
          if (rc != SQLITE_OK) return rc;
        }
      }
    }
  }
  return rc;
}

#ifdef SQLITE3MC_WXSQLITE3_COMPATIBLE
SQLITE_API int
wxsqlite3_config(sqlite3* db, const char* paramName, int newValue)
{
  return sqlite3mc_config(db, paramName, newValue);
}

SQLITE_API int
wxsqlite3_config_cipher(sqlite3* db, const char* cipherName, const char* paramName, int newValue)
{
  return sqlite3mc_config_cipher(db, cipherName, paramName, newValue);
}

SQLITE_API unsigned char*
wxsqlite3_codec_data(sqlite3* db, const char* zDbName, const char* paramName)
{
  return sqlite3mc_codec_data(db, zDbName, paramName);
}
#endif

/*
** 4) PRAGMA [schema.]name [= value]
*/

/*
** Called for every pragma name that is not handled otherwise.
** Slot: main database or no schema given -> default value, any other schema (temp, attached) -> current value.
** Returns SQLITE_NOTFOUND if the name is not a parameter of the common parameters or of the current cipher.
**
** A PRAGMA returns the value that is valid after its execution, even if the requested value could not be set
** (out of range, rejected by a constraint). The reason is written to the SQLite log; an application can detect
** the failure by comparing the requested value with the returned one. Only a value that can not be interpreted
** at all (not a number, unknown cipher name) is reported as an error. An unknown alias of an other parameter
** (e.g. an algorithm name) is treated like a rejected value.
*/

SQLITE_PRIVATE int
sqlite3mcPragmaConfig(sqlite3* db, int dbIndex, const char* zName, const char* zValue, char** pzOut)
{
  CipherParamSpec spec;
  CipherConfigRequest request;
  CipherConfigResult result;

  spec.eSlot = (dbIndex <= 0) ? CIPHER_PARAM_SLOT_DEFAULT : CIPHER_PARAM_SLOT_VALUE;
  spec.zName = zName;
  cipherCfgInitRequest(&request, db, CIPHER_PARAM_SCOPE_AUTO, NULL, &spec);
  if (zValue != NULL)
    cipherCfgSetText(&request, zValue);
  sqlite3mcConfigExec(&request, &result);
  if (result.eErr == CIPHER_CONFIG_ERR_UNKNOWN_PARAM)
    return SQLITE_NOTFOUND;
  if ((result.eErr == CIPHER_CONFIG_ERR_BAD_VALUE &&
       !(result.pParam != NULL && result.pParam->m_aliases != NULL &&
        (result.pParam->m_flags & CIPHER_PARAM_FLAG_SELECTOR) == 0)) ||
         result.eErr == CIPHER_CONFIG_ERR_UNKNOWN_CIPHER ||
         result.eErr == CIPHER_CONFIG_ERR_NODB ||
         result.eErr == CIPHER_CONFIG_ERR_NOTABLE)
  {
    *pzOut = sqlite3mcConfigErrorMsg(&request, &result);
    return SQLITE_ERROR;
  }
  if (result.eErr != CIPHER_CONFIG_OK)
  {
    /* Value rejected: report the unchanged value, log the reason */
    cipherCfgLogError("PRAGMA", &request, &result);
  }
  *pzOut = cipherCfgFormatValue(result.pParam, CIPHER_PARAM_FLAG_NAMED_PRAGMA, result.iValue);
  return SQLITE_OK;
}

/*
** Functions called from patched SQLite version
*/

SQLITE_PRIVATE int
sqlite3mcFileControlPragma(sqlite3* db, const char* zDbName, int op, void* pArg)
{
  int rc = sqlite3_file_control(db, zDbName, op, pArg);
  if (rc == SQLITE_NOTFOUND)
  {
    char* pragmaName;
    char* pragmaValue;
    int dbIndex = (zDbName) ? sqlite3FindDbName(db, zDbName) : 0;
    if (dbIndex < 0 && zDbName != NULL)
    {
      /* Unknown schema name */
      return rc;
    }

    pragmaName = ((char**) pArg)[1];
    pragmaValue = ((char**) pArg)[2];
    if (sqlite3StrICmp(pragmaName, "mc_aes_info") == 0)
    {
      ((char**)pArg)[0] = sqlite3_mprintf("%s", aesHardwareAvailable() ? "hardware" : "software");
      rc = SQLITE_OK;
    }
    else if (sqlite3StrICmp(pragmaName, "mc_aes_backend_info") == 0)
    {
#if SQLITE3MC_HAVE_AES_CORE
      ((char**)pArg)[0] = sqlite3_mprintf("%s", aesBackendInfo());
#else
      /* No cipher scheme of this build uses AES: the list of backends is empty */
      ((char**)pArg)[0] = sqlite3_mprintf("%s", "");
#endif
      rc = SQLITE_OK;
    }
    else if (sqlite3StrICmp(pragmaName, "mc_aes_backend") == 0)
    {
#if SQLITE3MC_HAVE_AES_CORE
      const char* backendName = aesRequestBackend(pragmaValue);
#else
      const char* backendName = NULL;
#endif
      if (backendName != NULL)
      {
        ((char**)pArg)[0] = sqlite3_mprintf("%s", backendName);
        rc = SQLITE_OK;
      }
      else
      {
        if (pragmaValue != NULL)
          ((char**)pArg)[0] = sqlite3_mprintf("AES backend '%s' not available or unknown", pragmaValue);
        else
          ((char**)pArg)[0] = sqlite3_mprintf("No AES backend available");
        rc = SQLITE_ERROR;
      }
    }
    else if (sqlite3StrICmp(pragmaName, "mc_cpu_info") == 0)
    {
      const char* hwInfo = sqlite3mcHardwareInfo();
      ((char**)pArg)[0] = sqlite3_mprintf("%s", hwInfo);
      rc = SQLITE_OK;
    }
    else if (sqlite3StrICmp(pragmaName, "mc_chacha20_hwaccel") == 0)
    {
      const char* option = (pragmaValue != NULL) ? pragmaValue : "";
      const char* optionSelected = sqlite3mcChaCha20HwConfig(option);
      if (optionSelected != NULL)
      {
        ((char**)pArg)[0] = sqlite3_mprintf("%s", optionSelected);
        rc = SQLITE_OK;
      }
      else
      {
        ((char**)pArg)[0] = sqlite3_mprintf("Invalid ChaCha20 hardware acceleration option: %s", option);
        rc = SQLITE_ERROR;
      }
    }
    else if (sqlite3StrICmp(pragmaName, "cipher_salt") == 0)
    {
      Codec* codec = sqlite3mcGetCodec(db, (zDbName) ? zDbName : "main");
      if (codec == NULL)
      {
        /* Codec not yet set up */
        if (pragmaValue && *pragmaValue != 0)
        {
          /* Save given cipher salt */
          if (sqlite3Strlen30(pragmaValue) >= 2 * KEYSALT_LENGTH &&
              sqlite3mcIsHexKey((unsigned char*) pragmaValue, 2 * KEYSALT_LENGTH))
          {
            char* cipherSalt = sqlite3_mprintf("%s", pragmaValue);
            if (cipherSalt != NULL &&
                sqlite3_set_clientdata(db, "sqlite3mc_cipher_salt", cipherSalt, sqlite3_free) == SQLITE_OK)
            {
              ((char**)pArg)[0] = sqlite3_mprintf("ok");
              rc = SQLITE_OK;
            }
            else
            {
              ((char**)pArg)[0] = sqlite3_mprintf("Out of memory. Cipher salt not saved.");
              rc = SQLITE_ERROR;
            }
          }
          else
          {
            ((char**)pArg)[0] = sqlite3_mprintf("Invalid cipher salt. Length < %d or invalid hex digits in '%s'.", 2 * KEYSALT_LENGTH, pragmaValue);
            rc = SQLITE_ERROR;
          }
        }
        else
        {
          char* cipherSalt = sqlite3_get_clientdata(db, "sqlite3mc_cipher_salt");
          if (cipherSalt)
          {
            ((char**)pArg)[0] = sqlite3_mprintf("%s", cipherSalt);
          }
          else
          {
            ((char**)pArg)[0] = sqlite3_mprintf("");
          }
          rc = SQLITE_OK;
        }
      }
      else if (sqlite3mcIsEncrypted(codec) && sqlite3mcHasWriteCipher(codec))
      {
        /* Database encrypted */
        if (pragmaValue && *pragmaValue != 0)
        {
          ((char**)pArg)[0] = sqlite3_mprintf("Cipher salt can't be changed.");
          rc = SQLITE_ERROR;
        }
        else
        {
          char* cipherSalt = (char*) sqlite3mc_codec_data(db, (zDbName) ? zDbName : "main", "cipher_salt");
          if (cipherSalt)
          {
            ((char**)pArg)[0] = cipherSalt;
          }
          else
          {
            ((char**)pArg)[0] = sqlite3_mprintf("");
          }
          rc = SQLITE_OK;
        }
      }
      else
      {
        ((char**)pArg)[0] = sqlite3_mprintf("Database not encrypted.");
        rc = SQLITE_ERROR;
      }
    }
    else if (sqlite3StrICmp(pragmaName, "rekey_salt") == 0)
    {
      if (pragmaValue && *pragmaValue != 0)
      {
        if (sqlite3StrICmp(pragmaValue, "on") == 0 || sqlite3StrICmp(pragmaValue, "true") == 0 ||
            sqlite3StrICmp(pragmaValue, "yes") == 0 || sqlite3StrICmp(pragmaValue, "1") == 0)
        {
          char* rekeySalt = NULL;
          char saltHex[33];
          unsigned char saltRaw[16];
          int j;
          chacha20_rng(saltRaw, 16);
          for (j = 0; j < 16; ++j)
            sprintf(&saltHex[2*j], "%02x", saltRaw[j]);
          rekeySalt = sqlite3_mprintf("%s", saltHex);
          if (rekeySalt == NULL || sqlite3_set_clientdata(db, "sqlite3mc_rekey_salt", rekeySalt, sqlite3_free) != SQLITE_OK)
          {
            ((char**)pArg)[0] = sqlite3_mprintf("Out of memory. Rekey salt not saved.");
            rc = SQLITE_ERROR;
          }
          else
          {
            ((char**)pArg)[0] = sqlite3_mprintf("%s", saltHex);
            rc = SQLITE_OK;
          }
        }
        else if (sqlite3StrICmp(pragmaValue, "off") == 0 || sqlite3StrICmp(pragmaValue, "false") == 0 ||
                 sqlite3StrICmp(pragmaValue, "no") == 0 || sqlite3StrICmp(pragmaValue, "0") == 0)
        {
          if (sqlite3_set_clientdata(db, "sqlite3mc_rekey_salt", NULL, NULL) != SQLITE_OK)
          {
            ((char**)pArg)[0] = sqlite3_mprintf("Error on removing rekey salt.");
            rc = SQLITE_ERROR;
          }
          else
          {
            ((char**)pArg)[0] = sqlite3_mprintf("Rekey salt removed.");
            rc = SQLITE_OK;
          }
        }
        else
        {
          ((char**)pArg)[0] = sqlite3_mprintf("Invalid option '%s'.", pragmaValue);
          rc = SQLITE_ERROR;
        }
      }
      else
      {
        char* rekeySalt = sqlite3_get_clientdata(db, "sqlite3mc_rekey_salt");
        if (rekeySalt)
        {
          ((char**)pArg)[0] = sqlite3_mprintf("%s", rekeySalt);
          rc = SQLITE_OK;
        }
      }
    }
    else if (sqlite3StrICmp(pragmaName, "key") == 0)
    {
      rc = sqlite3_key_v2(db, zDbName, pragmaValue, -1);
      if (rc == SQLITE_OK)
      {
        ((char**)pArg)[0] = sqlite3_mprintf("ok");
      }
      else
      {
        if (db->pErr)
        {
          const char* z = (const char*)sqlite3_value_text(db->pErr);
          if (z && sqlite3Strlen30(z) > 0)
          {
            ((char**)pArg)[0] = sqlite3_mprintf("%s", z);
          }
        }
      }
    }
    else if (sqlite3StrICmp(pragmaName, "hexkey") == 0)
    {
      int nValue = sqlite3Strlen30(pragmaValue);
      if (((nValue & 1) == 0) && (sqlite3mcIsHexKey((const unsigned char*) pragmaValue, nValue) != 0))
      {
        unsigned char* zHexKey = sqlite3_malloc(nValue/2+1);
        if (zHexKey != NULL)
        {
          sqlite3mcConvertHex2Bin((const unsigned char*)pragmaValue, nValue, zHexKey);
          rc = sqlite3_key_v2(db, zDbName, zHexKey, nValue / 2);
          sqlite3mcSecureZeroMemory(zHexKey, nValue / 2);
          sqlite3_free(zHexKey);
          if (rc == SQLITE_OK)
          {
            ((char**)pArg)[0] = sqlite3_mprintf("ok");
          }
          else
          {
            if (db->pErr)
            {
              const char* z = (const char*)sqlite3_value_text(db->pErr);
              if (z && sqlite3Strlen30(z) > 0)
              {
                ((char**)pArg)[0] = sqlite3_mprintf("%s", z);
              }
            }
          }
        }
        else
        {
          rc = SQLITE_NOMEM;
        }
      }
      else
      {
        rc = SQLITE_ERROR;
        ((char**)pArg)[0] = sqlite3_mprintf("Malformed hex string");
      }
    }
    else if (sqlite3StrICmp(pragmaName, "rekey") == 0)
    {
      rc = sqlite3_rekey_v2(db, zDbName, pragmaValue, -1);
      if (rc == SQLITE_OK)
      {
        ((char**)pArg)[0] = sqlite3_mprintf("ok");
      }
      else
      {
        if (db->pErr)
        {
          const char* z = (const char*) sqlite3_value_text(db->pErr);
          if (z && sqlite3Strlen30(z) > 0)
          {
            ((char**)pArg)[0] = sqlite3_mprintf("%s", z);
          }
        }
      }
    }
    else if (sqlite3StrICmp(pragmaName, "hexrekey") == 0)
    {
      int nValue = sqlite3Strlen30(pragmaValue);
      if (((nValue & 1) == 0) && (sqlite3mcIsHexKey((const unsigned char*) pragmaValue, nValue) != 0))
      {
        unsigned char* zHexKey = sqlite3_malloc(nValue/2+1);
        if (zHexKey != NULL)
        {
          sqlite3mcConvertHex2Bin((const unsigned char*)pragmaValue, nValue, zHexKey);
          rc = sqlite3_rekey_v2(db, zDbName, zHexKey, nValue / 2);
          sqlite3mcSecureZeroMemory(zHexKey, nValue / 2);
          sqlite3_free(zHexKey);
          if (rc == SQLITE_OK)
          {
            ((char**)pArg)[0] = sqlite3_mprintf("ok");
          }
          else
          {
            if (db->pErr)
            {
              const char* z = (const char*)sqlite3_value_text(db->pErr);
              if (z && sqlite3Strlen30(z) > 0)
              {
                ((char**)pArg)[0] = sqlite3_mprintf("%s", z);
              }
            }
          }
        }
        else
        {
          rc = SQLITE_NOMEM;
        }
      }
      else
      {
        rc = SQLITE_ERROR;
        ((char**)pArg)[0] = sqlite3_mprintf("Malformed hex string");
      }
    }
#if SQLITE3MC_SECURE_MEMORY
    else if (sqlite3StrICmp(pragmaName, "memory_security") == 0)
    {
      if (pragmaValue)
      {
        int intValue = -1;
        if (0 == sqlite3StrICmp(pragmaValue, "none") ||
            0 == sqlite3StrICmp(pragmaValue, "0"))
        {
          intValue = SECURE_MEMORY_NONE;
        }
        else if (0 == sqlite3StrICmp(pragmaValue, "fill") ||
                 0 == sqlite3StrICmp(pragmaValue, "1"))
        {
          intValue = SECURE_MEMORY_FILL;
        }
#if SQLITE3MC_ENABLE_MEMLOCK
        else if (0 == sqlite3StrICmp(pragmaValue, "lock") ||
                 0 == sqlite3StrICmp(pragmaValue, "2"))
        {
          intValue = SECURE_MEMORY_LOCK;
        }
#endif
        if (intValue >= 0)
        {
          sqlite3mcSetMemorySecurity(intValue);
          rc = SQLITE_OK;
          ((char**)pArg)[0] = sqlite3_mprintf("%d", intValue);
        }
        else
        {
          rc = SQLITE_ERROR;
          ((char**) pArg)[0] = sqlite3_mprintf("Secure memory option '%s' invalid.", pragmaValue);
        }
      }
      else
      {
        rc = SQLITE_OK;
        ((char**)pArg)[0] = sqlite3_mprintf("%d", sqlite3mcGetMemorySecurity());
      }
    }
#endif /* SQLITE3MC_SECURE_MEMORY */
    else
    {
      /* Configuration parameters of the ciphers (common parameters and parameters of the current cipher) */
      rc = sqlite3mcPragmaConfig(db, dbIndex, pragmaName, pragmaValue, &((char**) pArg)[0]);
    }
  }
  return rc;
}

/*
** Process URI filename query parameters relevant to the SQLite Encryption
** Extension.  Return true if any of the relevant query parameters are
** seen and return false if not.
*/
SQLITE_PRIVATE int
sqlite3mcCodecQueryParameters(sqlite3* db, const char* zDb, const char* zUri, int* ret)
{
  int rc = 1;
  *ret = SQLITE_OK;
  const char* zKey;
  if ((zKey = sqlite3_uri_parameter(zUri, "hexkey")) != 0 && zKey[0])
  {
    u8 iByte;
    int i;
    int nKey = sqlite3Strlen30(zKey);
    if (((nKey & 1) == 0) && (sqlite3mcIsHexKey((const unsigned char*)zKey, nKey) != 0))
    {
      char* zDecoded = sqlite3_malloc(nKey+1);
      if (zDecoded != NULL)
      {
        zDecoded[0] = '\0';
        for (i = 0, iByte = 0; i < nKey && sqlite3Isxdigit(zKey[i]); i++)
        {
          iByte = (iByte << 4) + sqlite3HexToInt(zKey[i]);
          if ((i & 1) != 0) zDecoded[i / 2] = iByte;
        }
        *ret = sqlite3_key_v2(db, zDb, zDecoded, i / 2);
        if (*ret != SQLITE_OK)
          sqlite3ErrorWithMsg(db, *ret, "Setting up cipher key failed.");
        sqlite3mcSecureZeroMemory(zDecoded, nKey);
        sqlite3_free(zDecoded);
      }
      else
      {
        /* A key was requested: without it the database must not be used */
        *ret = SQLITE_NOMEM;
        sqlite3ErrorWithMsg(db, *ret, "Setting up cipher key failed. Out of memory.");
      }
    }
    else
    {
      *ret = SQLITE_ERROR;
      sqlite3ErrorWithMsg(db, *ret, "Setting up cipher key failed due to invalid hexkey parameter.");
    }
  }
  else if ((zKey = sqlite3_uri_parameter(zUri, "key")) != 0)
  {
    *ret = sqlite3_key_v2(db, zDb, zKey, sqlite3Strlen30(zKey));
    if (*ret != SQLITE_OK)
      sqlite3ErrorWithMsg(db, *ret, "Setting up cipher key failed.");
  }
  else if ((zKey = sqlite3_uri_parameter(zUri, "textkey")) != 0)
  {
    *ret = sqlite3_key_v2(db, zDb, zKey, -1);
    if (*ret != SQLITE_OK)
      sqlite3ErrorWithMsg(db, *ret, "Setting up cipher key failed.");
  }
  else
  {
    rc = 0;
  }
  return rc;
}

SQLITE_PRIVATE int sqlite3mcIsEncryptionSupported(sqlite3* db, const char* zDbName);

SQLITE_PRIVATE int
sqlite3mcHandleAttachKey(sqlite3* db, const char* zName, const char* zPath, sqlite3_value* pKey, char** zErrDyn)
{
  int rc = SQLITE_OK;
  int nKey;
  char* zKey;
  int keyType = 0;
  int canEncrypt = 0;
  int hasUriKey = 0;
  if (zPath != NULL && zPath[0] != 0)
  {
    keyType = sqlite3_value_type(pKey);
    canEncrypt = sqlite3mcIsEncryptionSupported(db, zName);
    hasUriKey = (sqlite3_uri_parameter(zPath, "key") != NULL) ||
                (sqlite3_uri_parameter(zPath, "hexkey") != NULL) ||
                (sqlite3_uri_parameter(zPath, "textkey") != NULL);
  }
  else
  {
    /*
    ** Temporary database, do nothing, ignore KEY.
    ** It is not possible to attach a codec to a temporary database.
    */
    return SQLITE_OK;
  }
  switch (keyType)
  {
    case SQLITE_INTEGER:
    case SQLITE_FLOAT:
      /* Invalid data type for key */
      *zErrDyn = sqlite3DbStrDup(db, "Invalid key value");
      rc = SQLITE_ERROR;
      break;

    case SQLITE_TEXT:
    case SQLITE_BLOB:
      /* Key parameter specified in ATTACH statement */
      nKey = sqlite3_value_bytes(pKey);
      zKey = (char*) sqlite3_value_blob(pKey);
      if (hasUriKey)
      {
        rc = SQLITE_ERROR;
        *zErrDyn = sqlite3_mprintf("Key must not be specified both via KEY clause and via URI parameter");
      }
      else if (nKey > 0 && !canEncrypt)
      {
        rc = SQLITE_ERROR;
        *zErrDyn = sqlite3_mprintf("VFS of database '%s' does not support encryption", zName);
      }
      else
      {
        rc = sqlite3mcCodecAttach(db, db->nDb - 1, zPath, zKey, nKey);
      }
      break;

    case SQLITE_NULL:
      /* No key specified.  Use the key from URI filename, or if none,
      ** use the key from the main database. */
      if (sqlite3mcCodecQueryParameters(db, zName, zPath, &rc) == 0)
      {
        sqlite3mcCodecGetKey(db, 0, (void**) &zKey, &nKey);
        if (nKey)
        {
          if (canEncrypt)
          {
            rc = sqlite3mcCodecAttach(db, db->nDb - 1, zPath, zKey, nKey);
          }
          else
          {
            rc = SQLITE_ERROR;
            *zErrDyn = sqlite3_mprintf("VFS of database '%s' does not support encryption", zName);
          }
        }
      }
      break;
  }

  return rc;
}

SQLITE_PRIVATE int
sqlite3mcHandleMainKey(sqlite3* db, const char* zPath)
{
  int rc = sqlite3mcConfigureFromUri(db, zPath, 1);
  if (rc == SQLITE_OK)
  {
    sqlite3mcCodecQueryParameters(db, "main", zPath, &rc);
  }
  if (rc != SQLITE_OK)
  {
    /*
    ** The cipher configuration or the key given in the URI could not be set
    ** up. sqlite3_open() returns the error, but the connection handle is
    ** handed out as well. Treat it as SQLite treats every other failed open:
    ** the handle can only be asked for the error and be closed. Otherwise an
    ** application that goes on with the handle would read and write the
    ** database without the encryption it asked for.
    */
    sqlite3_mutex_enter(db->mutex);
    if (sqlite3_errcode(db) == SQLITE_OK)
    {
      sqlite3Error(db, rc);
    }
    db->eOpenState = SQLITE_STATE_SICK;
    sqlite3_mutex_leave(db->mutex);
  }
  return rc;
}
