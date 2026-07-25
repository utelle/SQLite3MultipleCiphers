/*
** Name:        sqlite3mc_vle.c
** Purpose:     Value Level Encryption extension for SQLite
** Author:      Ulrich Telle
** Created:     2026-07-17
** Copyright:   (c) 2026-2026 Ulrich Telle
** License:     MIT
*/

/*
** This extension implements "Value Level Encryption" (VLE).
** Currently, 2 encryption algorithms are supported: chacha20 and ascon128.
** The implementation accesses functions provided by the corresponding
** cipher schemes. Therefore it can be compiled only, if at least one
** cipher scheme is enabled. To use both encryption algorithms, both
** cipher schemes need to be enabled.
*/
#if HAVE_CIPHER_CHACHA20 || HAVE_CIPHER_ASCON128

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define VLE_MAGIC_NUM    0x1CAFEBA9

#define VLE_MAGIC        0xEC
#define VLE_VERSION      1
#define VLE_DEFAULT_ALGO CODEC_TYPE_CHACHA20
#define VLE_OTK_LEN      64
#define VLE_KEY_LEN      32
#define VLE_SALT_LEN     16
#define VLE_NONCE_LEN    16
#define VLE_TAG_LEN      16
#define VLE_KEY_ID_LEN    8

typedef struct _VleContext
{
  unsigned char key[VLE_KEY_LEN];
  unsigned char salt[VLE_SALT_LEN];
  size_t  keyLen;
  uint8_t algorithm;
  uint8_t flags;
  uint8_t nonceLen;
  uint8_t tagLen;
} VleContext;

typedef struct _VleHeader
{
  uint8_t magic;
  uint8_t version;
  uint8_t algorithm;
  uint8_t flags;
} VleHeader;

// ----------------- Function Prototypes -----------------

static VleContext* vle_getContext(sqlite3* db);

static int vle_packValue(sqlite3_value* val, unsigned char** out, int* out_len);
static int vle_unpackValue(sqlite3_context* ctx, VleHeader* header, const unsigned char* buf, int len);

static uint32_t vle_readU32BE(const unsigned char* p);
static void vle_writeU64BE(unsigned char* p, uint64_t v);
static uint64_t vle_readU64BE(const unsigned char* p);

static void vle_parseHeader(const unsigned char* buffer, VleHeader* hdr);


static void vle_setKey(sqlite3_context* ctx, int argc, sqlite3_value** argv);
static void vle_encrypt(sqlite3_context* ctx, int argc, sqlite3_value** argv);
static void vle_decrypt(sqlite3_context* ctx, int argc, sqlite3_value** argv);

SQLITE_API int sqlite3_vle_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi);

static uint32_t
vle_readU32BE(const unsigned char* p)
{
  return   ((uint32_t) p[3] <<  0)
         | ((uint32_t) p[2] <<  8)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[0] << 24);
}

static void
vle_writeU64BE(unsigned char* p, uint64_t v)
{
  p[7] = (v >>  0) & 0xFF;
  p[6] = (v >>  8) & 0xFF;
  p[5] = (v >> 16) & 0xFF;
  p[4] = (v >> 24) & 0xFF;
  p[3] = (v >> 32) & 0xFF;
  p[2] = (v >> 40) & 0xFF;
  p[1] = (v >> 48) & 0xFF;
  p[0] = (v >> 56) & 0xFF;
}

static uint64_t
vle_readU64BE(const unsigned char* p)
{
  return   ((uint64_t) p[7] <<  0)
         | ((uint64_t) p[6] <<  8)
         | ((uint64_t) p[5] << 16)
         | ((uint64_t) p[4] << 24)
         | ((uint64_t) p[3] << 32)
         | ((uint64_t) p[2] << 40)
         | ((uint64_t) p[1] << 48)
         | ((uint64_t) p[0] << 56);
}


static void
vle_parseHeader(const unsigned char* buffer, VleHeader* hdr)
{
  hdr->magic     = buffer[0];
  hdr->version   = buffer[1];
  hdr->algorithm = buffer[2];
  hdr->flags     = buffer[3];
}

/* Option parser */

typedef int (*VleOptionSetter)(const char* value, size_t valueLength, void* target);

typedef struct
{
  const char* name;
  VleOptionSetter  setter;
  void* target;
} VleOptionDef;


/*
** Find an option definition.
**
** Unknown options are deliberately ignored.
*/
static const VleOptionDef*
vle_findOption(const VleOptionDef* table, const char* name, int nameLength)
{
  const VleOptionDef* opt;
  for (opt = table; opt->name != 0; opt++)
  {
    if (sqlite3_strnicmp(opt->name, name, nameLength) == 0)
      return opt;
  }
  return 0;
}

/*
** Generic integer setter.
*/
static int
vle_optionSetInt(const char* value, size_t valueLength, void* target)
{
  i64 v;
  char buffer[64];

  /*
  ** sqlite3DecOrHexToI64() expects a zero terminated string.
  ** The option parser itself does not require one, therefore only
  ** the value part is copied temporarily.
  */
  if (valueLength >= sizeof(buffer))
    return SQLITE_ERROR;

  memcpy(buffer, value, valueLength);
  buffer[valueLength] = 0;

  if (sqlite3DecOrHexToI64(buffer, &v))
    return SQLITE_ERROR;

  *(int*)target = (int)v;

  return SQLITE_OK;
}

/*
** Parse option string.
**
** Format:
**
**     name=value,name=value,...
**
** Unknown names are ignored.
*/
static int
vle_parseOptions(const char* options, size_t optionsLength, const VleOptionDef* table)
{
  const char* p = options;
  const char* end = options + optionsLength;

  while (p < end)
  {
    const char* nameStart = p;
    const char* nameEnd;
    const char* valueStart;
    const char* valueEnd;

    while (p < end && *p != '=' && *p != ',')
      p++;

    if (p == end || *p != '=')
      return SQLITE_ERROR;

    nameEnd = p++;

    valueStart = p;

    while (p < end && *p != ',')
      p++;

    valueEnd = p;

    const VleOptionDef* opt = vle_findOption(table, nameStart, (int)(nameEnd - nameStart));

    if (opt != 0 && opt->setter != 0)
    {
      int rc = opt->setter(valueStart, (size_t)(valueEnd - valueStart), opt->target);

      if (rc != SQLITE_OK)
        return rc;
    }

    if (p < end)
      p++; /* skip comma */
  }

  return SQLITE_OK;
}

#define VLE_DEFAULT_SCOPE "@vle:default-scope"

static void
vle_getScope(sqlite3_value* argv, const unsigned char** scope, int* scopeLen)
{
  /* Retrieve scope if given, otherwise set default scope */
  *scope = NULL;
  *scopeLen = 0;
  if (argv != NULL)
  {
    int scope_type = sqlite3_value_type(argv);
    if (scope_type == SQLITE_TEXT || scope_type == SQLITE_BLOB)
    {
      *scopeLen = sqlite3_value_bytes(argv);
      *scope = (const unsigned char*) sqlite3_value_blob(argv);
    }
  }
  if (scopeLen == 0)
  {
    *scopeLen = (int) strlen(VLE_DEFAULT_SCOPE);
    *scope = (const unsigned char*) VLE_DEFAULT_SCOPE;
  }
}

static void
vle_aeadEncrypt(const VleContext* ctx,
                const unsigned char* data, int dataLen,
                unsigned char* ctext, int ctextLen,
                unsigned char* tag, int tagLen,
                unsigned char* nonce, int nonceLen,
                const unsigned char* scope, int scopeLen)
{
  uint8_t otk[64];
  unsigned char digest[SHA512_DIGEST_SIZE];
  sha512(scope, scopeLen, digest);
  memcpy(otk, digest, 64);

  switch (ctx->algorithm)
  {
#if HAVE_CIPHER_ASCON128    
    case CODEC_TYPE_ASCON128:
    {
      chacha20_rng(nonce, nonceLen);
      AsconGenOtk(otk, ctx->key, nonce, VLE_MAGIC_NUM);

      ascon_aead_encrypt(ctext, tag, ctext, ctextLen,
                         data, dataLen, nonce, otk);
      break;
    }
#endif
    case CODEC_TYPE_CHACHA20:
    default:
    {
      chacha20_rng(nonce, nonceLen);
      uint32_t counter = vle_readU32BE(nonce + nonceLen - 4) ^ VLE_MAGIC_NUM;
      chacha20_xor(otk, 64, ctx->key, nonce, counter);

      chacha20_xor(ctext, ctextLen, otk + 32, nonce, counter + 1);
      poly1305(data, dataLen + ctextLen, otk, tag);
      break;
    }
  }
}


static int
vle_aeadDecrypt(const VleContext* ctx,
                const unsigned char* data, int dataLen,
                unsigned char* ctext, int ctextLen,
                const unsigned char* tag, int tagLen,
                const unsigned char* nonce, int nonceLen,
                const unsigned char* scope, int scopeLen)
{
  int rc = SQLITE_OK;
  uint8_t otk[64];
  unsigned char digest[SHA512_DIGEST_SIZE];
  sha512(scope, scopeLen, digest);
  memcpy(otk, digest, 64);

  switch (ctx->algorithm)
  {
#if HAVE_CIPHER_ASCON128    
    case CODEC_TYPE_ASCON128:
    {
      AsconGenOtk(otk, ctx->key, nonce, VLE_MAGIC_NUM);

      int tagOk = ascon_aead_decrypt(ctext, ctext, ctextLen,
                                     data, dataLen,
                                     tag, nonce, otk);
      if (tagOk != 0)
      {
        rc = SQLITE_CORRUPT;
      }
      break;
    }
#endif
    case CODEC_TYPE_CHACHA20:
    {
      uint8_t tagCalc[16];
      uint32_t counter = vle_readU32BE(nonce + nonceLen - 4) ^ VLE_MAGIC_NUM;
      chacha20_xor(otk, 64, ctx->key, nonce, counter);

      poly1305(data, dataLen + ctextLen, otk, tagCalc);
      chacha20_xor(ctext, ctextLen, otk + 32, nonce, counter + 1);
      /* Verify the MAC */
      if (poly1305_tagcmp(tag, tagCalc))
      {
        rc = SQLITE_CORRUPT;
      }
      break;
    }
    default:
      rc = SQLITE_ERROR;
      break;
  }
  sqlite3mcSecureZeroMemory(otk, 64);
  return rc;
}

static const char* VLE_CONTEXT_KEY = "vle_context";

// ---------- Helper Functions ----------

static VleContext* vle_getContext(sqlite3* db)
{
  VleContext* ctx = sqlite3_get_clientdata(db, VLE_CONTEXT_KEY);
  if (!ctx)
  {
    ctx = sqlite3_malloc(sizeof(VleContext));
    memset(ctx, 0, sizeof(VleContext));
    ctx->algorithm = CODEC_TYPE_CHACHA20;
    ctx->flags = 0;
    ctx->nonceLen = VLE_NONCE_LEN;
    ctx->tagLen = VLE_TAG_LEN;
    sqlite3_set_clientdata(db, VLE_CONTEXT_KEY, ctx, sqlite3_free);
  }
  return ctx;
}

// ---------- Payload Packing / Unpacking ----------

static int
vle_packValue(sqlite3_value* val, unsigned char** out, int* out_len)
{
  int type = sqlite3_value_type(val);
  unsigned char tmp[8];
  const void* payload = NULL;
  uint32_t payloadLen = 0;

  switch(type)
  {
    case SQLITE_NULL:
      payloadLen = 0;
      break;
    case SQLITE_INTEGER:
    {
      int64_t v = sqlite3_value_int64(val);
      vle_writeU64BE(tmp, (uint64_t) v);
      payload = tmp;
      payloadLen = 8;
      break;
    }
    case SQLITE_FLOAT:
    {
      double d = sqlite3_value_double(val);
      uint64_t bits;
      memcpy(&bits, &d, 8);
      vle_writeU64BE(tmp, bits);
      payload = tmp;
      payloadLen = 8;
      break;
    }
    case SQLITE_TEXT:
      payloadLen = sqlite3_value_bytes(val);
      payload = sqlite3_value_text(val);
      break;
    case SQLITE_BLOB:
      payloadLen = sqlite3_value_bytes(val);
      payload = sqlite3_value_blob(val);
      break;
    default:
      return SQLITE_MISUSE;
  }

  *out = sqlite3_malloc(payloadLen);
  if (!*out)
  {
    return SQLITE_NOMEM;
  }
  if (payloadLen > 0)
  {
    memcpy(*out, payload, payloadLen);
  }
  *out_len = payloadLen;
  return SQLITE_OK;
}

static int
vle_unpackValue(sqlite3_context* ctx, VleHeader* hdr, const unsigned char* buffer, int len)
{
  uint8_t type = buffer[0];
  uint32_t payloadLen = len;

  const unsigned char* payload = buffer+1;

  switch (type)
  {
    case SQLITE_NULL:
      sqlite3_result_null(ctx);
      break;

    case SQLITE_INTEGER:
    {
      int64_t v = (int64_t) vle_readU64BE(payload);
      sqlite3_result_int64(ctx, v);
      break;
    }

    case SQLITE_FLOAT:
    {
      uint64_t bits = vle_readU64BE(payload);
      double d;
      memcpy(&d, &bits, 8);
      sqlite3_result_double(ctx, d);
      break;
    }

    case SQLITE_TEXT:
      sqlite3_result_text(ctx,
                          (const char*) payload,
                          payloadLen,
                          SQLITE_TRANSIENT);
      break;

    case SQLITE_BLOB:
      sqlite3_result_blob(ctx,
                          payload,
                          payloadLen,
                          SQLITE_TRANSIENT);
      break;

    default:
      return SQLITE_CORRUPT;
  }

  return SQLITE_OK;
}

// ---------- SQL Functions ----------

static void vle_setKey(sqlite3_context* ctx, int argc, sqlite3_value** argv)
{
  sqlite3* db = sqlite3_context_db_handle(ctx);
  VleContext* vle = vle_getContext(db);
  if (argc < 1)
  {
    sqlite3_result_error(ctx, "The key parameter is required", -1);
    return;
  }

  /* Passphrase type must be TEXT or BLOB */
  int pswdType = sqlite3_value_type(argv[0]);
  if (pswdType != SQLITE_TEXT && pswdType != SQLITE_BLOB)
  {
    sqlite3_result_error(ctx, "The passphrase parameter must have type TEXT or BLOB", -1);
    return;
  }

  /* Salt */
  static unsigned char* saltDefault = (unsigned char*) "vle:default-salt";
  int saltLen = 0;
  const unsigned char* salt = NULL;
  if (argc >= 2)
  {
    int saltType = sqlite3_value_type(argv[1]);
    if (saltType == SQLITE_TEXT || saltType == SQLITE_BLOB || saltType == SQLITE_NULL)
    {
      if (saltType != SQLITE_NULL)
      {
        saltLen = sqlite3_value_bytes(argv[1]);
        salt = sqlite3_value_blob(argv[1]);
      }
    }
    else
    {
      sqlite3_result_error(ctx, "The salt parameter must have type TEXT or BLOB, but can be NULL", -1);
      return;
    }
  }
  if (saltLen == 0)
  {
    salt = saltDefault;
    saltLen = (int) strlen((const char*) salt);
  }

  unsigned char digest[SHA256_DIGEST_SIZE];
  sha256(salt, saltLen, digest);
  memcpy(vle->salt, digest, sizeof(vle->salt));

  /* Algorithm */
  vle->algorithm = CODEC_TYPE_CHACHA20;
  if (argc >= 3)
  {
    int algorithmType = sqlite3_value_type(argv[2]);
    if (algorithmType == SQLITE_TEXT)
    {
      int algorithmLen = sqlite3_value_bytes(argv[2]);
      const char* algorithm = (const char*) sqlite3_value_text(argv[2]);
      if (sqlite3_strnicmp(algorithm, "chacha20", algorithmLen) == 0)
      {
        vle->algorithm = CODEC_TYPE_CHACHA20;
      }
      else if (sqlite3_strnicmp(algorithm, "ascon128", algorithmLen) == 0)
      {
        vle->algorithm = CODEC_TYPE_ASCON128;
      }
      else
      {
        sqlite3_result_error(ctx, "Unsupported cipher type", -1);
        return;
      }
    }
    else
    {
      sqlite3_result_error(ctx, "The algorithm parameter must have type TEXT", -1);
      return;
    }
  }

  /* Options */
  int optionsLen = 0;
  char* options = NULL;
  if (argc >= 4)
  {
    int optionsType = sqlite3_value_type(argv[3]);
    if (optionsType == SQLITE_TEXT)
    {
      optionsLen = sqlite3_value_bytes(argv[3]);
    }
    else
    {
      sqlite3_result_error(ctx, "The options parameter must have type TEXT", -1);
      return;
    }
    if (optionsLen > 0)
    {
      options = sqlite3_malloc(optionsLen);
      if (!options)
      {
        sqlite3_result_error_nomem(ctx);
        return;
      }
      memcpy(options, sqlite3_value_text(argv[3]), (size_t) optionsLen);
    }
  }

  char optionsUsed[256] = "";
  int pswdLen = sqlite3_value_bytes(argv[0]);
  const unsigned char* pswd = sqlite3_value_blob(argv[0]);
  switch (vle->algorithm)
  {
#if HAVE_CIPHER_CHACHA20
  case CODEC_TYPE_CHACHA20:
    {
      int kdfIter = CHACHA20_KDF_ITER_DEFAULT;
      const VleOptionDef chacha20KeyOptions[] =
      {
          { "kdf_iter", vle_optionSetInt, &kdfIter },
          { 0,          0,                0        }
      };
      vle_parseOptions(options, optionsLen, chacha20KeyOptions);
      if (kdfIter < 1)
      {
        kdfIter = CHACHA20_KDF_ITER_DEFAULT;
      }
      sqlite3_snprintf(sizeof(optionsUsed), optionsUsed, "kdf_iter=%d", kdfIter);
      fastpbkdf2_hmac_sha256(pswd, pswdLen,
                             vle->salt, SALTLENGTH_CHACHA20,
                             kdfIter,
                             vle->key, KEYLENGTH_CHACHA20);
      vle->keyLen = KEYLENGTH_CHACHA20;
      break;
  }
#endif
#if HAVE_CIPHER_ASCON128
    case CODEC_TYPE_ASCON128:
    {
      int kdfIter = ASCON128_KDF_ITER_DEFAULT;
      const VleOptionDef chacha20KeyOptions[] =
      {
          { "kdf_iter", vle_optionSetInt, &kdfIter },
          { 0,          0,                0        }
      };
      vle_parseOptions(options, optionsLen, chacha20KeyOptions);
      if (kdfIter < 1)
      {
        kdfIter = ASCON128_KDF_ITER_DEFAULT;
      }
      sqlite3_snprintf(sizeof(optionsUsed), optionsUsed, "kdf_iter=%d", kdfIter);
      ascon_pbkdf2(vle->key, KEYLENGTH_ASCON128,
                   (const uint8_t*) pswd, pswdLen,
                   vle->salt, SALTLENGTH_ASCON128, kdfIter);
      vle->keyLen = KEYLENGTH_ASCON128;
      break;
    }
#endif
    default:
      sqlite3_result_error(ctx, "Selected algorithm not supported", -1);
      return;
  }

  char* result = sqlite3_mprintf("Ok. Options(%s)", optionsUsed);
  sqlite3_result_text(ctx, result, -1, sqlite3_free);
  if (options != NULL)
  {
    sqlite3_free(options);
  }
}

static void
vle_encrypt(sqlite3_context* ctx, int argc, sqlite3_value** argv)
{
  sqlite3* db = sqlite3_context_db_handle(ctx);
  VleContext* vle = vle_getContext(db);
  if (argc < 1)
  {
    sqlite3_result_error(ctx, "sqlite3mc_vle_encrypt requires a value", -1);
    return;
  }
  if (vle->keyLen == 0)
  {
    sqlite3_result_error(ctx, "VLE key not set", -1);
    return;
  }

  /* Retrieve scope if given, otherwise set default scope */
  int scopeLen = 0;
  const unsigned char* scope = NULL;
  vle_getScope((argc > 1) ? argv[1] : NULL, &scope, &scopeLen);

  /* Pack Value */
  unsigned char* payload = NULL;
  int payloadLen = 0;
  if (vle_packValue(argv[0], &payload, &payloadLen) != SQLITE_OK)
  {
    sqlite3_result_error(ctx, "sqlite3mc_vle_encrypt: Failed to pack value", -1);
    return;
  }

  // Determine length of nonce and tag and total length
  int nonceLen = vle->nonceLen;
  int tagLen = vle->tagLen;
  int totalLen = sizeof(VleHeader) + nonceLen + 1 + payloadLen + tagLen;

  /* Allocate memory for buffer */
  unsigned char* buffer = sqlite3_malloc(totalLen);
  if (!buffer)
  {
    sqlite3_free(payload);
    sqlite3_result_error_nomem(ctx);
    return;
  }

  /* Fill header */
  buffer[0] = VLE_MAGIC;
  buffer[1] = VLE_VERSION;
  buffer[2] = vle->algorithm;
  buffer[3] = vle->flags;

  /* Define positions in output buffer */
  unsigned char* nonce = buffer + sizeof(VleHeader);
  unsigned char* ciphertext = nonce + nonceLen;
  unsigned char* tag = ciphertext + payloadLen + 1;

  /* Output SQLite value type and value */
  ciphertext[0] = (uint8_t) sqlite3_value_type(argv[0]);
  memcpy(ciphertext + 1, payload, payloadLen + 1);

  /* Encrypt */
  vle_aeadEncrypt(vle,
                  buffer, sizeof(VleHeader) + nonceLen,
                  ciphertext, payloadLen + 1,
                  tag, tagLen, nonce, nonceLen,
                  scope, scopeLen);

  sqlite3_result_blob(ctx, buffer, totalLen, sqlite3_free);
  sqlite3_free(payload);
}

static void
vle_decrypt(sqlite3_context* ctx, int argc, sqlite3_value** argv)
{
  sqlite3* db = sqlite3_context_db_handle(ctx);
  VleContext* vle = vle_getContext(db);

  /* Check type of value parameter, must be blob */
  if (argc < 1 || sqlite3_value_type(argv[0]) != SQLITE_BLOB)
  {
    sqlite3_result_error(ctx, "sqlite3mc_vle_decrypt requires a BLOB", -1);
    return;
  }

  /* Check whether key was set */
  if (vle->keyLen == 0)
  {
    sqlite3_result_error(ctx, "VLE key not set", -1);
    return;
  }

  /* Retrieve scope if given, otherwise set default scope */
  int scopeLen = 0;
  const unsigned char* scope = NULL;
  vle_getScope((argc > 1) ? argv[1] : NULL, &scope, &scopeLen);

  /* Retrieve value */
  int blobLen = sqlite3_value_bytes(argv[0]);
  const unsigned char* blob = (const unsigned char*) sqlite3_value_blob(argv[0]);
  if (blobLen < sizeof(VleHeader))
  {
    sqlite3_result_error(ctx, "Encrypted content too short", -1);
    return;
  }

  /* Make writable copy of value */
  unsigned char* buffer = sqlite3_malloc(blobLen);
  if (!buffer)
  {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  memcpy(buffer, blob, blobLen);

  /* Parse header */
  VleHeader hdr;
  vle_parseHeader(buffer, &hdr);
  if (hdr.magic != VLE_MAGIC)
  {
    sqlite3_result_error(ctx, "Invalid VLE header in encrypted value", -1);
    return;
  }

  /* Determine required lenghts and offsets */
  int nonceLen = vle->nonceLen;
  int tagLen = vle->tagLen;
  int payloadLen = blobLen - sizeof(VleHeader) - nonceLen - tagLen - 1;

  unsigned char* nonce = buffer + sizeof(VleHeader);
  unsigned char* ciphertext = nonce + nonceLen;
  unsigned char* tag = ciphertext + payloadLen + 1;

  /* Decrypt value and check tag */
  int rc = vle_aeadDecrypt(vle,
                           buffer, sizeof(VleHeader) + nonceLen,
                           ciphertext, payloadLen + 1,
                           tag, tagLen,
                           nonce, nonceLen,
                           scope, scopeLen);
  if (rc != SQLITE_OK)
  {
    sqlite3_result_error(ctx, "AEAD authentication failed", -1);
  }

  /* Unpack value and set return value */
  vle_unpackValue(ctx, &hdr, ciphertext, payloadLen);
}

/*
** ----------------- SQLite Extension Init -----------------
*/

SQLITE_API
int sqlite3_vle_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi)
{
  SQLITE_EXTENSION_INIT2(pApi);

  /* Define function sqlite3mc_vle_key(passphrase [, salt [, algoritm [, options]]]) */
  sqlite3_create_function(db, "sqlite3mc_vle_key", 1, SQLITE_UTF8|SQLITE_DETERMINISTIC,
                          NULL, vle_setKey, NULL, NULL);
  sqlite3_create_function(db, "sqlite3mc_vle_key", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          NULL, vle_setKey, NULL, NULL);
  sqlite3_create_function(db, "sqlite3mc_vle_key", 3, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          NULL, vle_setKey, NULL, NULL);
  sqlite3_create_function(db, "sqlite3mc_vle_key", 4, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          NULL, vle_setKey, NULL, NULL);

  /* Define function sqlite3mc_vle_encrypt(value [, scope]) */
  sqlite3_create_function(db, "sqlite3mc_vle_encrypt", 1, SQLITE_UTF8|SQLITE_DETERMINISTIC,
                          NULL, vle_encrypt, NULL, NULL);
  sqlite3_create_function(db, "sqlite3mc_vle_encrypt", 2, SQLITE_UTF8|SQLITE_DETERMINISTIC,
                          NULL, vle_encrypt, NULL, NULL);

  /* Define function sqlite3mc_vle_decrypt(value [, scope]) */
  sqlite3_create_function(db, "sqlite3mc_vle_decrypt", 1, SQLITE_UTF8|SQLITE_DETERMINISTIC,
                          NULL, vle_decrypt, NULL, NULL);
  sqlite3_create_function(db, "sqlite3mc_vle_decrypt", 2, SQLITE_UTF8|SQLITE_DETERMINISTIC,
                          NULL, vle_decrypt, NULL, NULL);

  return SQLITE_OK;
}

#endif
