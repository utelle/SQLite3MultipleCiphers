/*
** Name:        cipher_aes256gcm.c
** Purpose:     Implementation of cipher AES-256-GCM
** Author:      Ulrich Telle
** Created:     2026-11-19
** Copyright:   (c) 2026 Ulrich Telle
** License:     MIT
*/

#include "cipher_common.h"

/* --- AES-256-GCM --- */
#if HAVE_CIPHER_AES256GCM

#define CIPHER_NAME_AES256GCM "aes256gcm"

/*
** Configuration parameters for "aes256gcm"
**
** - kdf       : key derivation function
**               1 = argon2id (default)
**               2 = pbkdf2-hmac-sha512
** - tcost     : Argon2: number of iterations
** - mcost     : Argon2: amount of memory in kB
** - pcost     : Argon2: parallelism (number of lanes)
** - kdf_iter  : PBKDF2: number of iterations
** - algorithm : AEAD algorithm used for page encryption
**               1 = aes-256-gcm-siv (RFC 8452, default)
**               2 = xaes-256-gcm    (https://c2sp.org/XAES-256-GCM, as used by SQLCipher 5)
**
** Page layout: the reserved area at the end of each page contains
**   nonce | tag
** (aes-256-gcm-siv: 12 + 16 = 28 bytes, xaes-256-gcm: 24 + 16 = 40 bytes).
** The page number (4 bytes, big endian) is authenticated as additional data,
** so pages can not be swapped unnoticed. The first 16 bytes of the database
** file contain the key salt, bytes 16 to 23 of page 1 are not encrypted (as in
** the other SQLite3 Multiple Ciphers schemes). On page 1 all header bytes that
** are not encrypted (from offset 16 up to offset 24, or up to the end of the
** plaintext header if parameter plaintext_header_size is greater than 24) are
** authenticated, too: they follow the page number in the additional data.
*/

#define AES256GCM_ALGORITHM_GCMSIV  1
#define AES256GCM_ALGORITHM_XAES    2

#define AES256GCM_ALGORITHM_MIN      AES256GCM_ALGORITHM_GCMSIV
#define AES256GCM_ALGORITHM_MAX      AES256GCM_ALGORITHM_XAES
#define AES256GCM_ALGORITHM_DEFAULT  AES256GCM_ALGORITHM_GCMSIV

#define AES256GCM_KDF_ARGON2ID       1
#define AES256GCM_KDF_PBKDF2         2
#define AES256GCM_KDF_DEFAULT        AES256GCM_KDF_ARGON2ID

#define AES256GCM_TCOST_DEFAULT      2
#define AES256GCM_MCOST_DEFAULT      (19*1024)
#define AES256GCM_PCOST_DEFAULT      1
#define AES256GCM_KDF_ITER           256000

#define AES256GCM_PRESET_MIN         1
#define AES256GCM_PRESET_MAX         3
#define AES256GCM_PRESET_DEFAULT     1

/* Parameter "preset": configure parameters according to the selected preset */
static void
mcAes256GcmApplyPreset(sqlite3* db, const char* zCipher, CipherParamValueSlot eSlot, int preset)
{
  static const char* names[] = { "tcost", "mcost", "pcost", "kdf_iter", NULL };
  static int presetParams[AES256GCM_PRESET_MAX][4] =
  {
    { 2,  19*1024, 1,  210000 },
    { 3,  64*1024, 1,  256000 },
    { 3, 256*1024, 1, 1000000 }
  };
  int configDefault = eSlot == CIPHER_PARAM_SLOT_DEFAULT;

  if (preset > 0 && preset <= AES256GCM_PRESET_MAX)
  {
    CipherParamValueSlot eSlot = (configDefault != 0) ? CIPHER_PARAM_SLOT_DEFAULT : CIPHER_PARAM_SLOT_VALUE;
    int* values = &presetParams[preset - 1][0];
    int j;
    for (j = 0; names[j] != NULL; ++j)
    {
      /* Called from the parameter hook of 'preset': the connection mutex is already held */
      sqlite3mcConfigSetIntLocked(db, "aes256gcm", names[j], eSlot, values[j]);
    }
  }
}

static const CipherParamOps mcAes256GcmOpsPreset =
{
  NULL, NULL, NULL, mcAes256GcmApplyPreset, NULL
};

/* Names of the algorithms (aliases for the values of parameter "algorithm") */
static const CipherParamAlias mcAes256GcmAlgorithmAliases[] =
{
  { "aes-256-gcm-siv", AES256GCM_ALGORITHM_GCMSIV },
  { "xaes-256-gcm",    AES256GCM_ALGORITHM_XAES   },
  CIPHER_PARAM_ALIAS_SENTINEL
};

/* Names of the key derivation functions (aliases for the values of parameter "kdf") */
static const CipherParamAlias mcAes256GcmKdfAliases[] =
{
  { "argon2id",           AES256GCM_KDF_ARGON2ID },
  { "pbkdf2-hmac-sha512", AES256GCM_KDF_PBKDF2   },
  CIPHER_PARAM_ALIAS_SENTINEL
};

SQLITE_PRIVATE CipherParams mcAes256GcmParams[] =
{
  { "preset",                AES256GCM_PRESET_DEFAULT,    AES256GCM_PRESET_DEFAULT,    AES256GCM_PRESET_MIN,   AES256GCM_PRESET_MAX, CIPHER_PARAM_FLAG_APPLY_FIRST, NULL, &mcAes256GcmOpsPreset },
  { "kdf",                   AES256GCM_KDF_DEFAULT,       AES256GCM_KDF_DEFAULT,       AES256GCM_KDF_ARGON2ID, AES256GCM_KDF_PBKDF2, 0, mcAes256GcmKdfAliases, NULL },
  { "tcost",                 AES256GCM_TCOST_DEFAULT,     AES256GCM_TCOST_DEFAULT,     ARGON2_MIN_TIME,        0x7fffffff },
  { "mcost",                 AES256GCM_MCOST_DEFAULT,     AES256GCM_MCOST_DEFAULT,     ARGON2_MIN_MEMORY,      0x7fffffff },
  { "pcost",                 AES256GCM_PCOST_DEFAULT,     AES256GCM_PCOST_DEFAULT,     ARGON2_MIN_LANES,       ARGON2_MAX_LANES },
  { "kdf_iter",              AES256GCM_KDF_ITER,          AES256GCM_KDF_ITER,          1, 0x7fffffff },
  { "algorithm",             AES256GCM_ALGORITHM_DEFAULT, AES256GCM_ALGORITHM_DEFAULT, AES256GCM_ALGORITHM_MIN, AES256GCM_ALGORITHM_MAX, CIPHER_PARAM_FLAG_NAMED_PRAGMA, mcAes256GcmAlgorithmAliases, NULL },
  { "plaintext_header_size", 0,                           0,                           0, 100 /* restrict to db header size */ },
  CIPHER_PARAMS_SENTINEL
};

#define KEYLENGTH_AES256GCM       32
#define SALTLENGTH_AES256GCM      16
#define PAGE_TAG_LEN_AES256GCM    16
#define PAGE_NONCE_LEN_GCMSIV     AES_GCMSIV_NONCE_SIZE
#define PAGE_NONCE_LEN_XAES       AES_XAES_NONCE_SIZE

typedef struct _aes256GcmCipher
{
  int     m_preset;
  int     m_kdf;
  int     m_argon2Tcost;
  int     m_argon2Mcost;
  int     m_argon2Pcost;
  int     m_kdfIter;
  int     m_algorithm;
  int     m_plaintextHeaderSize;
  int     m_nonceLength;
  uint8_t m_key[KEYLENGTH_AES256GCM];
  uint8_t m_salt[SALTLENGTH_AES256GCM];
  AesCtx* m_aes;
} Aes256GcmCipher;

static int
Aes256GcmNonceLength(int algorithm)
{
  return (algorithm == AES256GCM_ALGORITHM_XAES) ? PAGE_NONCE_LEN_XAES : PAGE_NONCE_LEN_GCMSIV;
}

static void*
AllocateAes256GcmCipher(sqlite3* db)
{
  Aes256GcmCipher* aesCipher = (Aes256GcmCipher*) sqlite3_malloc(sizeof(Aes256GcmCipher));
  if (aesCipher != NULL)
  {
    memset(aesCipher, 0, sizeof(Aes256GcmCipher));
    aesCipher->m_aes = (AesCtx*) sqlite3_malloc(sizeof(AesCtx));
    if (aesCipher->m_aes != NULL)
    {
      sqlite3mcAesCbcWipe(aesCipher->m_aes);
    }
    else
    {
      sqlite3_free(aesCipher);
      aesCipher = NULL;
    }
  }
  if (aesCipher != NULL)
  {
    CipherParams* cipherParams = sqlite3mcGetCipherParams(db, CIPHER_NAME_AES256GCM);
    aesCipher->m_preset = sqlite3mcGetCipherParameter(cipherParams, "preset");
    aesCipher->m_kdf = sqlite3mcGetCipherParameter(cipherParams, "kdf");
    aesCipher->m_argon2Tcost = sqlite3mcGetCipherParameter(cipherParams, "tcost");
    aesCipher->m_argon2Mcost = sqlite3mcGetCipherParameter(cipherParams, "mcost");
    aesCipher->m_argon2Pcost = sqlite3mcGetCipherParameter(cipherParams, "pcost");
    aesCipher->m_kdfIter = sqlite3mcGetCipherParameter(cipherParams, "kdf_iter");
    aesCipher->m_algorithm = sqlite3mcGetCipherParameter(cipherParams, "algorithm");
    aesCipher->m_nonceLength = Aes256GcmNonceLength(aesCipher->m_algorithm);
    aesCipher->m_plaintextHeaderSize = sqlite3mcGetCipherParameter(cipherParams, "plaintext_header_size");
  }
  return aesCipher;
}

static void
FreeAes256GcmCipher(void* cipher)
{
  Aes256GcmCipher* aesCipher = (Aes256GcmCipher*) cipher;
  sqlite3mcSecureZeroMemory(aesCipher->m_aes, sizeof(AesCtx));
  sqlite3_free(aesCipher->m_aes);
  sqlite3mcSecureZeroMemory(aesCipher, sizeof(Aes256GcmCipher));
  sqlite3_free(aesCipher);
}

static void
CloneAes256GcmCipher(void* cipherTo, void* cipherFrom)
{
  Aes256GcmCipher* aesCipherTo = (Aes256GcmCipher*) cipherTo;
  Aes256GcmCipher* aesCipherFrom = (Aes256GcmCipher*) cipherFrom;

  aesCipherTo->m_preset = aesCipherFrom->m_preset;
  aesCipherTo->m_kdf = aesCipherFrom->m_kdf;
  aesCipherTo->m_argon2Tcost = aesCipherFrom->m_argon2Tcost;
  aesCipherTo->m_argon2Mcost = aesCipherFrom->m_argon2Mcost;
  aesCipherTo->m_argon2Pcost = aesCipherFrom->m_argon2Pcost;
  aesCipherTo->m_kdfIter = aesCipherFrom->m_kdfIter;
  aesCipherTo->m_algorithm = aesCipherFrom->m_algorithm;
  aesCipherTo->m_plaintextHeaderSize = aesCipherFrom->m_plaintextHeaderSize;
  aesCipherTo->m_nonceLength = aesCipherFrom->m_nonceLength;
  memcpy(aesCipherTo->m_key, aesCipherFrom->m_key, KEYLENGTH_AES256GCM);
  memcpy(aesCipherTo->m_salt, aesCipherFrom->m_salt, SALTLENGTH_AES256GCM);
  memcpy(aesCipherTo->m_aes, aesCipherFrom->m_aes, sizeof(AesCtx));
}

static int
GetLegacyAes256GcmCipher(void* cipher)
{
  return 0;
}

static int
GetPageSizeAes256GcmCipher(void* cipher)
{
  return 0;
}

static int
GetReservedAes256GcmCipher(void* cipher)
{
  Aes256GcmCipher* aesCipher = (Aes256GcmCipher*) cipher;
  return (aesCipher->m_nonceLength + PAGE_TAG_LEN_AES256GCM);
}

static unsigned char*
GetSaltAes256GcmCipher(void* cipher)
{
  Aes256GcmCipher* aesCipher = (Aes256GcmCipher*) cipher;
  return aesCipher->m_salt;
}

static int
GenerateKeyAes256GcmCipher(void* cipher, char* userPassword, int passwordLength, int rekey, unsigned char* cipherSalt)
{
  Aes256GcmCipher* aesCipher = (Aes256GcmCipher*) cipher;
  int rc = SQLITE_OK;
  int keyOnly = 0;

  if (cipherSalt == NULL)
  {
    chacha20_rng(aesCipher->m_salt, SALTLENGTH_AES256GCM);
  }
  else
  {
    memcpy(aesCipher->m_salt, cipherSalt, SALTLENGTH_AES256GCM);
  }

  /* Bypass key derivation, if raw key (and optionally salt) are given */
  int bypass = sqlite3mcExtractRawKey(userPassword, passwordLength,
                                      keyOnly, KEYLENGTH_AES256GCM, SALTLENGTH_AES256GCM,
                                      aesCipher->m_key, aesCipher->m_salt, &rc);
  if (rc != SQLITE_OK)
    return rc;

  if (!bypass)
  {
    if (aesCipher->m_kdf == AES256GCM_KDF_PBKDF2)
    {
      fastpbkdf2_hmac_sha512((unsigned char*) userPassword, passwordLength,
                             aesCipher->m_salt, SALTLENGTH_AES256GCM,
                             aesCipher->m_kdfIter,
                             aesCipher->m_key, KEYLENGTH_AES256GCM);
    }
    else
    {
      int argon2rc = argon2id_hash_raw((uint32_t) aesCipher->m_argon2Tcost,
                                       (uint32_t) aesCipher->m_argon2Mcost,
                                       (uint32_t) aesCipher->m_argon2Pcost,
                                       userPassword, passwordLength,
                                       aesCipher->m_salt, SALTLENGTH_AES256GCM,
                                       aesCipher->m_key, KEYLENGTH_AES256GCM);
      if (argon2rc != ARGON2_OK)
      {
        return SQLITE_ERROR;
      }
    }
  }

  /* Set up the key schedule of the main key (key-generating key for GCM-SIV) */
  if (aesCipher->m_algorithm == AES256GCM_ALGORITHM_XAES)
  {
    rc = sqlite3mcAesXaesInit(aesCipher->m_aes, aesCipher->m_key);
  }
  else
  {
    rc = sqlite3mcAesGcmSivInit(aesCipher->m_aes, aesCipher->m_key);
  }
  SQLITE3MC_DEBUG_LOG("generate: codec=%p\n", aesCipher);
  SQLITE3MC_DEBUG_HEX("generate  key:", aesCipher->m_key, KEYLENGTH_AES256GCM);
  SQLITE3MC_DEBUG_HEX("generate salt:", aesCipher->m_salt, SALTLENGTH_AES256GCM);
  return rc;
}

/*
** Offset of the encrypted area: on page 1 the salt (16 bytes) and the
** header bytes up to offset 24 are not encrypted, optionally more (plaintext header).
** Returns the offset; usePlaintextHeader is set if a plaintext header is configured.
*/
static int
Aes256GcmPageOffset(const Aes256GcmCipher* aesCipher, int page, int* usePlaintextHeader)
{
  int offset = 0;
  *usePlaintextHeader = 0;
  if (page == 1)
  {
    int plaintextHeaderSize = aesCipher->m_plaintextHeaderSize;
    if (plaintextHeaderSize > 0)
    {
      *usePlaintextHeader = 1;
      offset = (plaintextHeaderSize > CIPHER_PAGE1_OFFSET) ? plaintextHeaderSize : CIPHER_PAGE1_OFFSET;
    }
    else
    {
      offset = CIPHER_PAGE1_OFFSET;
    }
  }
  return offset;
}

static int
EncryptPageAes256GcmCipher(void* cipher, int page, unsigned char* data, int len, int reserved)
{
  Aes256GcmCipher* aesCipher = (Aes256GcmCipher*) cipher;
  int rc = SQLITE_OK;
  int nReserved = GetReservedAes256GcmCipher(cipher);
  int n = len - nReserved;
  int usePlaintextHeader = 0;
  int offset = Aes256GcmPageOffset(aesCipher, page, &usePlaintextHeader);
  const unsigned char* aadExtra = NULL;
  size_t aadExtraLen = 0;

  /* Check whether number of required reserved bytes and actually reserved bytes match */
  if (nReserved != reserved)
  {
    return SQLITE_CORRUPT;
  }

  /*
  ** Generate nonce, encrypt and authenticate. Additional data: the page number and, on page 1,
  ** the unencrypted header bytes behind the salt (offsets 16 up to the start of the encrypted area)
  */
  if (offset > SALTLENGTH_AES256GCM)
  {
    aadExtra = data + SALTLENGTH_AES256GCM;
    aadExtraLen = (size_t) (offset - SALTLENGTH_AES256GCM);
  }
  chacha20_rng(data + n, aesCipher->m_nonceLength);
  if (aesCipher->m_algorithm == AES256GCM_ALGORITHM_XAES)
  {
    rc = sqlite3mcAesXaesPageSealEx(aesCipher->m_aes, (uint32_t) page, aadExtra, aadExtraLen, data + offset, n - offset, data + offset, data + n);
  }
  else
  {
    rc = sqlite3mcAesGcmSivPageSealEx(aesCipher->m_aes, (uint32_t) page, aadExtra, aadExtraLen, data + offset, n - offset, data + offset, data + n);
  }

  if (rc == SQLITE_OK && page == 1 && usePlaintextHeader == 0)
  {
    memcpy(data, aesCipher->m_salt, SALTLENGTH_AES256GCM);
  }
  return rc;
}

static int
DecryptPageAes256GcmCipher(void* cipher, int page, unsigned char* data, int len, int reserved, int hmacCheck)
{
  Aes256GcmCipher* aesCipher = (Aes256GcmCipher*) cipher;
  int rc = SQLITE_OK;
  int nReserved = GetReservedAes256GcmCipher(cipher);
  int n = len - nReserved;
  int usePlaintextHeader = 0;
  int offset = Aes256GcmPageOffset(aesCipher, page, &usePlaintextHeader);
  const unsigned char* aadExtra = NULL;
  size_t aadExtraLen = 0;

  /* Check whether number of required reserved bytes and actually reserved bytes match */
  if (nReserved != reserved)
  {
    return (page == 1) ? SQLITE_NOTADB : SQLITE_CORRUPT;
  }

  /*
  ** Page 1: the reserved size in the database header (offset 20, not encrypted) must match
  ** the reserved size of this cipher scheme. SQLite takes the usable size of the pages from
  ** the header; a modified value would make SQLite interpret the (authenticated) pages
  ** with a wrong layout. Not checked in recovery mode (hmac_check=0).
  */
  if (page == 1 && hmacCheck != 0 && data[20] != (unsigned char) nReserved)
  {
    return SQLITE_NOTADB;
  }

  if (hmacCheck != 0)
  {
    /* Decrypt and verify the tag; the additional data are the same as on encryption (see above) */
    if (offset > SALTLENGTH_AES256GCM)
    {
      aadExtra = data + SALTLENGTH_AES256GCM;
      aadExtraLen = (size_t) (offset - SALTLENGTH_AES256GCM);
    }
    if (aesCipher->m_algorithm == AES256GCM_ALGORITHM_XAES)
    {
      rc = sqlite3mcAesXaesPageOpenEx(aesCipher->m_aes, (uint32_t) page, aadExtra, aadExtraLen, data + offset, n - offset, data + offset, data + n);
    }
    else
    {
      rc = sqlite3mcAesGcmSivPageOpenEx(aesCipher->m_aes, (uint32_t) page, aadExtra, aadExtraLen, data + offset, n - offset, data + offset, data + n);
    }
    if (rc == AES_GCM_TAG_MISMATCH)
    {
      SQLITE3MC_DEBUG_LOG("decrypt: codec=%p page=%d\n", aesCipher, page);
      /* Bad tag */
      rc = (page == 1) ? SQLITE_NOTADB : SQLITE_CORRUPT;
    }
  }
  else
  {
    /* Recovery mode: decrypt without checking the tag */
    if (aesCipher->m_algorithm == AES256GCM_ALGORITHM_XAES)
    {
      rc = sqlite3mcAesXaesOpenUnverified(aesCipher->m_aes, data + n, data + offset, n - offset, data + offset);
    }
    else
    {
      rc = sqlite3mcAesGcmSivOpenUnverified(aesCipher->m_aes, data + n, data + offset, n - offset,
                                            data + n + aesCipher->m_nonceLength, data + offset);
    }
  }

  if (page == 1 && usePlaintextHeader == 0 && rc == SQLITE_OK)
  {
    memcpy(data, SQLITE_FILE_HEADER, 16);
  }
  return rc;
}

SQLITE_PRIVATE const CipherDescriptor mcAes256GcmDescriptor =
{
  CIPHER_NAME_AES256GCM,
  AllocateAes256GcmCipher,
  FreeAes256GcmCipher,
  CloneAes256GcmCipher,
  GetLegacyAes256GcmCipher,
  GetPageSizeAes256GcmCipher,
  GetReservedAes256GcmCipher,
  GetSaltAes256GcmCipher,
  GenerateKeyAes256GcmCipher,
  EncryptPageAes256GcmCipher,
  DecryptPageAes256GcmCipher
};
#endif
