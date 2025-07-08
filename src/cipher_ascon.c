/*
** Name:        cipher_ascon.c
** Purpose:     Implementation of cipher Ascon
** Author:      Ulrich Telle
** Created:     2023-11-13
** Copyright:   (c) 2023-2024 Ulrich Telle
** License:     MIT
*/

#include "cipher_common.h"

/* --- Ascon --- */
#if HAVE_CIPHER_ASCON128

#define CIPHER_NAME_ASCON128 "ascon128"

/*
** Configuration parameters for "ascon128a"
**
** - kdf_iter : number of iterations for key derivation
*/

#define ASCON128_KDF_ITER_DEFAULT 64007

#include "ascon/prolog.h"
#include "ascon/aead.c"
#include "ascon/hash.c"
#include "ascon/pbkdf2.c"

SQLITE_PRIVATE CipherParams mcAscon128Params[] =
{
  { "kdf_iter",              ASCON128_KDF_ITER_DEFAULT, ASCON128_KDF_ITER_DEFAULT, 1, 0x7fffffff },
  { "plaintext_header_size", 0,                         0,                         0, 100 /* restrict to db header size */ },
  CIPHER_PARAMS_SENTINEL
};

#define KEYLENGTH_ASCON128       32
#define SALTLENGTH_ASCON128      16
#define PAGE_NONCE_LEN_ASCON128  16
#define PAGE_TAG_LEN_ASCON128    16
#define PAGE_RESERVED_ASCON128   (PAGE_NONCE_LEN_ASCON128 + PAGE_TAG_LEN_ASCON128)

typedef struct _ascon128Cipher
{
  int     m_kdfIter;
  int     m_plaintextHeaderSize;
  int     m_keyLength;
  uint8_t m_key[KEYLENGTH_ASCON128];
  uint8_t m_salt[SALTLENGTH_ASCON128];
} Ascon128Cipher;

static void*
AllocateAscon128Cipher(sqlite3* db)
{
  Ascon128Cipher* ascon128Cipher = (Ascon128Cipher*) sqlite3_malloc(sizeof(Ascon128Cipher));
  if (ascon128Cipher != NULL)
  {
    memset(ascon128Cipher, 0, sizeof(Ascon128Cipher));
    ascon128Cipher->m_keyLength = KEYLENGTH_ASCON128;
    memset(ascon128Cipher->m_key, 0, KEYLENGTH_ASCON128);
    memset(ascon128Cipher->m_salt, 0, SALTLENGTH_ASCON128);
  }
  if (ascon128Cipher != NULL)
  {
    CipherParams* cipherParams = sqlite3mcGetCipherParams(db, CIPHER_NAME_ASCON128);
    ascon128Cipher->m_kdfIter = sqlite3mcGetCipherParameter(cipherParams, "kdf_iter");
    ascon128Cipher->m_plaintextHeaderSize = sqlite3mcGetCipherParameter(cipherParams, "plaintext_header_size");
  }
  return ascon128Cipher;
}

static void
FreeAscon128Cipher(void* cipher)
{
  Ascon128Cipher* ascon128Cipher = (Ascon128Cipher*) cipher;
  memset(ascon128Cipher, 0, sizeof(Ascon128Cipher));
  sqlite3_free(ascon128Cipher);
}

static void
CloneAscon128Cipher(void* cipherTo, void* cipherFrom)
{
  Ascon128Cipher* ascon128CipherTo = (Ascon128Cipher*) cipherTo;
  Ascon128Cipher* ascon128CipherFrom = (Ascon128Cipher*) cipherFrom;
  ascon128CipherTo->m_kdfIter = ascon128CipherFrom->m_kdfIter;
  ascon128CipherTo->m_plaintextHeaderSize = ascon128CipherFrom->m_plaintextHeaderSize;
  ascon128CipherTo->m_keyLength = ascon128CipherFrom->m_keyLength;
  memcpy(ascon128CipherTo->m_key, ascon128CipherFrom->m_key, KEYLENGTH_ASCON128);
  memcpy(ascon128CipherTo->m_salt, ascon128CipherFrom->m_salt, SALTLENGTH_ASCON128);
}

static int
GetLegacyAscon128Cipher(void* cipher)
{
  Ascon128Cipher* ascon128Cipher = (Ascon128Cipher*)cipher;
  return 0;
}

static int
GetPageSizeAscon128Cipher(void* cipher)
{
  Ascon128Cipher* ascon128Cipher = (Ascon128Cipher*) cipher;
  int pageSize = 0;
  return pageSize;
}

static int
GetReservedAscon128Cipher(void* cipher)
{
  return PAGE_RESERVED_ASCON128;
}

static unsigned char*
GetSaltAscon128Cipher(void* cipher)
{
  Ascon128Cipher* ascon128Cipher = (Ascon128Cipher*) cipher;
  return ascon128Cipher->m_salt;
}

static void
GenerateKeyAscon128Cipher(void* cipher, char* userPassword, int passwordLength, int rekey, unsigned char* cipherSalt)
{
  Ascon128Cipher* ascon128Cipher = (Ascon128Cipher*) cipher;

  int keyOnly = 1;
  if (rekey || cipherSalt == NULL)
  {
    chacha20_rng(ascon128Cipher->m_salt, SALTLENGTH_ASCON128);
    keyOnly = 0;
  }
  else
  {
    memcpy(ascon128Cipher->m_salt, cipherSalt, SALTLENGTH_ASCON128);
  }

  /* Bypass key derivation, if raw key (and optionally salt) are given */
  int bypass = sqlite3mcExtractRawKey(userPassword, passwordLength,
                                      keyOnly, KEYLENGTH_ASCON128, SALTLENGTH_ASCON128,
                                      ascon128Cipher->m_key, ascon128Cipher->m_salt);
  if (!bypass)
  {
    ascon_pbkdf2(ascon128Cipher->m_key, KEYLENGTH_ASCON128,
                 (const uint8_t*) userPassword, passwordLength,
                 ascon128Cipher->m_salt, SALTLENGTH_ASCON128, ascon128Cipher->m_kdfIter);
  }
  SQLITE3MC_DEBUG_LOG("generate: codec=%p pFile=%p\n", ascon128Cipher, fd);
  SQLITE3MC_DEBUG_HEX("generate  key:", ascon128Cipher->m_key, KEYLENGTH_ASCON128);
  SQLITE3MC_DEBUG_HEX("generate salt:", ascon128Cipher->m_salt, SALTLENGTH_ASCON128);
}

static int
AsconGenOtk(uint8_t* out, const uint8_t* key, const uint8_t* nonce, int page)
{
  ascon_state_t s;
  uint8_t temp[KEYLENGTH_ASCON128+PAGE_NONCE_LEN_ASCON128+4];
  memcpy(temp, key, KEYLENGTH_ASCON128);
  memcpy(temp+KEYLENGTH_ASCON128, nonce, PAGE_NONCE_LEN_ASCON128);
  STORE32_BE(temp+KEYLENGTH_ASCON128+PAGE_NONCE_LEN_ASCON128, page);
  ascon_inithash(&s);
  ascon_absorb(&s, temp, KEYLENGTH_ASCON128+PAGE_NONCE_LEN_ASCON128+4);
  ascon_squeeze(&s, out, ASCON_HASH_BYTES);
  sqlite3mcSecureZeroMemory(temp, sizeof(temp));
  return 0;
}

static int
EncryptPageAscon128Cipher(void* cipher, int page, unsigned char* data, int len, int reserved)
{
  Ascon128Cipher* ascon128Cipher = (Ascon128Cipher*) cipher;
  int rc = SQLITE_OK;
  int nReserved = (reserved == 0) ? 0 : GetReservedAscon128Cipher(cipher);
  int n = len - nReserved;
  uint64_t mlen = n;
  int usePlaintextHeader = 0;

  /* Generate one-time keys */
  uint8_t otk[ASCON_HASH_BYTES];
  int offset = 0;

  /* Check whether a plaintext header should be used */
  if (page == 1)
  {
    int plaintextHeaderSize = ascon128Cipher->m_plaintextHeaderSize;
    if (plaintextHeaderSize > 0)
    {
      usePlaintextHeader = 1;
      offset = (plaintextHeaderSize > CIPHER_PAGE1_OFFSET) ? plaintextHeaderSize : CIPHER_PAGE1_OFFSET;
    }
    else
    {
      offset = CIPHER_PAGE1_OFFSET;
    }
  }

  /* Check whether number of required reserved bytes and actually reserved bytes match */
  if (nReserved > reserved)
  {
    return SQLITE_CORRUPT;
  }

  if (nReserved > 0)
  {
    /* Encrypt and authenticate */
    memset(otk, 0, ASCON_HASH_BYTES);
    /* Generate nonce */
    chacha20_rng(data + n + PAGE_TAG_LEN_ASCON128, PAGE_NONCE_LEN_ASCON128);
    AsconGenOtk(otk, ascon128Cipher->m_key, data + n + PAGE_TAG_LEN_ASCON128, page);

    ascon_aead_encrypt(data + offset, data + n, data + offset, mlen - offset,
                       NULL /* ad */, 0 /* adlen*/,
                       data + n + PAGE_TAG_LEN_ASCON128, otk);
    if (page == 1 && usePlaintextHeader == 0)
    {
      memcpy(data, ascon128Cipher->m_salt, SALTLENGTH_ASCON128);
    }
  }
  else
  {
    /* Encrypt only */
    uint8_t nonce[PAGE_NONCE_LEN_ASCON128];
    uint8_t dummyTag[PAGE_TAG_LEN_ASCON128];
    memset(dummyTag, 0, PAGE_TAG_LEN_ASCON128);
    memset(otk, 0, ASCON_HASH_BYTES);
    sqlite3mcGenerateInitialVector(page, nonce);
    AsconGenOtk(otk, ascon128Cipher->m_key, nonce, page);

    /* Encrypt */
    ascon_aead_encrypt(data + offset, dummyTag, data + offset, mlen - offset,
                       NULL /* ad */, 0 /* adlen*/,
                       nonce, otk);
      if (page == 1 && usePlaintextHeader == 0)
    {
      memcpy(data, ascon128Cipher->m_salt, SALTLENGTH_ASCON128);
    }
  }

  return rc;
}

static int
DecryptPageAscon128Cipher(void* cipher, int page, unsigned char* data, int len, int reserved, int hmacCheck)
{
  Ascon128Cipher* ascon128Cipher = (Ascon128Cipher*) cipher;
  int rc = SQLITE_OK;
  int nReserved = (reserved == 0) ? 0 : GetReservedAscon128Cipher(cipher);
  int n = len - nReserved;
  uint64_t clen = n;
  int tagOk;
  int usePlaintextHeader = 0;

  /* Generate one-time keys */
  uint8_t otk[ASCON_HASH_BYTES];
  int offset = 0;

  /* Check whether a plaintext header should be used */
  if (page == 1)
  {
    int plaintextHeaderSize = ascon128Cipher->m_plaintextHeaderSize;
    if (plaintextHeaderSize > 0)
    {
      usePlaintextHeader = 1;
      offset = (plaintextHeaderSize > CIPHER_PAGE1_OFFSET) ? plaintextHeaderSize : CIPHER_PAGE1_OFFSET;
    }
    else
    {
      offset = CIPHER_PAGE1_OFFSET;
    }
  }

  /* Check whether number of required reserved bytes and actually reserved bytes match */
  if (nReserved > reserved)
  {
    return (page == 1) ? SQLITE_NOTADB : SQLITE_CORRUPT;
  }

  if (nReserved > 0)
  {
    /* Decrypt and verify MAC */
    memset(otk, 0, ASCON_HASH_BYTES);
    AsconGenOtk(otk, ascon128Cipher->m_key, data + n + PAGE_TAG_LEN_ASCON128, page);

    /* Determine MAC and decrypt */
    tagOk = ascon_aead_decrypt(data + offset, data + offset, clen - offset,
                               NULL /* ad */, 0 /* adlen */,
                               data + n, data + n + PAGE_TAG_LEN_ASCON128, otk);
    if (hmacCheck != 0)
    {
      /* Verify the MAC */
      if (tagOk != 0)
      {
        SQLITE3MC_DEBUG_LOG("decrypt: codec=%p page=%d\n", ascon128Cipher, page);
        SQLITE3MC_DEBUG_HEX("decrypt key:", ascon128Cipher->m_key, 32);
        SQLITE3MC_DEBUG_HEX("decrypt otk:", otk, 64);
        SQLITE3MC_DEBUG_HEX("decrypt data+00:", data, 16);
        SQLITE3MC_DEBUG_HEX("decrypt data+24:", data + 24, 16);
        SQLITE3MC_DEBUG_HEX("decrypt data+n:", data + n, 16);
        SQLITE3MC_DEBUG_HEX("decrypt tag r:", data + n + PAGE_NONCE_LEN_ASCON128, PAGE_TAG_LEN_ASCON128);
        SQLITE3MC_DEBUG_HEX("decrypt tag c:", tag, PAGE_TAG_LEN_ASCON128);
        /* Bad MAC */
        rc = (page == 1) ? SQLITE_NOTADB : SQLITE_CORRUPT;
      }
    }
    if (page == 1 && usePlaintextHeader == 0 && rc == SQLITE_OK)
    {
      memcpy(data, SQLITE_FILE_HEADER, 16);
    }
  }
  else
  {
    /* Decrypt only */
    uint8_t nonce[PAGE_NONCE_LEN_ASCON128];
    uint8_t dummyTag[PAGE_TAG_LEN_ASCON128];
    memset(dummyTag, 0, PAGE_TAG_LEN_ASCON128);
    memset(otk, 0, ASCON_HASH_BYTES);
    sqlite3mcGenerateInitialVector(page, nonce);
    AsconGenOtk(otk, ascon128Cipher->m_key, nonce, page);

    /* Decrypt */
    tagOk = ascon_aead_decrypt(data + offset, data + offset, clen - offset,
                               NULL /* ad */, 0 /* adlen */,
                               dummyTag, nonce, otk);
    if (page == 1 && usePlaintextHeader == 0)
    {
      memcpy(data, SQLITE_FILE_HEADER, 16);
    }
  }

  return rc;
}

SQLITE_PRIVATE const CipherDescriptor mcAscon128Descriptor =
{
  CIPHER_NAME_ASCON128,
  AllocateAscon128Cipher,
  FreeAscon128Cipher,
  CloneAscon128Cipher,
  GetLegacyAscon128Cipher,
  GetPageSizeAscon128Cipher,
  GetReservedAscon128Cipher,
  GetSaltAscon128Cipher,
  GenerateKeyAscon128Cipher,
  EncryptPageAscon128Cipher,
  DecryptPageAscon128Cipher
};
#endif
