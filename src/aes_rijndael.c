/*
** Name:        aes_rijndael.c
** Purpose:     "rijndael" backend for aes_core.c: the table-based Rijndael
**              implementation of rijndael.c (RijndaelInit, RijndaelBlockEncrypt,
**              RijndaelBlockDecrypt) with its own CBC + ciphertext stealing
** Author:      Ulrich Telle
** Created:     2026-10-09
** Copyright:   (c) 2026 Ulrich Telle
** License:     MIT
*/

/*
** If the target has a Rijndael backend, it defines SQLITE3MC_AES_RIJNDAEL
** and SQLITE3MC_RIJNDAEL_STATE_SIZE, which switches the backend on in
** aes_core.c. Options:
**   SQLITE3MC_AES_NO_RIJNDAEL        do not provide the backend
**   SQLITE3MC_RIJNDAEL_CHUNK         maximum number of bytes handed to
**                                    RijndaelBlockEncrypt/Decrypt in one call
**                                    (multiple of 16, below 2^28, since the
**                                    functions take the length in bits as int)
**
** The context holds two Rijndael structures, one for encryption and one for
** decryption (the key schedule of the table-based implementation depends on
** the direction); only the requested ones are initialized.
**
** RijndaelBlockEncrypt/Decrypt read the initialization vector from the
** structure. Since aes_core.c passes the IV with each call and the context
** must stay unchanged (it may be shared), each call works on a local copy
** of the Rijndael structure, which is wiped afterwards.
*/

#include "cipher_common.h"

#if !defined(SQLITE3MC_AES_NO_RIJNDAEL) && !defined(SQLITE3MC_AES_HARDWARE_ONLY)

#define SQLITE3MC_AES_RIJNDAEL 1

#ifndef SQLITE3MC_RIJNDAEL_CHUNK
#define SQLITE3MC_RIJNDAEL_CHUNK (1u << 24)
#endif

typedef struct _AesRijndaelState
{
  Rijndael enc;
  Rijndael dec;
} AesRijndaelState;

#define SQLITE3MC_RIJNDAEL_STATE_SIZE (sizeof(AesRijndaelState))

/* Direction flags, equal to AES_FOR_ENCRYPT and AES_FOR_DECRYPT in aes_core.c */
#define AES_RIJNDAEL_FOR_ENCRYPT 1
#define AES_RIJNDAEL_FOR_DECRYPT 2

/*
** Key setup; state has SQLITE3MC_RIJNDAEL_STATE_SIZE bytes.
** Returns 0 on success, -1 for a key length other than 16 or 32 or if the
** initialization failed.
*/
SQLITE_PRIVATE int
sqlite3mcRijndaelInit(void* state, const unsigned char* key, int keyLen, int flags)
{
  AesRijndaelState* st = (AesRijndaelState*) state;
  int keyLenId;

  if (keyLen == 16)
  {
    keyLenId = RIJNDAEL_Direction_KeyLength_Key16Bytes;
  }
  else if (keyLen == 32)
  {
    keyLenId = RIJNDAEL_Direction_KeyLength_Key32Bytes;
  }
  else
  {
    return -1;
  }

  memset(st, 0, sizeof(AesRijndaelState));
  /* A structure that is not requested must never be usable */
  st->enc.m_state = RIJNDAEL_State_Invalid;
  st->dec.m_state = RIJNDAEL_State_Invalid;

  if ((flags & AES_RIJNDAEL_FOR_ENCRYPT) != 0)
  {
    if (RijndaelInit(&st->enc, RIJNDAEL_Direction_Mode_CBC, RIJNDAEL_Direction_Encrypt,
                     (UINT8*) key, keyLenId, NULL) != RIJNDAEL_SUCCESS)
    {
      return -1;
    }
  }
  if ((flags & AES_RIJNDAEL_FOR_DECRYPT) != 0)
  {
    if (RijndaelInit(&st->dec, RIJNDAEL_Direction_Mode_CBC, RIJNDAEL_Direction_Decrypt,
                     (UINT8*) key, keyLenId, NULL) != RIJNDAEL_SUCCESS)
    {
      return -1;
    }
  }
  return 0;
}

/*
** CBC (+ CTS, layout "CS3") in place for len >= 16.
** The lengths of RijndaelBlockEncrypt/Decrypt are in bits (type int), so long
** inputs are processed in chunks of SQLITE3MC_RIJNDAEL_CHUNK bytes; the IV of the
** next chunk is the last ciphertext block of the previous chunk. The last
** chunk (at least 32 bytes are kept for it) contains the ciphertext stealing.
**
** Return value: 0 on success, -1 if RijndaelBlockEncrypt/Decrypt report an
** error (a negative return value, e.g. RIJNDAEL_NOT_INITIALIZED or
** RIJNDAEL_BAD_DIRECTION). In the success case the functions return the
** number of bits of the processed full blocks (RijndaelBlockDecrypt one block
** less if ciphertext stealing is used, therefore possibly 0), so only a
** negative value counts as an error. The copy of the Rijndael structure is
** wiped in every case.
*/
static int
aesRijndaelCbcCts(const Rijndael* initialized, int decrypt, const unsigned char iv[16],
                  unsigned char* buf, size_t len)
{
  Rijndael r;
  const size_t chunk = (size_t) SQLITE3MC_RIJNDAEL_CHUNK;
  int rc = 0;
  int ret;

  memcpy(&r, initialized, sizeof(Rijndael));
  memcpy(r.m_initVector, iv, 16);

  while (rc == 0 && len >= chunk + 32)
  {
    if (decrypt)
    {
      unsigned char nextIv[16];
      memcpy(nextIv, buf + chunk - 16, 16);   /* last ciphertext block, before it is overwritten */
      ret = RijndaelBlockDecrypt(&r, buf, (int) (chunk * 8), buf);
      memcpy(r.m_initVector, nextIv, 16);
    }
    else
    {
      ret = RijndaelBlockEncrypt(&r, buf, (int) (chunk * 8), buf);
      memcpy(r.m_initVector, buf + chunk - 16, 16);
    }
    if (ret < 0)
    {
      rc = -1;
    }
    buf += chunk;
    len -= chunk;
  }

  if (rc == 0)
  {
    ret = decrypt ? RijndaelBlockDecrypt(&r, buf, (int)(len * 8), buf)
                  : RijndaelBlockEncrypt(&r, buf, (int)(len * 8), buf);
    if (ret < 0)
    {
      rc = -1;
    }
  }

  sqlite3mcSecureZeroMemory(&r, sizeof(Rijndael));
  return rc;
}

/*
** Encrypt/decrypt len >= 16 bytes in place; return 0 on success
*/
SQLITE_PRIVATE int
sqlite3mcRijndaelCbcCtsEncrypt(const void* state, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return aesRijndaelCbcCts(&((const AesRijndaelState*) state)->enc, 0, iv, buf, len);
}

SQLITE_PRIVATE int
sqlite3mcRijndaelCbcCtsDecrypt(const void* state, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return aesRijndaelCbcCts(&((const AesRijndaelState*) state)->dec, 1, iv, buf, len);
}

#endif /* !SQLITE3MC_AES_NO_RIJNDAEL && !SQLITE3MC_AES_HARDWARE_ONLY */
