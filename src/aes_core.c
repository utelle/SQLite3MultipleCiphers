/*
** Name:        aes_core.c
** Purpose:     AES-128/256-CBC with ciphertext stealing (CTS) and
**              selectable implementations ("backends"):
**                - AES hardware (AES-NI / ARMv8 crypto, see aes_hardware.c)
**                - BearSSL "ct64" (constant time, bitsliced, 64-bit words)
**                - BearSSL "ct"   (constant time, bitsliced, 32-bit words)
**                - vpaes          (optional, to be provided by a separate port)
** Author:      Ulrich Telle, Markus Trossbach
** Created:     2026-10-07
** Copyright:   (c) 2026 Ulrich Telle, Markus Trossbach
** License:     MIT
*/

/*
** Overview
** --------
**
** The API consists of an AES context (AesCtx) and a few functions:
**
**   sqlite3mcAesCbcInit(ctx, key, keyLen, flags)            automatic selection
**   sqlite3mcAesCbcInitImpl(ctx, key, keyLen, flags, impl)  explicit selection
**   sqlite3mcAesCbcEncrypt(ctx, iv, buf, len)               in place, CBC + CTS
**   sqlite3mcAesCbcDecrypt(ctx, iv, buf, len)
**   sqlite3mcAesCbcWipe(ctx)                                erase key material
**   sqlite3mcAesEncryptBlocks(ctx, in, out, nblocks)        ECB, encryption only
**
** keyLen is 16 (AES-128) or 32 (AES-256) bytes.
** flags tells for which direction(s) the context is needed:
** AES_FOR_ENCRYPT, AES_FOR_DECRYPT or AES_FOR_BOTH.
** Backends with separate encryption and decryption key schedules
** (hardware) only create the requested ones.
** The direction is checked uniformly for all backends:
** encrypting with a context that was set up only for decryption
** (or vice versa) returns SQLITE_MISUSE.
**
** A context can be used for any number of calls; the IV is a parameter
** of each call and is not modified. A context that was set up for both
** directions can be shared by encryption and decryption (the key
** schedule of the BearSSL backends is the same for both directions).
**
** Buffer lengths:
** - A length that is a multiple of 16 is processed as plain CBC.
** - Any other length of at least 16 bytes is processed as CBC with
**   ciphertext stealing (layout "CS3": the last two ciphertext blocks
**   are always swapped, the final block is truncated). This is the
**   layout used by the table-based implementation in rijndael.cpp.
** - A length below 16 bytes that is not a multiple of 16 is rejected
**   (SQLITE_MISUSE).
** CTS is implemented once, on top of the plain CBC functions of the
** backends, so that all backends behave identically.
**
** Backends that already contain a complete CBC+CTS implementation
** (the AES hardware functions of aes_hardware.c and the table-based
** rijndael.c) can supply it in the two optional entries
** m_cbcCtsEncrypt / m_cbcCtsDecrypt of the backend table.
** If these are not NULL, they are called for every length >= 16
** (a multiple of 16 or not) instead of the generic CTS code.
** They must behave exactly like sqlite3mcAesCbcEncrypt() and
** sqlite3mcAesCbcDecrypt() for valid lengths (layout CS3, in place,
** IV not modified). The checks of the context, the direction and of
** lengths below 16 are always done by aes_core.c before.
**
** Block encryption (ECB)
**
** sqlite3mcAesEncryptBlocks() encrypts nblocks independent 16-byte blocks.
** It is the AES primitive of the counter-based modes (AES-GCM, XAES-256-GCM
** in aes_gcm.c). The context must have been set up with AES_FOR_ENCRYPT.
** in and out must be identical (in-place) or must not overlap.
** Backends supply an optimized multi-block function in the optional entry
** m_encryptBlocks of the backend table (the BearSSL backends process 4
** (ct64) or 2 (ct) blocks at once; hardware, vpaes and rijndael can be
** connected with the macros described at their interfaces below).
** Backends without it (m_encryptBlocks == NULL) are served by a generic
** function that encrypts block by block with the CBC function of the backend
** and a zero IV (CBC with a zero IV is ECB for a single block).
**
** The context also holds the data for XAES-256-GCM (m_xaes, m_k1), which
** is set by sqlite3mcAesXaesInit() in aes_gcm.c.
**
** Automatic selection (sqlite3mcAesCbcInit), in this order:
**   1. hardware, if compiled in and available at run time
**   2. vpaes, if compiled in (SQLITE3MC_AES_VPAES) and available
**   3. the preferred software implementation (SQLITE3MC_AES_DEFAULT_IMPL:
**      ct64 on 64-bit platforms and WASM, ct on 32-bit platforms)
**   4. any other software implementation that is compiled in
**
** Compile-time options:
**   SQLITE3MC_AES_HARDWARE_ONLY  no software implementations at all
**   SQLITE3MC_AES_NO_CT64        omit the BearSSL ct64 backend
**   SQLITE3MC_AES_NO_CT32        omit the BearSSL ct (32-bit) backend
**   SQLITE3MC_AES_NO_VPAES       omit the vpaes backend; requires the
**                                interface declared below and the macro
**                                SQLITE3MC_VPAES_STATE_SIZE
**   SQLITE3MC_AES_NO_RIJNDAEL    omit the table-based Rijndael backend
**                                requires the interface declared below and
**                                the macro SQLITE3MC_RIJNDAEL_STATE_SIZE.
**                                It is not constant time and is therefore
**                                never selected automatically, except as
**                                the very last resort
**   SQLITE3MC_AES_DEFAULT_IMPL   AES_IMPL_CT64 or AES_IMPL_CT32
**
** The BearSSL files are included unmodified
** aes_ct.c, aes_ct_enc.c, aes_ct_dec.c for ct;
** aes_ct64.c, aes_ct64_enc.c, aes_ct64_dec.c for ct64).
** Neither software path uses table lookups that depend on the key
** or the data.
*/

#include "cipher_common.h"

#define AESCBC_MAX_ROUNDS 14

/* Implementation identifiers */
#define AES_IMPL_AUTO     0
#define AES_IMPL_HW       1
#define AES_IMPL_VPAES    2
#define AES_IMPL_CT64     3
#define AES_IMPL_CT32     4
#define AES_IMPL_RIJNDAEL 5

/* Direction flags for the initialization */
#define AES_FOR_ENCRYPT 1
#define AES_FOR_DECRYPT 2
#define AES_FOR_BOTH    3

/*
** Compile-time configuration
** --------------------------
*/

#ifndef SQLITE3MC_AES_HARDWARE_ONLY
#ifndef SQLITE3MC_AES_NO_CT64
#define AES_HAVE_CT64 1
#endif
#ifndef SQLITE3MC_AES_NO_CT32
#define AES_HAVE_CT32 1
#endif
#endif

#if HAS_AES_HARDWARE != AES_HARDWARE_NONE
#define AES_HAVE_HW 1
#endif

#ifndef SQLITE3MC_AES_NO_VPAES
#define AES_HAVE_VPAES 1
#ifndef SQLITE3MC_VPAES_STATE_SIZE
#error "SQLITE3MC_AES_VPAES requires SQLITE3MC_VPAES_STATE_SIZE (size of the vpaes key schedule in bytes)"
#endif
#endif

#if !defined(SQLITE3MC_AES_NO_RIJNDAEL) && !defined(SQLITE3MC_AES_HARDWARE_ONLY)
#define AES_HAVE_RIJNDAEL 1
#ifndef SQLITE3MC_RIJNDAEL_STATE_SIZE
#error "SQLITE3MC_AES_RIJNDAEL requires SQLITE3MC_RIJNDAEL_STATE_SIZE (size of the Rijndael state in bytes)"
#endif
#endif

#ifndef SQLITE3MC_AES_DEFAULT_IMPL
#if defined(__LP64__) || defined(_WIN64) || defined(__wasm__) || defined(__x86_64__) || defined(__aarch64__)
#define SQLITE3MC_AES_DEFAULT_IMPL AES_IMPL_CT64
#else
#define SQLITE3MC_AES_DEFAULT_IMPL AES_IMPL_CT32
#endif
#endif

/*
** BearSSL sources
** ---------------
*/

#if defined(AES_HAVE_CT64) || defined(AES_HAVE_CT32)

#include "bearssl/inner.h"

/*
** The static helpers of the BearSSL files have the same names in several
** files (Rcon, sub_word, add_round_key, shift_rows, mix_columns, rotr16,
** rotr32, ...) and, for ct and ct64, even with different signatures.
** They are renamed per file to avoid clashes within the amalgamation
** (rotr32 may also be defined as a macro by Argon2).
** The macros SWAPN/SWAP2/4/8 are defined by both aes_ct.c and aes_ct64.c
** and are removed after use.
*/

#ifdef AES_HAVE_CT64
#undef Rcon
#undef sub_word
#define Rcon     aesCt64_Rcon
#define sub_word aesCt64_sub_word
#include "bearssl/aes_ct64.c"
#undef Rcon
#undef sub_word
#undef SWAPN
#undef SWAP2
#undef SWAP4
#undef SWAP8

#undef add_round_key
#undef shift_rows
#undef mix_columns
#undef rotr32
#define add_round_key aesCt64_enc_add_round_key
#define shift_rows    aesCt64_shift_rows
#define mix_columns   aesCt64_mix_columns
#define rotr32        aesCt64_enc_rotr32
#include "bearssl/aes_ct64_enc.c"
#undef add_round_key
#undef shift_rows
#undef mix_columns
#undef rotr32

#undef inv_shift_rows
#undef inv_mix_columns
#define add_round_key  aesCt64_dec_add_round_key
#define inv_shift_rows aesCt64_inv_shift_rows
#define inv_mix_columns aesCt64_inv_mix_columns
#define rotr32         aesCt64_dec_rotr32
#include "bearssl/aes_ct64_dec.c"
#undef add_round_key
#undef inv_shift_rows
#undef inv_mix_columns
#undef rotr32
#endif /* AES_HAVE_CT64 */

#ifdef AES_HAVE_CT32
#undef Rcon
#undef sub_word
#define Rcon     aesCt32_Rcon
#define sub_word aesCt32_sub_word
#include "bearssl/aes_ct.c"
#undef Rcon
#undef sub_word
#undef SWAPN
#undef SWAP2
#undef SWAP4
#undef SWAP8

#undef add_round_key
#undef shift_rows
#undef mix_columns
#undef rotr16
#define add_round_key aesCt32_enc_add_round_key
#define shift_rows    aesCt32_shift_rows
#define mix_columns   aesCt32_mix_columns
#define rotr16        aesCt32_enc_rotr16
#include "bearssl/aes_ct_enc.c"
#undef add_round_key
#undef shift_rows
#undef mix_columns
#undef rotr16

#undef inv_shift_rows
#undef inv_mix_columns
#define add_round_key  aesCt32_dec_add_round_key
#define inv_shift_rows aesCt32_inv_shift_rows
#define inv_mix_columns aesCt32_inv_mix_columns
#define rotr16         aesCt32_dec_rotr16
#include "bearssl/aes_ct_dec.c"
#undef add_round_key
#undef inv_shift_rows
#undef inv_mix_columns
#undef rotr16
#endif /* AES_HAVE_CT32 */

#endif /* AES_HAVE_CT64 || AES_HAVE_CT32 */

/*
** vpaes interface
** ---------------
*/

#ifdef AES_HAVE_VPAES
/*
** 'state' points to SQLITE3MC_VPAES_STATE_SIZE bytes that are at least
** 8-byte aligned; if the port needs a stronger alignment,
** it must handle that itself (for example by unaligned loads).
**
** Init returns 0 on success.
** Cbc functions: len is a multiple of 16, the IV is not modified, in-place operation.
*/
SQLITE_PRIVATE int sqlite3mcVpaesAvailable(void);
SQLITE_PRIVATE int sqlite3mcVpaesInit(void* state, const unsigned char* key, int keyLen, int flags);
SQLITE_PRIVATE int sqlite3mcVpaesCbcEncrypt(const void* state, int rounds, const unsigned char iv[16],
                                            unsigned char* buf, size_t len);
SQLITE_PRIVATE int sqlite3mcVpaesCbcDecrypt(const void* state, int rounds, const unsigned char iv[16],
                                            unsigned char* buf, size_t len);
SQLITE_PRIVATE int sqlite3mcVpaesEncryptBlocks(const void* state, int rounds,
                                               const unsigned char* in, unsigned char* out, size_t nblocks);

/*
** Optional: define SQLITE3MC_VPAES_HAS_ENCRYPT_BLOCKS and provide
**   int sqlite3mcVpaesEncryptBlocks(const void* state, int rounds,
**                                   const unsigned char* in, unsigned char* out, size_t nblocks)
** (ECB, nblocks independent blocks, in == out allowed, returns 0 on success)
** to use the multi-block function of vpaes for sqlite3mcAesEncryptBlocks().
*/
#endif

/*
** Rijndael interface
** ------------------
*/

#ifdef AES_HAVE_RIJNDAEL
/*
** Interface of the table-based Rijndael backend (aes_rijndael.c). The state
** has SQLITE3MC_RIJNDAEL_STATE_SIZE bytes. The CBC functions include the
** ciphertext stealing for lengths that are not a multiple of 16.
*/
SQLITE_PRIVATE int sqlite3mcRijndaelInit(void* state, const unsigned char* key, int keyLen, int flags);
SQLITE_PRIVATE int sqlite3mcRijndaelCbcCtsEncrypt(const void* state, const unsigned char iv[16],
                                                  unsigned char* buf, size_t len);
SQLITE_PRIVATE int sqlite3mcRijndaelCbcCtsDecrypt(const void* state, const unsigned char iv[16],
                                                  unsigned char* buf, size_t len);
/*
** Optional: define SQLITE3MC_RIJNDAEL_HAS_ENCRYPT_BLOCKS and provide
**   int sqlite3mcRijndaelEncryptBlocks(const void* state, const unsigned char* in,
**                                      unsigned char* out, size_t nblocks)
** (ECB, nblocks independent blocks, in == out allowed, returns 0 on success;
** the state must have been initialized for encryption).
*/
#ifdef SQLITE3MC_RIJNDAEL_HAS_ENCRYPT_BLOCKS
SQLITE_PRIVATE int sqlite3mcRijndaelEncryptBlocks(const void* state, const unsigned char* in,
                                                  unsigned char* out, size_t nblocks);
#endif
#endif

/*
** Context and backend table
** -------------------------
*/

typedef struct _AesCtx AesCtx;
typedef struct _AesBackend AesBackend;

/*
** (1) m_cbcEncrypt and m_cbcDecrypt handle
**     - complete AES blocks only.
**
** (2) m_cbcCtsEncrypt and m_cbcCtsDecrypt handle
**     - complete CBC+CTS in one call for any length >= 16;
**
** Either the function pointers for (1) or (2) are not NULL,
** but not both.
**
** (3) m_encryptBlocks (optional, may be NULL) encrypts nblocks >= 1
**     independent blocks (ECB, encryption direction only, in == out
**     or no overlap). If it is NULL, sqlite3mcAesEncryptBlocks() uses the
**     generic function aesEncryptBlocksGeneric().
*/

struct _AesBackend
{
  int m_id;
  const char* m_name;
  int (*m_available)(void);  /* usable on this machine? */
  int (*m_init)(AesCtx* ctx, const unsigned char* key, int keyLen, int flags);
  int (*m_cbcEncrypt)(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len);
  int (*m_cbcDecrypt)(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len);
  int (*m_cbcCtsEncrypt)(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len);
  int (*m_cbcCtsDecrypt)(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len);
  int (*m_encryptBlocks)(const AesCtx* ctx, const unsigned char* in, unsigned char* out, size_t nblocks);
};

struct _AesCtx
{
  const AesBackend* m_impl; /* NULL: not initialized */
  int m_rounds;             /* 10 (AES-128) or 14 (AES-256) */
  int m_flags;              /* AES_FOR_ENCRYPT / AES_FOR_DECRYPT */
  int m_xaes;               /* 1: m_k1 is valid (context of sqlite3mcAesXaesInit) */
  unsigned char m_k1[16];   /* XAES-256-GCM: CMAC subkey K1 of the master key */
  union
  {
#ifdef AES_HAVE_CT64
    uint64_t ct64[(AESCBC_MAX_ROUNDS + 1) * 8];   /* expanded bitsliced key schedule */
#endif
#ifdef AES_HAVE_CT32
    uint32_t ct32[(AESCBC_MAX_ROUNDS + 1) * 8];   /* expanded bitsliced key schedule */
#endif
#ifdef AES_HAVE_HW
    struct
    {
      unsigned char enc[(AESCBC_MAX_ROUNDS + 1) * 16];
      unsigned char dec[(AESCBC_MAX_ROUNDS + 1) * 16];
    } hw;
#endif
#ifdef AES_HAVE_VPAES
    unsigned char vpaes[SQLITE3MC_VPAES_STATE_SIZE];
#endif
#ifdef AES_HAVE_RIJNDAEL
    unsigned char rijndael[SQLITE3MC_RIJNDAEL_STATE_SIZE];  /* encryption and decryption state */
#endif
    uint64_t unused; /* keeps the union non-empty */
  } u;
};

/*
** Backend: BearSSL ct64
** ---------------------
*/

#ifdef AES_HAVE_CT64

/*
** CBC encryption with the bitsliced AES, one block at a time, since each
** block depends on the previous one (adapted from BearSSL aes_ct64_cbcenc.c)
*/
static int
aesCbcEncryptCt64(int rounds, const uint64_t* skey, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  uint32_t ivw[4];
  br_range_dec32le(ivw, 4, iv);
  while (len > 0)
  {
    uint32_t w[4];
    uint64_t q[8];

    memset(q, 0, sizeof(q));
    w[0] = ivw[0] ^ br_dec32le(buf);
    w[1] = ivw[1] ^ br_dec32le(buf + 4);
    w[2] = ivw[2] ^ br_dec32le(buf + 8);
    w[3] = ivw[3] ^ br_dec32le(buf + 12);
    br_aes_ct64_interleave_in(&q[0], &q[4], w);
    br_aes_ct64_ortho(q);
    br_aes_ct64_bitslice_encrypt(rounds, skey, q);
    br_aes_ct64_ortho(q);
    br_aes_ct64_interleave_out(w, q[0], q[4]);
    memcpy(ivw, w, sizeof(ivw));
    br_range_enc32le(buf, w, 4);
    buf += 16;
    len -= 16;
  }
  return 0;
}

/*
** CBC decryption with the bitsliced AES, four blocks in parallel
** (adapted from BearSSL aes_ct64_cbcdec.c)
*/
static int
aesCbcDecryptCt64(int rounds, const uint64_t* skey, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  uint32_t ivw[4];
  br_range_dec32le(ivw, 4, iv);
  while (len > 0)
  {
    uint64_t q[8];
    uint32_t w1[16], w2[16];
    size_t nWords = (len >= 64) ? 16 : (len >> 2);
    size_t i;

    memset(w1, 0, sizeof(w1));
    br_range_dec32le(w1, nWords, buf);
    for (i = 0; i < 4; i++)
    {
      br_aes_ct64_interleave_in(&q[i], &q[i + 4], w1 + (i << 2));
    }
    br_aes_ct64_ortho(q);
    br_aes_ct64_bitslice_decrypt(rounds, skey, q);
    br_aes_ct64_ortho(q);
    for (i = 0; i < 4; i++)
    {
      br_aes_ct64_interleave_out(w2 + (i << 2), q[i], q[i + 4]);
    }
    for (i = 0; i < 4; i++)
    {
      w2[i] ^= ivw[i];
    }
    for (i = 4; i < nWords; i++)
    {
      w2[i] ^= w1[i - 4];
    }
    memcpy(ivw, w1 + nWords - 4, sizeof(ivw));
    br_range_enc32le(buf, w2, nWords);
    buf += nWords * 4;
    len -= nWords * 4;
  }
  return 0;
}

/*
** ECB encryption with the bitsliced AES, four blocks in parallel
** (same structure as the decryption above; in-place operation is possible
** since all input blocks of a round are read before the output is written)
*/
static int
aesEncryptBlocksCt64(int rounds, const uint64_t* skey, const unsigned char* in, unsigned char* out, size_t nblocks)
{
  while (nblocks > 0)
  {
    uint64_t q[8];
    uint32_t w[16];
    size_t nb = (nblocks >= 4) ? 4 : nblocks;
    size_t i;

    memset(w, 0, sizeof(w));
    br_range_dec32le(w, nb * 4, in);
    for (i = 0; i < 4; i++)
    {
      br_aes_ct64_interleave_in(&q[i], &q[i + 4], w + (i << 2));
    }
    br_aes_ct64_ortho(q);
    br_aes_ct64_bitslice_encrypt((unsigned) rounds, skey, q);
    br_aes_ct64_ortho(q);
    for (i = 0; i < 4; i++)
    {
      br_aes_ct64_interleave_out(w + (i << 2), q[i], q[i + 4]);
    }
    br_range_enc32le(out, w, nb * 4);
    in += nb * 16;
    out += nb * 16;
    nblocks -= nb;
  }
  return 0;
}

static int
aesAvailableSoftware(void)
{
  return 1;
}

static int
aesInitCt64(AesCtx* ctx, const unsigned char* key, int keyLen, int flags)
{
  uint64_t compSkey[(AESCBC_MAX_ROUNDS + 1) * 2];
  (void) flags; /* the same key schedule serves both directions */
  ctx->m_rounds = (int) br_aes_ct64_keysched(compSkey, key, (size_t) keyLen);
  br_aes_ct64_skey_expand(ctx->u.ct64, (unsigned) ctx->m_rounds, compSkey);
  sqlite3mcSecureZeroMemory(compSkey, sizeof(compSkey));
  return SQLITE_OK;
}

static int
aesCbcEncryptCt64Ctx(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return aesCbcEncryptCt64(ctx->m_rounds, ctx->u.ct64, iv, buf, len);
}

static int
aesCbcDecryptCt64Ctx(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return aesCbcDecryptCt64(ctx->m_rounds, ctx->u.ct64, iv, buf, len);
}

static int
aesEncryptBlocksCt64Ctx(const AesCtx* ctx, const unsigned char* in, unsigned char* out, size_t nblocks)
{
  return aesEncryptBlocksCt64(ctx->m_rounds, ctx->u.ct64, in, out, nblocks);
}

static const AesBackend aesBackendCt64 =
{
  AES_IMPL_CT64, "ct64",
  aesAvailableSoftware,
  aesInitCt64,
  aesCbcEncryptCt64Ctx,
  aesCbcDecryptCt64Ctx,
  NULL,
  NULL,
  aesEncryptBlocksCt64Ctx
};

#endif /* AES_HAVE_CT64 */

/*
** Backend: BearSSL ct (32-bit)
** ----------------------------
*/

#ifdef AES_HAVE_CT32

/*
** CBC encryption with the 32-bit bitsliced AES, one block at a time
** (adapted from BearSSL aes_ct_cbcenc.c; the second lane is unused)
*/
static int
aesCbcEncryptCt32(int rounds, const uint32_t* skey, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  uint32_t q[8];
  uint32_t iv0 = br_dec32le(iv);
  uint32_t iv1 = br_dec32le(iv + 4);
  uint32_t iv2 = br_dec32le(iv + 8);
  uint32_t iv3 = br_dec32le(iv + 12);
  while (len > 0)
  {
    q[1] = 0;
    q[3] = 0;
    q[5] = 0;
    q[7] = 0;
    q[0] = iv0 ^ br_dec32le(buf);
    q[2] = iv1 ^ br_dec32le(buf + 4);
    q[4] = iv2 ^ br_dec32le(buf + 8);
    q[6] = iv3 ^ br_dec32le(buf + 12);
    br_aes_ct_ortho(q);
    br_aes_ct_bitslice_encrypt((unsigned) rounds, skey, q);
    br_aes_ct_ortho(q);
    iv0 = q[0];
    iv1 = q[2];
    iv2 = q[4];
    iv3 = q[6];
    br_enc32le(buf, iv0);
    br_enc32le(buf + 4, iv1);
    br_enc32le(buf + 8, iv2);
    br_enc32le(buf + 12, iv3);
    buf += 16;
    len -= 16;
  }
  return 0;
}

/*
** CBC decryption with the 32-bit bitsliced AES, two blocks in parallel
** (adapted from BearSSL aes_ct_cbcdec.c)
*/
static int
aesCbcDecryptCt32(int rounds, const uint32_t* skey, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  uint32_t iv0 = br_dec32le(iv);
  uint32_t iv1 = br_dec32le(iv + 4);
  uint32_t iv2 = br_dec32le(iv + 8);
  uint32_t iv3 = br_dec32le(iv + 12);
  while (len > 0)
  {
    uint32_t q[8], sq[8];

    q[0] = br_dec32le(buf);
    q[2] = br_dec32le(buf + 4);
    q[4] = br_dec32le(buf + 8);
    q[6] = br_dec32le(buf + 12);
    if (len >= 32)
    {
      q[1] = br_dec32le(buf + 16);
      q[3] = br_dec32le(buf + 20);
      q[5] = br_dec32le(buf + 24);
      q[7] = br_dec32le(buf + 28);
    }
    else
    {
      q[1] = 0;
      q[3] = 0;
      q[5] = 0;
      q[7] = 0;
    }
    memcpy(sq, q, sizeof(q));
    br_aes_ct_ortho(q);
    br_aes_ct_bitslice_decrypt((unsigned) rounds, skey, q);
    br_aes_ct_ortho(q);
    br_enc32le(buf, q[0] ^ iv0);
    br_enc32le(buf + 4, q[2] ^ iv1);
    br_enc32le(buf + 8, q[4] ^ iv2);
    br_enc32le(buf + 12, q[6] ^ iv3);
    if (len < 32)
    {
      break;
    }
    br_enc32le(buf + 16, q[1] ^ sq[0]);
    br_enc32le(buf + 20, q[3] ^ sq[2]);
    br_enc32le(buf + 24, q[5] ^ sq[4]);
    br_enc32le(buf + 28, q[7] ^ sq[6]);
    iv0 = sq[1];
    iv1 = sq[3];
    iv2 = sq[5];
    iv3 = sq[7];
    buf += 32;
    len -= 32;
  }
  return 0;
}

/*
** ECB encryption with the 32-bit bitsliced AES, two blocks in parallel
*/
static int
aesEncryptBlocksCt32(int rounds, const uint32_t* skey, const unsigned char* in, unsigned char* out, size_t nblocks)
{
  while (nblocks > 0)
  {
    uint32_t q[8];

    q[0] = br_dec32le(in);
    q[2] = br_dec32le(in + 4);
    q[4] = br_dec32le(in + 8);
    q[6] = br_dec32le(in + 12);
    if (nblocks >= 2)
    {
      q[1] = br_dec32le(in + 16);
      q[3] = br_dec32le(in + 20);
      q[5] = br_dec32le(in + 24);
      q[7] = br_dec32le(in + 28);
    }
    else
    {
      q[1] = 0;
      q[3] = 0;
      q[5] = 0;
      q[7] = 0;
    }
    br_aes_ct_ortho(q);
    br_aes_ct_bitslice_encrypt((unsigned) rounds, skey, q);
    br_aes_ct_ortho(q);
    br_enc32le(out, q[0]);
    br_enc32le(out + 4, q[2]);
    br_enc32le(out + 8, q[4]);
    br_enc32le(out + 12, q[6]);
    if (nblocks < 2)
    {
      break;
    }
    br_enc32le(out + 16, q[1]);
    br_enc32le(out + 20, q[3]);
    br_enc32le(out + 24, q[5]);
    br_enc32le(out + 28, q[7]);
    in += 32;
    out += 32;
    nblocks -= 2;
  }
  return 0;
}

#ifndef AES_HAVE_CT64
static int
aesAvailableSoftware(void)
{
  return 1;
}
#endif

static int
aesInitCt32(AesCtx* ctx, const unsigned char* key, int keyLen, int flags)
{
  uint32_t compSkey[(AESCBC_MAX_ROUNDS + 1) * 4];
  (void) flags; /* the same key schedule serves both directions */
  ctx->m_rounds = (int) br_aes_ct_keysched(compSkey, key, (size_t) keyLen);
  br_aes_ct_skey_expand(ctx->u.ct32, (unsigned) ctx->m_rounds, compSkey);
  sqlite3mcSecureZeroMemory(compSkey, sizeof(compSkey));
  return SQLITE_OK;
}

static int
aesCbcEncryptCt32Ctx(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return aesCbcEncryptCt32(ctx->m_rounds, ctx->u.ct32, iv, buf, len);
}

static int
aesCbcDecryptCt32Ctx(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return aesCbcDecryptCt32(ctx->m_rounds, ctx->u.ct32, iv, buf, len);
}

static int
aesEncryptBlocksCt32Ctx(const AesCtx* ctx, const unsigned char* in, unsigned char* out, size_t nblocks)
{
  return aesEncryptBlocksCt32(ctx->m_rounds, ctx->u.ct32, in, out, nblocks);
}

static const AesBackend aesBackendCt32 =
{
  AES_IMPL_CT32, "ct32",
  aesAvailableSoftware,
  aesInitCt32,
  aesCbcEncryptCt32Ctx,
  aesCbcDecryptCt32Ctx,
  NULL,
  NULL,
  aesEncryptBlocksCt32Ctx
};

#endif /* AES_HAVE_CT32 */

/*
** Backend: AES hardware
** ---------------------
*/

#ifdef AES_HAVE_HW

static int
aesAvailableHw(void)
{
  return aesHardwareAvailable() ? 1 : 0;
}

static int
aesInitHw(AesCtx* ctx, const unsigned char* key, int keyLen, int flags)
{
  ctx->m_rounds = (keyLen == 16) ? 10 : 14;
  if ((flags & AES_FOR_ENCRYPT) && aesGenKeyEncrypt(key, keyLen * 8, ctx->u.hw.enc) != 0)
  {
    return SQLITE_ERROR;
  }
  if ((flags & AES_FOR_DECRYPT) && aesGenKeyDecrypt(key, keyLen * 8, ctx->u.hw.dec) != 0)
  {
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

static int
aesCbcCtsEncryptHw(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  unsigned char ivec[16];
  memcpy(ivec, iv, 16);
  return aesEncryptCBC(buf, buf, ivec, (unsigned long) len, ctx->u.hw.enc, ctx->m_rounds);
}

static int
aesCbcCtsDecryptHw(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  unsigned char ivec[16];
  memcpy(ivec, iv, 16);
  return aesDecryptCBC(buf, buf, ivec, (unsigned long) len, ctx->u.hw.dec, ctx->m_rounds);
}

/*
** Optional: define SQLITE3MC_AES_HW_HAS_ENCRYPT_BLOCKS and include aes_hw_blocks.c
** (before this file, or provide the function elsewhere) to use the interleaved
** multi-block encryption of the hardware backend for sqlite3mcAesEncryptBlocks():
**   int sqlite3mcAesHwEncryptBlocks(const unsigned char* in, unsigned char* out, size_t nblocks,
**                                   const unsigned char* roundKeys, int rounds)
** roundKeys is the expanded encryption key in the layout of FIPS 197 (ctx->u.hw.enc).
*/
#ifdef SQLITE3MC_AES_HW_HAS_ENCRYPT_BLOCKS
SQLITE_PRIVATE int sqlite3mcAesHwEncryptBlocks(const unsigned char* in, unsigned char* out, size_t nblocks,
                                               const unsigned char* roundKeys, int rounds);

static int
aesEncryptBlocksHw(const AesCtx* ctx, const unsigned char* in, unsigned char* out, size_t nblocks)
{
  return sqlite3mcAesHwEncryptBlocks(in, out, nblocks, ctx->u.hw.enc, ctx->m_rounds);
}
#endif

/*
** aesEncryptCBC() / aesDecryptCBC() of aes_hardware.c already implement CBC
** including ciphertext stealing for lengths that are not a multiple of 16,
** so they serve as the plain CBC function and as the complete CBC+CTS
** function at the same time.
*/
static const AesBackend aesBackendHw =
{
  AES_IMPL_HW, "hardware",
  aesAvailableHw,
  aesInitHw,
  NULL,
  NULL,
  aesCbcCtsEncryptHw,
  aesCbcCtsDecryptHw,
#ifdef SQLITE3MC_AES_HW_HAS_ENCRYPT_BLOCKS
  aesEncryptBlocksHw
#else
  NULL   /* generic function: one aesEncryptCBC call per block with a zero IV */
#endif
};

#endif /* AES_HAVE_HW */

/*
** Backend: vpaes
** --------------
*/

#ifdef AES_HAVE_VPAES

static int
aesAvailableVpaes(void)
{
  return sqlite3mcVpaesAvailable();
}

static int
aesInitVpaes(AesCtx* ctx, const unsigned char* key, int keyLen, int flags)
{
  ctx->m_rounds = (keyLen == 16) ? 10 : 14;
  return (sqlite3mcVpaesInit(ctx->u.vpaes, key, keyLen, flags) == 0) ? SQLITE_OK : SQLITE_ERROR;
}

static int
aesCbcEncryptVpaes(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return sqlite3mcVpaesCbcEncrypt(ctx->u.vpaes, ctx->m_rounds, iv, buf, len);
}

static int
aesCbcDecryptVpaes(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return sqlite3mcVpaesCbcDecrypt(ctx->u.vpaes, ctx->m_rounds, iv, buf, len);
}

static int
aesEncryptBlocksVpaes(const AesCtx* ctx, const unsigned char* in, unsigned char* out, size_t nblocks)
{
  return sqlite3mcVpaesEncryptBlocks(ctx->u.vpaes, ctx->m_rounds, in, out, nblocks);
}

static const AesBackend aesBackendVpaes =
{
  AES_IMPL_VPAES, "vpaes",
  aesAvailableVpaes,
  aesInitVpaes,
  aesCbcEncryptVpaes,
  aesCbcDecryptVpaes,
  NULL,
  NULL,
  aesEncryptBlocksVpaes
};

#endif /* AES_HAVE_VPAES */

/*
** Backend: Rijndael
** -----------------
*/

#ifdef AES_HAVE_RIJNDAEL

/* aes_rijndael.c uses the numeric values of the direction flags */
typedef char aesRijndaelFlagsCheck[(AES_FOR_ENCRYPT == 1 && AES_FOR_DECRYPT == 2) ? 1 : -1];

static int
aesAvailableRijndael(void)
{
  return 1;
}

static int
aesInitRijndael(AesCtx* ctx, const unsigned char* key, int keyLen, int flags)
{
  ctx->m_rounds = (keyLen == 16) ? 10 : 14;
  return (sqlite3mcRijndaelInit(ctx->u.rijndael, key, keyLen, flags) == 0) ? SQLITE_OK : SQLITE_ERROR;
}

static int
aesCbcCtsEncryptRijndael(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return sqlite3mcRijndaelCbcCtsEncrypt(ctx->u.rijndael, iv, buf, len);
}

static int
aesCbcCtsDecryptRijndael(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return sqlite3mcRijndaelCbcCtsDecrypt(ctx->u.rijndael, iv, buf, len);
}

#ifdef SQLITE3MC_RIJNDAEL_HAS_ENCRYPT_BLOCKS
static int
aesEncryptBlocksRijndael(const AesCtx* ctx, const unsigned char* in, unsigned char* out, size_t nblocks)
{
  return sqlite3mcRijndaelEncryptBlocks(ctx->u.rijndael, in, out, nblocks);
}
#endif

static const AesBackend aesBackendRijndael =
{
  AES_IMPL_RIJNDAEL, "rijndael",
  aesAvailableRijndael,
  aesInitRijndael,
  NULL,
  NULL,
  aesCbcCtsEncryptRijndael,
  aesCbcCtsDecryptRijndael,
#ifdef SQLITE3MC_RIJNDAEL_HAS_ENCRYPT_BLOCKS
  aesEncryptBlocksRijndael
#else
  NULL
#endif
};

#endif /* AES_HAVE_RIJNDEAL */

/*
** Backend registry and selection
** ------------------------------
*/

static const AesBackend* const aesBackends[] =
{
#ifdef AES_HAVE_HW
  &aesBackendHw,
#endif
#ifdef AES_HAVE_VPAES
  &aesBackendVpaes,
#endif
#ifdef AES_HAVE_CT64
  &aesBackendCt64,
#endif
#ifdef AES_HAVE_CT32
  &aesBackendCt32,
#endif
#ifdef AES_HAVE_RIJNDAEL
  &aesBackendRijndael,
#endif
  NULL
};

static size_t gAesBackendOrderStart = 0;
static const int gAesBackendOrder[] =
{
  AES_IMPL_HW, AES_IMPL_VPAES, AES_IMPL_CT64, AES_IMPL_CT32, AES_IMPL_RIJNDAEL
};

static size_t
aesGetOrderStart(void)
{
  size_t start;
  sqlite3_mutex* mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MAIN);
  sqlite3_mutex_enter(mutex);
  start = gAesBackendOrderStart;
  sqlite3_mutex_leave(mutex);
  return start;
}

static void
aesSetOrderStart(size_t start)
{
  sqlite3_mutex* mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MAIN);
  sqlite3_mutex_enter(mutex);
  gAesBackendOrderStart = start;
  sqlite3_mutex_leave(mutex);
}

static const AesBackend*
aesFindBackend(int impl)
{
  size_t i;
  for (i = 0; aesBackends[i] != NULL; i++)
  {
    if (aesBackends[i]->m_id == impl)
    {
      return aesBackends[i];
    }
  }
  return NULL;
}

static const AesBackend*
aesSelectBackend(void)
{
  const size_t orderCount = sizeof(gAesBackendOrder) / sizeof(gAesBackendOrder[0]);
  size_t orderStart = aesGetOrderStart();
  size_t j;
  for (j = orderStart; j < orderCount; ++j)
  {
    const AesBackend* backend = aesFindBackend(gAesBackendOrder[j]);
    if (backend != NULL && backend->m_available())
    {
      return backend;
    }
  }
  return NULL;
}

static const char*
aesRequestBackend(const char* selectBackend)
{
  const AesBackend* backend = NULL;
  const size_t orderCount = sizeof(gAesBackendOrder) / sizeof(gAesBackendOrder[0]);
  int backendIndex = 0;
  if (selectBackend != NULL)
  {
    if (sqlite3StrICmp(selectBackend, "auto") == 0)
    {
      aesSetOrderStart(0);
    }
    else
    {
      size_t j, k;
      size_t newOrderStart = orderCount;
      for (j = 0; aesBackends[j] != NULL; ++j)
      {
        /* Find backend id from backend name */
        if (sqlite3StrICmp(aesBackends[j]->m_name, selectBackend) == 0)
          break;
      }
      if (aesBackends[j] == NULL)
      {
        /* Backend unknown or not included */
        return NULL;
      }
      for (k = 0; k < orderCount; ++k)
      {
        if (gAesBackendOrder[k] == aesBackends[j]->m_id)
        {
          newOrderStart = k;
          break;
        }
      }
      if (newOrderStart == orderCount)
      {
        return NULL;
      }
      aesSetOrderStart(newOrderStart);
    }
  }
  backend = aesSelectBackend();
  return (backend != NULL) ? backend->m_name : (const char*)NULL;
}

static const char*
aesBackendInfo()
{
  static char aesInfoBuf[256];
  static int  aesInfoBuilt = 0;

  if (!aesInfoBuilt)
  {
    int k = 0;
    int offset = 0;
    int writeDelim = 0;
    for (k = 0; aesBackends[k] != NULL; ++k)
    {
      if (aesBackends[k]->m_available())
      {
        offset += snprintf(aesInfoBuf + offset, sizeof(aesInfoBuf) - offset,
                           (writeDelim == 0) ? "%s" : ",%s", aesBackends[k]->m_name);
        if (offset >= sizeof(aesInfoBuf)) break;
        writeDelim = 1;
      }
    }
    aesInfoBuilt = 1;
  }
  return aesInfoBuf;
}

/*
** Public functions
** ----------------
*/

/*
** Is the implementation 'impl' compiled in and usable on this machine?
*/
SQLITE_PRIVATE int
sqlite3mcAesImplAvailable(int impl)
{
  const AesBackend* backend = aesFindBackend(impl);
  return (backend != NULL && backend->m_available()) ? 1 : 0;
}

/*
** Name of the implementation used by an initialized context
** ("" if none)
*/
SQLITE_PRIVATE const char*
sqlite3mcAesImplName(const AesCtx* ctx)
{
  return (ctx->m_impl != NULL) ? ctx->m_impl->m_name : "";
}

/*
** Erase all key material of the context
*/
SQLITE_PRIVATE void
sqlite3mcAesCbcWipe(AesCtx* ctx)
{
  sqlite3mcSecureZeroMemory(ctx, sizeof(AesCtx));
}

/*
** Set up a context for a 128-bit or 256-bit key with a specific
** implementation (AES_IMPL_AUTO: automatic selection).
**
** keyLen is the key length in bytes (16 or 32).
** flags: AES_FOR_ENCRYPT, AES_FOR_DECRYPT or AES_FOR_BOTH.
**
** Returns SQLITE_MISUSE for an unsupported key length or flags, and
** SQLITE_ERROR if the requested implementation is not compiled in or
** not available, or if no implementation is available at all.
*/
SQLITE_PRIVATE int
sqlite3mcAesCbcInitImpl(AesCtx* ctx, const unsigned char* key, int keyLen, int flags, int impl)
{
  const AesBackend* backend;
  int rc;
  memset(ctx, 0, sizeof(AesCtx));
  if ((keyLen != 16 && keyLen != 32) || (flags & ~AES_FOR_BOTH) != 0 || flags == 0)
  {
    return SQLITE_MISUSE;
  }
  backend = (impl == AES_IMPL_AUTO) ? aesSelectBackend() : aesFindBackend(impl);
  if (backend == NULL || !backend->m_available())
  {
    return SQLITE_ERROR;
  }
  rc = backend->m_init(ctx, key, keyLen, flags);
  if (rc != SQLITE_OK)
  {
    sqlite3mcAesCbcWipe(ctx);
    return rc;
  }
  ctx->m_impl = backend;
  ctx->m_flags = flags;
  return SQLITE_OK;
}

/*
** Set up a context with automatic selection of the implementation
*/
SQLITE_PRIVATE int
sqlite3mcAesCbcInit(AesCtx* ctx, const unsigned char* key, int keyLen, int flags)
{
  return sqlite3mcAesCbcInitImpl(ctx, key, keyLen, flags, AES_IMPL_AUTO);
}

/*
** Generic block encryption (ECB) for backends without m_encryptBlocks:
** one block at a time with the CBC function of the backend and a zero IV
** (the first block of CBC with a zero IV is the plain ECB encryption).
*/
static int
aesEncryptBlocksGeneric(const AesCtx* ctx, const unsigned char* in, unsigned char* out, size_t nblocks)
{
  static const unsigned char zeroIv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  size_t i;
  for (i = 0; i < nblocks; i++)
  {
    unsigned char* block = out + i * 16;
    if (block != in + i * 16)
    {
      memcpy(block, in + i * 16, 16);
    }
    if (ctx->m_impl->m_cbcEncrypt != NULL)
    {
      ctx->m_impl->m_cbcEncrypt(ctx, zeroIv, block, 16);
    }
    else
    {
      ctx->m_impl->m_cbcCtsEncrypt(ctx, zeroIv, block, 16);
    }
  }
  return SQLITE_OK;
}

/*
** Encrypt nblocks independent 16-byte blocks (ECB), in place (in == out)
** or without overlap of in and out.
**
** Returns SQLITE_OK, or SQLITE_MISUSE if the context is not initialized for
** encryption, or the error code of the backend.
*/
SQLITE_PRIVATE int
sqlite3mcAesEncryptBlocks(const AesCtx* ctx, const unsigned char* in, unsigned char* out, size_t nblocks)
{
  if (ctx->m_impl == NULL || (ctx->m_flags & AES_FOR_ENCRYPT) == 0)
  {
    return SQLITE_MISUSE;
  }
  if (nblocks == 0)
  {
    return SQLITE_OK;
  }
  if (ctx->m_impl->m_encryptBlocks != NULL)
  {
    return (ctx->m_impl->m_encryptBlocks(ctx, in, out, nblocks) == 0) ? SQLITE_OK : SQLITE_ERROR;
  }
  return aesEncryptBlocksGeneric(ctx, in, out, nblocks);
}

/*
** Encrypt len bytes in place
** Method: CBC, with CTS if len is not a multiple of 16.
** The IV is not modified.
**
** Returns SQLITE_OK, or SQLITE_MISUSE if the context is not
** initialized for encryption, or if len is not a multiple of 16
** and less than 16.
**
** With len = 16 * n + r (0 < r < 16, n >= 1):
**   C_1 ... C_n = CBC(P_1 ... P_n)
**   C*          = Enc(C_n xor (P_{n+1} padded with zeros))
**   output      = C_1 ... C_{n-1} || C* || C_n[0..r)
*/
SQLITE_PRIVATE int
sqlite3mcAesCbcEncrypt(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  size_t n = len / 16;
  size_t r = len % 16;
  if (ctx->m_impl == NULL || (ctx->m_flags & AES_FOR_ENCRYPT) == 0)
  {
    return SQLITE_MISUSE;
  }
  if (len == 0)
  {
    return SQLITE_OK;   /* nothing to do; the backend is not called */
  }
  if (ctx->m_impl->m_cbcCtsEncrypt != NULL && n > 0)
  {
    ctx->m_impl->m_cbcCtsEncrypt(ctx, iv, buf, len);   /* native CBC+CTS of the backend */
  }
  else if (r == 0)
  {
    ctx->m_impl->m_cbcEncrypt(ctx, iv, buf, len);
  }
  else if (n == 0)
  {
    return SQLITE_MISUSE;
  }
  else
  {
    unsigned char cn[16];
    unsigned char last[16];

    ctx->m_impl->m_cbcEncrypt(ctx, iv, buf, n * 16);   /* C_1 ... C_n */
    memcpy(cn, buf + (n - 1) * 16, 16);                /* C_n */
    memset(last, 0, 16);
    memcpy(last, buf + n * 16, r);                     /* P_{n+1}, padded with zeros */
    ctx->m_impl->m_cbcEncrypt(ctx, cn, last, 16);      /* C* = Enc(last xor C_n) */
    memcpy(buf + (n - 1) * 16, last, 16);
    memcpy(buf + n * 16, cn, r);
    sqlite3mcSecureZeroMemory(last, sizeof(last));
  }
  return SQLITE_OK;
}

/*
** Decrypt len bytes in place
** Method: CBC, with CTS if len is not a multiple of 16.
** The IV is not modified.
** Returns SQLITE_OK, or SQLITE_MISUSE if the context is not
** initialized for decryption, or if len is not a multiple of 16
** and less than 16.
*/
SQLITE_PRIVATE int
sqlite3mcAesCbcDecrypt(const AesCtx* ctx, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  size_t n = len / 16;
  size_t r = len % 16;
  if (ctx->m_impl == NULL || (ctx->m_flags & AES_FOR_DECRYPT) == 0)
  {
    return SQLITE_MISUSE;
  }
  if (len == 0)
  {
    return SQLITE_OK;   /* nothing to do; the backend is not called */
  }
  if (ctx->m_impl->m_cbcCtsDecrypt != NULL && n > 0)
  {
    ctx->m_impl->m_cbcCtsDecrypt(ctx, iv, buf, len);   /* native CBC+CTS of the backend */
  }
  else if (r == 0)
  {
    ctx->m_impl->m_cbcDecrypt(ctx, iv, buf, len);
  }
  else if (n == 0)
  {
    return SQLITE_MISUSE;
  }
  else
  {
    unsigned char prev[16]; /* C_{n-1}, or the IV if n == 1 */
    unsigned char d[16];
    unsigned char cn[16];
    unsigned char tail[16];
    unsigned char zero[16];
    size_t i;

    /* C_{n-1} must be saved before the in-place decryption overwrites it */
    memcpy(prev, (n >= 2) ? buf + (n - 2) * 16 : iv, 16);
    if (n >= 2)
    {
      ctx->m_impl->m_cbcDecrypt(ctx, iv, buf, (n - 1) * 16);   /* P_1 ... P_{n-1} */
    }
    memset(zero, 0, 16);
    memcpy(d, buf + (n - 1) * 16, 16);                         /* C* */
    ctx->m_impl->m_cbcDecrypt(ctx, zero, d, 16);               /* D = Dec(C*) = C_n xor (P_{n+1} padded) */

    memcpy(cn, buf + n * 16, r);                               /* C_n[0..r) */
    for (i = 0; i < r; i++)
    {
      tail[i] = d[i] ^ cn[i];                                  /* P_{n+1} */
    }
    memcpy(cn + r, d + r, 16 - r);                             /* C_n completed with D[r..16) */
    ctx->m_impl->m_cbcDecrypt(ctx, prev, cn, 16);              /* P_n */
    memcpy(buf + (n - 1) * 16, cn, 16);
    memcpy(buf + n * 16, tail, r);

    sqlite3mcSecureZeroMemory(d, sizeof(d));
    sqlite3mcSecureZeroMemory(cn, sizeof(cn));
    sqlite3mcSecureZeroMemory(tail, sizeof(tail));
  }
  return SQLITE_OK;
}
