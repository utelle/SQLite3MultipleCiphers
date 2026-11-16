/*
** Tests for the AES implementations (aes_core.c, aes_gcm.c):
**
** 1. Known-answer tests for every AES backend that is compiled in and
**    available on this machine: FIPS-197 (block encryption), NIST SP 800-38A
**    (CBC), CBC with ciphertext stealing (reference values computed with an
**    independent implementation) and the XAES-256-GCM test vectors of
**    c2sp.org/XAES-256-GCM with every GHASH variant.
** 2. All backends must give the same result for random keys, IVs and data:
**    CBC with and without ciphertext stealing, block encryption (ECB) and
**    XAES-256-GCM, also for buffers that do not start on an aligned address.
** 3. XAES-256-GCM must reject a changed ciphertext, tag, AAD, nonce or page
**    number, and must not return any plaintext in that case.
** 4. Invalid use (wrong direction, key length, data length) must be refused.
**
** Usage: aestest [rounds]
*/

#include "sqlite3mc.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, ...) do { \
  checks++; \
  if (!(cond)) { failures++; if (failures <= 50) { printf("  [FAIL] "); printf(__VA_ARGS__); printf("\n"); } } \
} while (0)

static const int implIds[] = { AES_IMPL_HW, AES_IMPL_VPAES, AES_IMPL_CT64, AES_IMPL_CT32, AES_IMPL_RIJNDAEL };
static const char* implNames[] = { "auto", "hardware", "vpaes", "ct64", "ct32", "rijndael" };
static const int ghashIds[] = { AES_GHASH_BITWISE, AES_GHASH_CTMUL64, AES_GHASH_PCLMUL, AES_GHASH_PMULL };
static const char* ghashNames[] = { "auto", "bitwise", "ctmul64", "pclmul", "pmull" };

#define MAX_IMPLS 5
static int impls[MAX_IMPLS];
static int implCount;

/* Deterministic pseudo random numbers (xorshift64*) */
static uint64_t rngState = 0x9e3779b97f4a7c15ULL;
static unsigned int rnd(void)
{
  rngState ^= rngState >> 12;
  rngState ^= rngState << 25;
  rngState ^= rngState >> 27;
  return (unsigned int) ((rngState * 0x2545f4914f6cdd1dULL) >> 32);
}
static void rndFill(unsigned char* p, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) p[i] = (unsigned char) rnd();
}

static int fromHex(const char* hex, unsigned char* out)
{
  int n = 0;
  while (hex[0] != 0 && hex[1] != 0)
  {
    out[n++] = (unsigned char) ((sqlite3mcConvertHex2Int(hex[0]) << 4) | sqlite3mcConvertHex2Int(hex[1]));
    hex += 2;
  }
  return n;
}

/*
** 1. Known-answer tests
*/
static const struct { const char *key, *plain, *cipher; } blockVectors[] =
{
  /* FIPS-197, C.1 and C.3 */
  { "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a" },
  { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089" },
};

static const struct { const char *key, *iv, *plain, *cipher; } cbcVectors[] =
{
  /* NIST SP 800-38A, F.2.1 and F.2.5 */
  { "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7" },
  { "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b" },
  /* CBC with ciphertext stealing (CS3), computed with Go's crypto/aes and crypto/cipher */
  { "41552839245c203106f61bd675e3ca04", "b6df0a1f17200eb4a0ae2053dd0e3d29",
    "8ab4b89a8ff6a03670abca95bda44b63ab", "1f774be3ab5041bffa0ff008468a6ce266" },
  { "fc531667002f1ebb67ca3e75d759e257", "598525ffbb7248c65de585602bb53b26",
    "b5fa46855f02e484e33c39c0d4d169daee6fc525afd566e827cbfa0b2423d8a9e6",
    "1c533667d38fba6afb3079daa20bca50437c76db9fda054e4734d72ca13f8aee0e" },
  { "a61d27b5f45ecd8442b4b827d11f52ff57958a19a73f4e67131054e8dc5ba76f", "4ff7b6684b972b5605398b2dfc5b2167",
    "0e8330da06905b46e8d8353fbbe2d8f734", "f038b40866eb000b7e7650c1a94fbba13e" },
  { "2fd3ae26424cd862a7fcb5786e22388e70d7fe54a0bfe8994aaaea13b5d1cdae", "4a9b07da83342709726519be64e8c2ea",
    "b5e27d92a2cea68258a1a3a34dc98cd738f0ab13b06af5f176437aaab65b9a1860",
    "c70f3cb9823dc350bb0fb52cf2f2f5efce682a281936065c5a79e69c4fc33fc0f1" },
  { "f4810cf3989f83f53d91f048d03c0bc45b4973eeca324136f554b110a16ddc52", "fb7754dca84a521d4bf56a65f7098e62",
    "e643fd1a0c1db324774ec1f083a2a515c42c8bfe03ebeb1d76054780ed75ff15c63b9fbd1e0ee844bc17e310364f73",
    "7ff4a3590859438d92b97e68cb33cd010da8ed95e07ebbf3c2ce79b30de6b11514138b4261e13d9072b747c9c7493d" },
};

/* c2sp.org/XAES-256-GCM: key, nonce, AAD, plaintext, ciphertext || tag */
static const struct { const char *key, *nonce, *aad, *plain, *sealed; } xaesVectors[] =
{
  { "0101010101010101010101010101010101010101010101010101010101010101",
    "4142434445464748494a4b4c4d4e4f505152535455565758", "",
    "584145532d3235362d47434d", "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271" },
  { "0303030303030303030303030303030303030303030303030303030303030303",
    "4142434445464748494a4b4c4d4e4f505152535455565758", "633273702e6f72672f584145532d3235362d47434d",
    "584145532d3235362d47434d", "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d" },
};

static void testKnownAnswers(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32], iv[16], plain[64], cipher[80], buf[80], aad[32], nonce[24], tag[16];
  AesCtx ctx;
  size_t i, g;

  for (i = 0; i < sizeof(blockVectors) / sizeof(blockVectors[0]); i++)
  {
    int keyLen = fromHex(blockVectors[i].key, key);
    fromHex(blockVectors[i].plain, plain);
    fromHex(blockVectors[i].cipher, cipher);
    CHECK(sqlite3mcAesCbcInitImpl(&ctx, key, keyLen, AES_FOR_ENCRYPT, impl) == SQLITE_OK, "%s: init AES-%d", name, keyLen * 8);
    CHECK(sqlite3mcAesEncryptBlocks(&ctx, plain, buf, 1) == SQLITE_OK && memcmp(buf, cipher, 16) == 0,
          "%s: FIPS-197 AES-%d", name, keyLen * 8);
    sqlite3mcAesCbcWipe(&ctx);
  }

  for (i = 0; i < sizeof(cbcVectors) / sizeof(cbcVectors[0]); i++)
  {
    int keyLen = fromHex(cbcVectors[i].key, key);
    int len;
    fromHex(cbcVectors[i].iv, iv);
    len = fromHex(cbcVectors[i].plain, plain);
    fromHex(cbcVectors[i].cipher, cipher);
    sqlite3mcAesCbcInitImpl(&ctx, key, keyLen, AES_FOR_BOTH, impl);
    memcpy(buf, plain, len);
    CHECK(sqlite3mcAesCbcEncrypt(&ctx, iv, buf, len) == SQLITE_OK && memcmp(buf, cipher, len) == 0,
          "%s: CBC AES-%d encrypt, %d bytes", name, keyLen * 8, len);
    CHECK(sqlite3mcAesCbcDecrypt(&ctx, iv, buf, len) == SQLITE_OK && memcmp(buf, plain, len) == 0,
          "%s: CBC AES-%d decrypt, %d bytes", name, keyLen * 8, len);
    sqlite3mcAesCbcWipe(&ctx);
  }

  for (g = 0; g < sizeof(ghashIds) / sizeof(ghashIds[0]); g++)
  {
    if (sqlite3mcAesGhashSelect(ghashIds[g]) != 0) continue;
    for (i = 0; i < sizeof(xaesVectors) / sizeof(xaesVectors[0]); i++)
    {
      int aadLen, len;
      fromHex(xaesVectors[i].key, key);
      fromHex(xaesVectors[i].nonce, nonce);
      aadLen = fromHex(xaesVectors[i].aad, aad);
      len = fromHex(xaesVectors[i].plain, plain);
      fromHex(xaesVectors[i].sealed, cipher);
      CHECK(sqlite3mcAesXaesInitImpl(&ctx, key, impl) == SQLITE_OK, "%s: XAES init", name);
      CHECK(sqlite3mcAesXaesSeal(&ctx, nonce, aad, aadLen, plain, len, buf, tag) == SQLITE_OK &&
            memcmp(buf, cipher, len) == 0 && memcmp(tag, cipher + len, 16) == 0,
            "%s/%s: XAES-256-GCM test vector %d", name, ghashNames[ghashIds[g]], (int) i + 1);
      CHECK(sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, buf, len, tag, buf) == SQLITE_OK && memcmp(buf, plain, len) == 0,
            "%s/%s: XAES-256-GCM test vector %d, open", name, ghashNames[ghashIds[g]], (int) i + 1);
      sqlite3mcAesCbcWipe(&ctx);
    }
  }
  sqlite3mcAesGhashSelect(AES_GHASH_AUTO);
}

/*
** 2. All backends against each other
*/
#define MAX_LEN 4200
static unsigned char data[MAX_LEN + 32];
static unsigned char ref[MAX_LEN + 32];
static unsigned char work[MAX_LEN + 32];

static void testCrossCbc(int rounds)
{
  unsigned char key[32], iv[16], ivCopy[16];
  AesCtx ctx;
  int r, k;
  for (r = 0; r < rounds; r++)
  {
    int keyLen = (r & 1) ? 32 : 16;
    int len = (r % 5 == 0) ? 16 * (1 + rnd() % (MAX_LEN / 16)) : 16 + rnd() % (MAX_LEN - 15);
    int offset = rnd() % 16;
    rndFill(key, keyLen);
    rndFill(iv, 16);
    rndFill(data, len);
    memcpy(ivCopy, iv, 16);
    for (k = 0; k < implCount; k++)
    {
      unsigned char* p = work + offset;
      memcpy(p, data, len);
      sqlite3mcAesCbcInitImpl(&ctx, key, keyLen, AES_FOR_BOTH, impls[k]);
      CHECK(sqlite3mcAesCbcEncrypt(&ctx, iv, p, len) == SQLITE_OK, "%s: CBC encrypt, %d bytes", implNames[impls[k]], len);
      if (k == 0)
        memcpy(ref, p, len);
      else
        CHECK(memcmp(ref, p, len) == 0, "%s: CBC AES-%d, %d bytes, offset %d differs from %s",
              implNames[impls[k]], keyLen * 8, len, offset, implNames[impls[0]]);
      CHECK(sqlite3mcAesCbcDecrypt(&ctx, iv, p, len) == SQLITE_OK && memcmp(p, data, len) == 0,
            "%s: CBC AES-%d, %d bytes, decrypt", implNames[impls[k]], keyLen * 8, len);
      CHECK(memcmp(iv, ivCopy, 16) == 0, "%s: IV changed", implNames[impls[k]]);
      sqlite3mcAesCbcWipe(&ctx);
    }
  }
}

static void testCrossBlocks(int rounds)
{
  unsigned char key[32];
  AesCtx ctx;
  int r, k;
  for (r = 0; r < rounds; r++)
  {
    int keyLen = (r & 1) ? 32 : 16;
    size_t blocks = 1 + rnd() % 64;
    int offset = rnd() % 16;
    rndFill(key, keyLen);
    rndFill(data, blocks * 16);
    for (k = 0; k < implCount; k++)
    {
      unsigned char* out = work + offset;
      sqlite3mcAesCbcInitImpl(&ctx, key, keyLen, AES_FOR_ENCRYPT, impls[k]);
      CHECK(sqlite3mcAesEncryptBlocks(&ctx, data, out, blocks) == SQLITE_OK, "%s: block encryption", implNames[impls[k]]);
      if (k == 0)
        memcpy(ref, out, blocks * 16);
      else
        CHECK(memcmp(ref, out, blocks * 16) == 0, "%s: %d blocks AES-%d differ from %s",
              implNames[impls[k]], (int) blocks, keyLen * 8, implNames[impls[0]]);
      memcpy(out, data, blocks * 16);
      sqlite3mcAesEncryptBlocks(&ctx, out, out, blocks);
      CHECK(memcmp(ref, out, blocks * 16) == 0, "%s: %d blocks in place", implNames[impls[k]], (int) blocks);
      sqlite3mcAesCbcWipe(&ctx);
    }
  }
}

/*
** 2. and 3.: XAES-256-GCM with every backend and every GHASH variant
*/
static int allZero(const unsigned char* p, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) if (p[i] != 0) return 0;
  return 1;
}

static void testCrossXaes(int rounds)
{
  unsigned char key[32], nonce[24], aad[40], tag[16], refTag[16], badTag[16];
  AesCtx ctx;
  int r, k;
  size_t g;
  for (r = 0; r < rounds; r++)
  {
    size_t len = rnd() % (MAX_LEN + 1);
    size_t aadLen = rnd() % sizeof(aad);
    int first = 1;
    rndFill(key, 32);
    rndFill(nonce, 24);
    rndFill(aad, aadLen);
    rndFill(data, len);
    for (k = 0; k < implCount; k++)
    {
      for (g = 0; g < sizeof(ghashIds) / sizeof(ghashIds[0]); g++)
      {
        const char* name = implNames[impls[k]];
        const char* gname = ghashNames[ghashIds[g]];
        int rc;
        if (sqlite3mcAesGhashSelect(ghashIds[g]) != 0) continue;
        sqlite3mcAesXaesInitImpl(&ctx, key, impls[k]);
        CHECK(sqlite3mcAesXaesSeal(&ctx, nonce, aad, aadLen, data, len, work, tag) == SQLITE_OK, "%s/%s: XAES seal", name, gname);
        if (first)
        {
          memcpy(ref, work, len);
          memcpy(refTag, tag, 16);
          first = 0;
        }
        else
        {
          CHECK(memcmp(ref, work, len) == 0 && memcmp(refTag, tag, 16) == 0,
                "%s/%s: XAES, %d bytes, AAD %d bytes differs", name, gname, (int) len, (int) aadLen);
        }
        CHECK(sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, work, len, tag, work) == SQLITE_OK && memcmp(work, data, len) == 0,
              "%s/%s: XAES open in place, %d bytes", name, gname, (int) len);

        /* Tag, ciphertext, AAD and nonce changed: refused, no plaintext */
        memcpy(badTag, tag, 16);
        badTag[rnd() % 16] ^= (unsigned char) (1 << (rnd() % 8));
        memset(work, 0x55, len);
        rc = sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, ref, len, badTag, work);
        CHECK(rc == AES_GCM_TAG_MISMATCH && allZero(work, len), "%s/%s: changed tag accepted", name, gname);
        if (len > 0)
        {
          size_t pos = rnd() % len;
          ref[pos] ^= 0x01;
          memset(work, 0x55, len);
          rc = sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, ref, len, tag, work);
          CHECK(rc == AES_GCM_TAG_MISMATCH && allZero(work, len), "%s/%s: changed ciphertext accepted", name, gname);
          ref[pos] ^= 0x01;
        }
        if (aadLen > 0)
        {
          aad[0] ^= 0x80;
          rc = sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, ref, len, tag, work);
          CHECK(rc == AES_GCM_TAG_MISMATCH, "%s/%s: changed AAD accepted", name, gname);
          aad[0] ^= 0x80;
        }
        nonce[23] ^= 0x01;
        rc = sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, ref, len, tag, work);
        CHECK(rc == AES_GCM_TAG_MISMATCH, "%s/%s: changed nonce accepted", name, gname);
        nonce[23] ^= 0x01;
        sqlite3mcAesCbcWipe(&ctx);
      }
    }
  }
  sqlite3mcAesGhashSelect(AES_GHASH_AUTO);
}

/* SQLCipher 5 page functions: page number is authenticated */
static void testPages(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32], page[4096], enc[4096], reserve[AES_XAES_RESERVE_SIZE];
  size_t len = sizeof(page) - AES_XAES_RESERVE_SIZE;
  AesCtx ctx;
  rndFill(key, 32);
  rndFill(page, sizeof(page));
  rndFill(reserve, AES_XAES_NONCE_SIZE);
  sqlite3mcAesXaesInitImpl(&ctx, key, impl);
  CHECK(sqlite3mcAesXaesPageSeal(&ctx, 7, page, len, enc, reserve) == SQLITE_OK, "%s: page seal", name);
  CHECK(sqlite3mcAesXaesPageOpen(&ctx, 7, enc, len, work, reserve) == SQLITE_OK && memcmp(work, page, len) == 0,
        "%s: page open", name);
  CHECK(sqlite3mcAesXaesPageOpen(&ctx, 8, enc, len, work, reserve) == AES_GCM_TAG_MISMATCH, "%s: page with wrong page number accepted", name);
  sqlite3mcAesCbcWipe(&ctx);
}

/*
** 4. Invalid use
*/
static void testMisuse(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32] = { 1 }, iv[16] = { 2 }, buf[64] = { 0 }, nonce[24] = { 0 }, tag[16];
  AesCtx ctx;
  CHECK(sqlite3mcAesCbcInitImpl(&ctx, key, 24, AES_FOR_BOTH, impl) == SQLITE_MISUSE, "%s: 24-byte key accepted", name);
  CHECK(sqlite3mcAesCbcInitImpl(&ctx, key, 16, 0, impl) == SQLITE_MISUSE, "%s: no direction accepted", name);
  sqlite3mcAesCbcInitImpl(&ctx, key, 32, AES_FOR_ENCRYPT, impl);
  CHECK(sqlite3mcAesCbcDecrypt(&ctx, iv, buf, 32) == SQLITE_MISUSE, "%s: decryption with encryption context", name);
  CHECK(sqlite3mcAesCbcEncrypt(&ctx, iv, buf, 15) == SQLITE_MISUSE, "%s: 15 bytes accepted", name);
  CHECK(sqlite3mcAesXaesSeal(&ctx, nonce, NULL, 0, buf, 16, buf, tag) == SQLITE_MISUSE, "%s: XAES with plain AES context", name);
  sqlite3mcAesCbcInitImpl(&ctx, key, 32, AES_FOR_DECRYPT, impl);
  CHECK(sqlite3mcAesCbcEncrypt(&ctx, iv, buf, 32) == SQLITE_MISUSE, "%s: encryption with decryption context", name);
  CHECK(sqlite3mcAesEncryptBlocks(&ctx, buf, buf, 1) == SQLITE_MISUSE, "%s: block encryption with decryption context", name);
  sqlite3mcAesCbcWipe(&ctx);
}

int main(int argc, char** argv)
{
  int rounds = (argc > 1) ? atoi(argv[1]) : 200;
  size_t i;

  printf("AES backends:");
  for (i = 0; i < sizeof(implIds) / sizeof(implIds[0]); i++)
  {
    if (sqlite3mcAesImplAvailable(implIds[i]))
    {
      impls[implCount++] = implIds[i];
      printf(" %s", implNames[implIds[i]]);
    }
  }
  printf("\nGHASH variants:");
  for (i = 0; i < sizeof(ghashIds) / sizeof(ghashIds[0]); i++)
  {
    if (sqlite3mcAesGhashGet(ghashIds[i]) != NULL) printf(" %s", ghashNames[ghashIds[i]]);
  }
  printf("\n");
  if (implCount == 0)
  {
    printf("No AES backend available\n");
    return 0;
  }

  for (i = 0; i < (size_t) implCount; i++)
  {
    int before = failures;
    testKnownAnswers(impls[i]);
    testPages(impls[i]);
    testMisuse(impls[i]);
    printf("  %-9s known answers, pages, misuse: %s\n", implNames[impls[i]], failures == before ? "ok" : "FAILED");
  }
  testCrossCbc(rounds * 10);
  testCrossBlocks(rounds);
  testCrossXaes(rounds);

  printf("%d checks, %d failures\n", checks, failures);
  return failures != 0;
}
