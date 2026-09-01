#include "crypto_stream_chacha20.h"
#include "private/chacha20_ietf_ext.h"
#include "private/common.h"
#include "stream_chacha20.h"

#if defined(SQLITE3MC_TARGET_X86)
/* Original order: avx512, avx2, ssse3 */
# include "dolbeau/chacha20_dolbeau-ssse3.c"
# include "dolbeau/chacha20_dolbeau-avx2.c"
# include "dolbeau/chacha20_dolbeau-avx512.c"
#elif defined(SQLITE3MC_TARGET_ARM) && defined(__ARM_NEON)
# include "dolbeau/chacha20_dolbeau-neon.c"
#endif

static const crypto_stream_chacha20_implementation* sodium_chacha20_implementation = NULL;

#if 0
/* Functions not used in SQLite3MC context */

size_t
crypto_stream_chacha20_keybytes(void) {
    return crypto_stream_chacha20_KEYBYTES;
}

size_t
crypto_stream_chacha20_noncebytes(void) {
    return crypto_stream_chacha20_NONCEBYTES;
}

size_t
crypto_stream_chacha20_messagebytes_max(void)
{
    return crypto_stream_chacha20_MESSAGEBYTES_MAX;
}

size_t
crypto_stream_chacha20_ietf_keybytes(void) {
    return crypto_stream_chacha20_ietf_KEYBYTES;
}

size_t
crypto_stream_chacha20_ietf_noncebytes(void) {
    return crypto_stream_chacha20_ietf_NONCEBYTES;
}

size_t
crypto_stream_chacha20_ietf_messagebytes_max(void)
{
    return crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX;
}
#endif

int
crypto_stream_chacha20(unsigned char *c, unsigned long long clen,
                       const unsigned char *n, const unsigned char *k)
{
    if (clen > crypto_stream_chacha20_MESSAGEBYTES_MAX) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return sodium_chacha20_implementation->stream(c, clen, n, k);
}

int
crypto_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n, uint64_t ic,
                              const unsigned char *k)
{
    if (mlen > crypto_stream_chacha20_MESSAGEBYTES_MAX) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return sodium_chacha20_implementation->stream_xor_ic(c, m, mlen, n, ic, k);
}

int
crypto_stream_chacha20_xor(unsigned char *c, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *n,
                           const unsigned char *k)
{
    if (mlen > crypto_stream_chacha20_MESSAGEBYTES_MAX) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return sodium_chacha20_implementation->stream_xor_ic(c, m, mlen, n, 0U, k);
}

int
crypto_stream_chacha20_ietf_ext(unsigned char *c, unsigned long long clen,
                                const unsigned char *n, const unsigned char *k)
{
    if (clen > crypto_stream_chacha20_MESSAGEBYTES_MAX) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return sodium_chacha20_implementation->stream_ietf_ext(c, clen, n, k);
}

int
crypto_stream_chacha20_ietf_ext_xor_ic(unsigned char *c, const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *n, uint32_t ic,
                                       const unsigned char *k)
{
    if (mlen > crypto_stream_chacha20_MESSAGEBYTES_MAX) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return sodium_chacha20_implementation->stream_ietf_ext_xor_ic(c, m, mlen, n, ic, k);
}

static int
crypto_stream_chacha20_ietf_ext_xor(unsigned char *c, const unsigned char *m,
                                    unsigned long long mlen, const unsigned char *n,
                                    const unsigned char *k)
{
    if (mlen > crypto_stream_chacha20_MESSAGEBYTES_MAX) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return sodium_chacha20_implementation->stream_ietf_ext_xor_ic(c, m, mlen, n, 0U, k);
}

int
crypto_stream_chacha20_ietf(unsigned char *c, unsigned long long clen,
                            const unsigned char *n, const unsigned char *k)
{
    if (clen > crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return crypto_stream_chacha20_ietf_ext(c, clen, n, k);
}

int
crypto_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
                                   unsigned long long mlen,
                                   const unsigned char *n, uint32_t ic,
                                   const unsigned char *k)
{
    if ((unsigned long long) ic >
        (64ULL * (1ULL << 32)) / 64ULL - (mlen + 63ULL) / 64ULL) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return crypto_stream_chacha20_ietf_ext_xor_ic(c, m, mlen, n, ic, k);
}

int
crypto_stream_chacha20_ietf_xor(unsigned char *c, const unsigned char *m,
                                unsigned long long mlen, const unsigned char *n,
                                const unsigned char *k)
{
    if (mlen > crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return crypto_stream_chacha20_ietf_ext_xor(c, m, mlen, n, k);
}

void
crypto_stream_chacha20_ietf_keygen(unsigned char k[crypto_stream_chacha20_ietf_KEYBYTES])
{
    randombytes_buf(k, crypto_stream_chacha20_ietf_KEYBYTES);
}

void
crypto_stream_chacha20_keygen(unsigned char k[crypto_stream_chacha20_KEYBYTES])
{
    randombytes_buf(k, crypto_stream_chacha20_KEYBYTES);
}


#define SQLITE3MC_CHACHA20_HWACCL_UNKNOWN -1
#define SQLITE3MC_CHACHA20_HWACCL_OFF      0

/* X86 options */
#define SQLITE3MC_CHACHA20_HWACCL_SSSE3    1
#define SQLITE3MC_CHACHA20_HWACCL_AVX2     2
#define SQLITE3MC_CHACHA20_HWACCL_AVX512   3

/* ARM options */
#define SQLITE3MC_CHACHA20_HWACCL_NEON     4

#define SQLITE3MC_CHACHA20_HWACCL_AUTO     5
#define SQLITE3MC_CHACHA20_HWACCL_MAX      6

/*                                         0      1        2       3          4       5     */
static char* gChaCha20HwAccelOptions[] = { "off", "ssse3", "avx2", "avx512f", "neon", "auto" };
static int gChaCha20HwAccelRequest = SQLITE3MC_CHACHA20_HWACCL_AUTO;
static int gChaCha20HwAccelSelected = SQLITE3MC_CHACHA20_HWACCL_UNKNOWN;

/*
** The following constants define the range of valid options per hardware family
**
** gChaCha20HwAccelMin specifies the minimal allowed option in the range.
** gChaCha20HwAccelMax specifies the maximal allowed option in the range.
**
** gChaCha20HwAccelAuto specifies the default value in the range.
** This constant allows to exclude experimental options.
** For example, the AVX512F implementation is currently experimental
** and not yet included in official releases of libsodium.
** If the status in libsodium changes in the future, the value of this constant
** may be changed accordingly. However, the option AVX512F can be chosen explicitly
** at the user's discretion. The same is true for the NEON option on ARM.
*/

#if defined(SQLITE3MC_TARGET_X86)
static int gChaCha20HwAccelMin = SQLITE3MC_CHACHA20_HWACCL_SSSE3;
static int gChaCha20HwAccelMax = SQLITE3MC_CHACHA20_HWACCL_AVX512;
static int gChaCha20HwAccelAuto = SQLITE3MC_CHACHA20_HWACCL_AVX2;
#elif defined(SQLITE3MC_TARGET_ARM)
static int gChaCha20HwAccelMin = SQLITE3MC_CHACHA20_HWACCL_NEON;
static int gChaCha20HwAccelMax = SQLITE3MC_CHACHA20_HWACCL_NEON;
static int gChaCha20HwAccelAuto = SQLITE3MC_CHACHA20_HWACCL_OFF;
#elif defined(SQLITE3MC_TARGET_WASM)
static int gChaCha20HwAccelMin = SQLITE3MC_CHACHA20_HWACCL_SSSE3;
static int gChaCha20HwAccelMax = SQLITE3MC_CHACHA20_HWACCL_SSSE3;
static int gChaCha20HwAccelAuto = SQLITE3MC_CHACHA20_HWACCL_SSSE3;
#endif

SODIUM_EXPORT int
sqlite3mcChaCha20HwAccelerated()
{
  int rc = 0;
  if (gChaCha20HwAccelSelected == SQLITE3MC_CHACHA20_HWACCL_UNKNOWN)
  {
    rc = crypto_stream_chacha20_pick_best_implementation();
  }
  return gChaCha20HwAccelSelected > 0;
}

SODIUM_EXPORT const char*
sqlite3mcChaCha20HwConfig(const char* option)
{
  int rc;
  if (strlen(option) > 0)
  {
    /* Identify option */
    int optRequested = SQLITE3MC_CHACHA20_HWACCL_UNKNOWN;
    int k;
    for (k = SQLITE3MC_CHACHA20_HWACCL_OFF; k < SQLITE3MC_CHACHA20_HWACCL_MAX; ++k)
    {
      if (sqlite3StrICmp(option, gChaCha20HwAccelOptions[k]) == 0)
      {
        optRequested = k;
        break;
      }
    }

    int valid = (optRequested == SQLITE3MC_CHACHA20_HWACCL_OFF) ||
                (optRequested == SQLITE3MC_CHACHA20_HWACCL_AUTO) ||
                (optRequested >= gChaCha20HwAccelMin && optRequested <= gChaCha20HwAccelMax);
    if (!valid)
      return NULL;

    /* Reset current selected option, if necessary */
    if (optRequested != gChaCha20HwAccelSelected)
    {
      /* Reset selected option */
      if (optRequested == SQLITE3MC_CHACHA20_HWACCL_AUTO)
        gChaCha20HwAccelRequest = gChaCha20HwAccelAuto;
      else
        gChaCha20HwAccelRequest = optRequested;
      rc = crypto_stream_chacha20_pick_best_implementation();
    }
  }
  else if (gChaCha20HwAccelSelected == SQLITE3MC_CHACHA20_HWACCL_UNKNOWN)
  {
    gChaCha20HwAccelRequest = SQLITE3MC_CHACHA20_HWACCL_AUTO;
    rc = crypto_stream_chacha20_pick_best_implementation();
  }

  /* Return current selected option */
  if (gChaCha20HwAccelSelected >= SQLITE3MC_CHACHA20_HWACCL_OFF &&
      gChaCha20HwAccelSelected <= SQLITE3MC_CHACHA20_HWACCL_AUTO)
    return gChaCha20HwAccelOptions[gChaCha20HwAccelSelected];
  else
    return NULL;
}

SODIUM_EXPORT int
crypto_stream_chacha20_pick_best_implementation(void)
{
#if defined(SQLITE3MC_TARGET_X86) || defined(SQLITE3MC_TARGET_WASM)
#if defined(SQLITE3MC_TARGET_X86)
  if (gChaCha20HwAccelRequest >= SQLITE3MC_CHACHA20_HWACCL_AVX512 &&
      sqlite3mcCpuFeatures() & SQLITE3MC_CPU_AVX512F)
  {
    sodium_chacha20_implementation = &crypto_stream_chacha20_dolbeau_avx512_implementation;
    gChaCha20HwAccelSelected = SQLITE3MC_CHACHA20_HWACCL_AVX512;
    return 0;
  }
  if (gChaCha20HwAccelRequest >= SQLITE3MC_CHACHA20_HWACCL_AVX2 &&
      sqlite3mcCpuFeatures() & SQLITE3MC_CPU_AVX2)
  {
    sodium_chacha20_implementation = &crypto_stream_chacha20_dolbeau_avx2_implementation;
    gChaCha20HwAccelSelected = SQLITE3MC_CHACHA20_HWACCL_AVX2;
    return 0;
  }
#endif
  if (gChaCha20HwAccelRequest >= SQLITE3MC_CHACHA20_HWACCL_SSSE3 &&
      sqlite3mcCpuFeatures() & SQLITE3MC_CPU_SSSE3)
  {
    sodium_chacha20_implementation = &crypto_stream_chacha20_dolbeau_ssse3_implementation;
    gChaCha20HwAccelSelected = SQLITE3MC_CHACHA20_HWACCL_SSSE3;
    return 0;
  }
#endif
#ifdef SQLITE3MC_TARGET_ARM
  if (gChaCha20HwAccelRequest >= SQLITE3MC_CHACHA20_HWACCL_NEON &&
      sqlite3mcCpuFeatures() & SQLITE3MC_CPU_NEON)
  {
    sodium_chacha20_implementation = &crypto_stream_chacha20_dolbeau_neon_implementation;
    gChaCha20HwAccelSelected = SQLITE3MC_CHACHA20_HWACCL_NEON;
    return 0;
  }
#endif
  /* Signal that no implementation with hardware support available */
  /* In that case we use our own ChaCha20 implementation. */
  sodium_chacha20_implementation = NULL;
  gChaCha20HwAccelSelected = SQLITE3MC_CHACHA20_HWACCL_OFF;
  return -1;
}
