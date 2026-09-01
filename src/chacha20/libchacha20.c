#define SODIUM_STATIC

static void
sodium_misuse()
{
  /*
  ** This function does intentionally nothing.
  ** It is called from sodium code, if the message length exceeds
  ** the allowed maximum.
  ** This never happens in the SQLite3MC context, because we are
  ** dealing at most with 64k pages.
  */
}

static void
randombytes_buf(void* const buf, const size_t size)
{
  /* We use our own random number generator */
  chacha20_rng(buf, size);
}

static void
sodium_memzero(void* const pnt, const size_t len)
{
  /* We use our own function to securely zero out memory */
  sqlite3mcSecureZeroMemory(pnt, len);
}

/*
** Context structure for Sodium's ChaCha20 implementation
** Definition moved here from the individual implementation files.
*/
typedef struct chacha_ctx {
  uint32_t input[16];
} chacha_ctx;

#include "src/stream_chacha20.c"

#undef SODIUM_STATIC
