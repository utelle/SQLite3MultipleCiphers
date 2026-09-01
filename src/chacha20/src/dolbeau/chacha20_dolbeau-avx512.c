
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../crypto_stream_chacha20.h"
#include "../private/common.h"

#if defined(SQLITE3MC_TARGET_X86)

# ifdef __clang__
#  if __clang_major__ >= 18 && __clang_major__ < 22
#   pragma clang attribute push(__attribute__((target("sse2,ssse3,sse4.1,avx2,avx512f,evex512"))), apply_to = function)
#  else
#   pragma clang attribute push(__attribute__((target("sse2,ssse3,sse4.1,avx2,avx512f"))), apply_to = function)
#  endif
# elif defined(__GNUC__)
#  pragma GCC target("sse2,ssse3,sse4.1,avx2,avx512f")
# endif

# include <emmintrin.h>
# include <immintrin.h>
# include <smmintrin.h>
# include <tmmintrin.h>
# include "../private/sse2_64_32.h"

# include "../stream_chacha20.h"
# include "chacha20_dolbeau-avx512.h"

#ifdef DOLBEAU_ROUNDS
#  undef DOLBEAU_ROUNDS
#  define DOLBEAU_ROUNDS 20
#else
#  define DOLBEAU_ROUNDS 20
#endif

#if 0
typedef struct chacha_ctx {
    uint32_t input[16];
} chacha_ctx;
#endif

static void
dolbeau_avx512_chacha_keysetup(chacha_ctx *ctx, const uint8_t *k)
{
    ctx->input[0]  = 0x61707865;
    ctx->input[1]  = 0x3320646e;
    ctx->input[2]  = 0x79622d32;
    ctx->input[3]  = 0x6b206574;
    ctx->input[4]  = SODIUM_LOAD32_LE(k + 0);
    ctx->input[5]  = SODIUM_LOAD32_LE(k + 4);
    ctx->input[6]  = SODIUM_LOAD32_LE(k + 8);
    ctx->input[7]  = SODIUM_LOAD32_LE(k + 12);
    ctx->input[8]  = SODIUM_LOAD32_LE(k + 16);
    ctx->input[9]  = SODIUM_LOAD32_LE(k + 20);
    ctx->input[10] = SODIUM_LOAD32_LE(k + 24);
    ctx->input[11] = SODIUM_LOAD32_LE(k + 28);
}

static void
dolbeau_avx512_chacha_ivsetup(chacha_ctx *ctx, const uint8_t *iv, const uint8_t *counter)
{
    ctx->input[12] = counter == NULL ? 0 : SODIUM_LOAD32_LE(counter + 0);
    ctx->input[13] = counter == NULL ? 0 : SODIUM_LOAD32_LE(counter + 4);
    ctx->input[14] = SODIUM_LOAD32_LE(iv + 0);
    ctx->input[15] = SODIUM_LOAD32_LE(iv + 4);
}

static void
dolbeau_avx512_chacha_ietf_ivsetup(chacha_ctx *ctx, const uint8_t *iv, const uint8_t *counter)
{
    ctx->input[12] = counter == NULL ? 0 : SODIUM_LOAD32_LE(counter);
    ctx->input[13] = SODIUM_LOAD32_LE(iv + 0);
    ctx->input[14] = SODIUM_LOAD32_LE(iv + 4);
    ctx->input[15] = SODIUM_LOAD32_LE(iv + 8);
}

static void
dolbeau_avx512_chacha20_encrypt_bytes(chacha_ctx *ctx, const uint8_t *m, uint8_t *c,
                       unsigned long long bytes)
{
    uint32_t * const x = &ctx->input[0];

    if (!bytes) {
        return; /* LCOV_EXCL_LINE */
    }
# include "u16.h"
# include "u8.h"
# include "u4.h"
# include "u1.h"
# include "u0.h"
}

static int
dolbeau_avx512_stream_ref(unsigned char *c, unsigned long long clen, const unsigned char *n,
           const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!clen) {
        return 0;
    }
    COMPILER_ASSERT(crypto_stream_chacha20_KEYBYTES == 256 / 8);
    dolbeau_avx512_chacha_keysetup(&ctx, k);
    dolbeau_avx512_chacha_ivsetup(&ctx, n, NULL);
    memset(c, 0, clen);
    dolbeau_avx512_chacha20_encrypt_bytes(&ctx, c, c, clen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
dolbeau_avx512_stream_ietf_ext_ref(unsigned char *c, unsigned long long clen,
                    const unsigned char *n, const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!clen) {
        return 0;
    }
    COMPILER_ASSERT(crypto_stream_chacha20_KEYBYTES == 256 / 8);
    dolbeau_avx512_chacha_keysetup(&ctx, k);
    dolbeau_avx512_chacha_ietf_ivsetup(&ctx, n, NULL);
    memset(c, 0, clen);
    dolbeau_avx512_chacha20_encrypt_bytes(&ctx, c, c, clen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
dolbeau_avx512_stream_ref_xor_ic(unsigned char *c, const unsigned char *m,
                  unsigned long long mlen, const unsigned char *n, uint64_t ic,
                  const unsigned char *k)
{
    struct chacha_ctx ctx;
    uint8_t           ic_bytes[8];
    uint32_t          ic_high;
    uint32_t          ic_low;

    if (!mlen) {
        return 0;
    }
    ic_high = (uint32_t) (ic >> 32);
    ic_low  = (uint32_t) ic;
    SODIUM_STORE32_LE(&ic_bytes[0], ic_low);
    SODIUM_STORE32_LE(&ic_bytes[4], ic_high);
    dolbeau_avx512_chacha_keysetup(&ctx, k);
    dolbeau_avx512_chacha_ivsetup(&ctx, n, ic_bytes);
    dolbeau_avx512_chacha20_encrypt_bytes(&ctx, m, c, mlen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
dolbeau_avx512_stream_ietf_ext_ref_xor_ic(unsigned char *c, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *n,
                           uint32_t ic, const unsigned char *k)
{
    struct chacha_ctx ctx;
    uint8_t           ic_bytes[4];

    if (!mlen) {
        return 0;
    }
    SODIUM_STORE32_LE(ic_bytes, ic);
    dolbeau_avx512_chacha_keysetup(&ctx, k);
    dolbeau_avx512_chacha_ietf_ivsetup(&ctx, n, ic_bytes);
    dolbeau_avx512_chacha20_encrypt_bytes(&ctx, m, c, mlen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

struct crypto_stream_chacha20_implementation
    crypto_stream_chacha20_dolbeau_avx512_implementation = {
        .stream                 = dolbeau_avx512_stream_ref,
        .stream_ietf_ext        = dolbeau_avx512_stream_ietf_ext_ref,
        .stream_xor_ic          = dolbeau_avx512_stream_ref_xor_ic,
        .stream_ietf_ext_xor_ic = dolbeau_avx512_stream_ietf_ext_ref_xor_ic
    };

# ifdef __clang__
#  pragma clang attribute pop
# endif

#endif
