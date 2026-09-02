
/*
 chacha-merged.c version 20080118
 D. J. Bernstein
 Public domain.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../crypto_stream_chacha20.h"
#include "../private/common.h"

#include "../stream_chacha20.h"
#include "chacha20_ref.h"

#if 0
struct chacha_ctx {
    uint32_t input[16];
};

typedef struct chacha_ctx chacha_ctx;
#endif

#define SODIUM_U32C(v) (v##U)

#define SODIUM_U32V(v) ((uint32_t)(v) &SODIUM_U32C(0xFFFFFFFF))

#define SODIUM_ROTATE(v, c) (SODIUM_ROTL32(v, c))
#define SODIUM_XOR(v, w) ((v) ^ (w))
#define SODIUM_PLUS(v, w) (SODIUM_U32V((v) + (w)))
#define SODIUM_PLUSONE(v) (SODIUM_PLUS((v), 1))

#define SODIUM_QUARTERROUND(a, b, c, d) \
    a = SODIUM_PLUS(a, b);              \
    d = SODIUM_ROTATE(SODIUM_XOR(d, a), 16);   \
    c = SODIUM_PLUS(c, d);              \
    b = SODIUM_ROTATE(SODIUM_XOR(b, c), 12);   \
    a = SODIUM_PLUS(a, b);              \
    d = SODIUM_ROTATE(SODIUM_XOR(d, a), 8);    \
    c = SODIUM_PLUS(c, d);              \
    b = SODIUM_ROTATE(SODIUM_XOR(b, c), 7);

static void
sodium_chacha_keysetup(chacha_ctx *ctx, const uint8_t *k)
{
    ctx->input[0]  = SODIUM_U32C(0x61707865);
    ctx->input[1]  = SODIUM_U32C(0x3320646e);
    ctx->input[2]  = SODIUM_U32C(0x79622d32);
    ctx->input[3]  = SODIUM_U32C(0x6b206574);
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
sodium_chacha_ivsetup(chacha_ctx *ctx, const uint8_t *iv, const uint8_t *counter)
{
    ctx->input[12] = counter == NULL ? 0 : SODIUM_LOAD32_LE(counter + 0);
    ctx->input[13] = counter == NULL ? 0 : SODIUM_LOAD32_LE(counter + 4);
    ctx->input[14] = SODIUM_LOAD32_LE(iv + 0);
    ctx->input[15] = SODIUM_LOAD32_LE(iv + 4);
}

static void
sodium_chacha_ietf_ivsetup(chacha_ctx *ctx, const uint8_t *iv, const uint8_t *counter)
{
    ctx->input[12] = counter == NULL ? 0 : SODIUM_LOAD32_LE(counter);
    ctx->input[13] = SODIUM_LOAD32_LE(iv + 0);
    ctx->input[14] = SODIUM_LOAD32_LE(iv + 4);
    ctx->input[15] = SODIUM_LOAD32_LE(iv + 8);
}

static void
sodium_chacha20_encrypt_bytes(chacha_ctx *ctx, const uint8_t *m, uint8_t *c,
                       unsigned long long bytes)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14,
        x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14,
        j15;
    uint8_t     *ctarget = NULL;
    uint8_t      tmp[64];
    unsigned int i;

    if (!bytes) {
        return; /* LCOV_EXCL_LINE */
    }
    j0  = ctx->input[0];
    j1  = ctx->input[1];
    j2  = ctx->input[2];
    j3  = ctx->input[3];
    j4  = ctx->input[4];
    j5  = ctx->input[5];
    j6  = ctx->input[6];
    j7  = ctx->input[7];
    j8  = ctx->input[8];
    j9  = ctx->input[9];
    j10 = ctx->input[10];
    j11 = ctx->input[11];
    j12 = ctx->input[12];
    j13 = ctx->input[13];
    j14 = ctx->input[14];
    j15 = ctx->input[15];

    for (;;) {
        if (bytes < 64) {
            memset(tmp, 0, 64);
            for (i = 0; i < bytes; ++i) {
                tmp[i] = m[i];
            }
            m       = tmp;
            ctarget = c;
            c       = tmp;
        }
        x0  = j0;
        x1  = j1;
        x2  = j2;
        x3  = j3;
        x4  = j4;
        x5  = j5;
        x6  = j6;
        x7  = j7;
        x8  = j8;
        x9  = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        for (i = 20; i > 0; i -= 2) {
            SODIUM_QUARTERROUND(x0, x4, x8, x12)
            SODIUM_QUARTERROUND(x1, x5, x9, x13)
            SODIUM_QUARTERROUND(x2, x6, x10, x14)
            SODIUM_QUARTERROUND(x3, x7, x11, x15)
            SODIUM_QUARTERROUND(x0, x5, x10, x15)
            SODIUM_QUARTERROUND(x1, x6, x11, x12)
            SODIUM_QUARTERROUND(x2, x7, x8, x13)
            SODIUM_QUARTERROUND(x3, x4, x9, x14)
        }
        x0  = SODIUM_PLUS(x0, j0);
        x1  = SODIUM_PLUS(x1, j1);
        x2  = SODIUM_PLUS(x2, j2);
        x3  = SODIUM_PLUS(x3, j3);
        x4  = SODIUM_PLUS(x4, j4);
        x5  = SODIUM_PLUS(x5, j5);
        x6  = SODIUM_PLUS(x6, j6);
        x7  = SODIUM_PLUS(x7, j7);
        x8  = SODIUM_PLUS(x8, j8);
        x9  = SODIUM_PLUS(x9, j9);
        x10 = SODIUM_PLUS(x10, j10);
        x11 = SODIUM_PLUS(x11, j11);
        x12 = SODIUM_PLUS(x12, j12);
        x13 = SODIUM_PLUS(x13, j13);
        x14 = SODIUM_PLUS(x14, j14);
        x15 = SODIUM_PLUS(x15, j15);

        x0  = SODIUM_XOR(x0, SODIUM_LOAD32_LE(m + 0));
        x1  = SODIUM_XOR(x1, SODIUM_LOAD32_LE(m + 4));
        x2  = SODIUM_XOR(x2, SODIUM_LOAD32_LE(m + 8));
        x3  = SODIUM_XOR(x3, SODIUM_LOAD32_LE(m + 12));
        x4  = SODIUM_XOR(x4, SODIUM_LOAD32_LE(m + 16));
        x5  = SODIUM_XOR(x5, SODIUM_LOAD32_LE(m + 20));
        x6  = SODIUM_XOR(x6, SODIUM_LOAD32_LE(m + 24));
        x7  = SODIUM_XOR(x7, SODIUM_LOAD32_LE(m + 28));
        x8  = SODIUM_XOR(x8, SODIUM_LOAD32_LE(m + 32));
        x9  = SODIUM_XOR(x9, SODIUM_LOAD32_LE(m + 36));
        x10 = SODIUM_XOR(x10, SODIUM_LOAD32_LE(m + 40));
        x11 = SODIUM_XOR(x11, SODIUM_LOAD32_LE(m + 44));
        x12 = SODIUM_XOR(x12, SODIUM_LOAD32_LE(m + 48));
        x13 = SODIUM_XOR(x13, SODIUM_LOAD32_LE(m + 52));
        x14 = SODIUM_XOR(x14, SODIUM_LOAD32_LE(m + 56));
        x15 = SODIUM_XOR(x15, SODIUM_LOAD32_LE(m + 60));

        j12 = SODIUM_PLUSONE(j12);
        /* LCOV_EXCL_START */
        if (!j12) {
            j13 = SODIUM_PLUSONE(j13);
        }
        /* LCOV_EXCL_STOP */

        SODIUM_STORE32_LE(c + 0, x0);
        SODIUM_STORE32_LE(c + 4, x1);
        SODIUM_STORE32_LE(c + 8, x2);
        SODIUM_STORE32_LE(c + 12, x3);
        SODIUM_STORE32_LE(c + 16, x4);
        SODIUM_STORE32_LE(c + 20, x5);
        SODIUM_STORE32_LE(c + 24, x6);
        SODIUM_STORE32_LE(c + 28, x7);
        SODIUM_STORE32_LE(c + 32, x8);
        SODIUM_STORE32_LE(c + 36, x9);
        SODIUM_STORE32_LE(c + 40, x10);
        SODIUM_STORE32_LE(c + 44, x11);
        SODIUM_STORE32_LE(c + 48, x12);
        SODIUM_STORE32_LE(c + 52, x13);
        SODIUM_STORE32_LE(c + 56, x14);
        SODIUM_STORE32_LE(c + 60, x15);

        if (bytes <= 64) {
            if (bytes < 64) {
                for (i = 0; i < (unsigned int) bytes; ++i) {
                    ctarget[i] = c[i]; /* ctarget cannot be NULL */
                }
            }
            ctx->input[12] = j12;
            ctx->input[13] = j13;

            return;
        }
        bytes -= 64;
        c += 64;
        m += 64;
    }
}

static int
sodium_stream_ref(unsigned char *c, unsigned long long clen, const unsigned char *n,
           const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!clen) {
        return 0;
    }
    COMPILER_ASSERT(crypto_stream_chacha20_KEYBYTES == 256 / 8);
    sodium_chacha_keysetup(&ctx, k);
    sodium_chacha_ivsetup(&ctx, n, NULL);
    memset(c, 0, clen);
    sodium_chacha20_encrypt_bytes(&ctx, c, c, clen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
sodium_stream_ietf_ext_ref(unsigned char *c, unsigned long long clen,
                           const unsigned char *n, const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!clen) {
        return 0;
    }
    COMPILER_ASSERT(crypto_stream_chacha20_KEYBYTES == 256 / 8);
    sodium_chacha_keysetup(&ctx, k);
    sodium_chacha_ietf_ivsetup(&ctx, n, NULL);
    memset(c, 0, clen);
    sodium_chacha20_encrypt_bytes(&ctx, c, c, clen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
sodium_stream_ref_xor_ic(unsigned char *c, const unsigned char *m,
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
    ic_high = SODIUM_U32V(ic >> 32);
    ic_low  = SODIUM_U32V(ic);
    SODIUM_STORE32_LE(&ic_bytes[0], ic_low);
    SODIUM_STORE32_LE(&ic_bytes[4], ic_high);
    sodium_chacha_keysetup(&ctx, k);
    sodium_chacha_ivsetup(&ctx, n, ic_bytes);
    sodium_chacha20_encrypt_bytes(&ctx, m, c, mlen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
sodium_stream_ietf_ext_ref_xor_ic(unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen, const unsigned char *n,
                                  uint32_t ic, const unsigned char *k)
{
    struct chacha_ctx ctx;
    uint8_t           ic_bytes[4];

    if (!mlen) {
        return 0;
    }
    SODIUM_STORE32_LE(ic_bytes, ic);
    sodium_chacha_keysetup(&ctx, k);
    sodium_chacha_ietf_ivsetup(&ctx, n, ic_bytes);
    sodium_chacha20_encrypt_bytes(&ctx, m, c, mlen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

struct crypto_stream_chacha20_implementation
    crypto_stream_chacha20_ref_implementation = {
        .stream = sodium_stream_ref,
        .stream_ietf_ext = sodium_stream_ietf_ext_ref,
        .stream_xor_ic = sodium_stream_ref_xor_ic,
        .stream_ietf_ext_xor_ic = sodium_stream_ietf_ext_ref_xor_ic
    };
