
#include "poly1305_donna.h"
#include "../private/common.h"

#if defined(HAVE_TI_MODE) || defined(SQLITE3MC_POLY1305_HAVE_128BIT)
#include "poly1305_donna64.h"
#else
#include "poly1305_donna32.h"
#endif
#include "../onetimeauth_poly1305.h"

static void
donna_poly1305_update(donna_poly1305_state_internal_t *st, const unsigned char *m,
                unsigned long long bytes)
{
    unsigned long long i;

    /* handle leftover */
    if (st->leftover) {
        unsigned long long want = (poly1305_block_size - st->leftover);

        if (want > bytes) {
            want = bytes;
        }
        for (i = 0; i < want; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_block_size) {
            return;
        }
        donna_poly1305_blocks(st, st->buffer, poly1305_block_size);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_block_size) {
        unsigned long long want = (bytes & ~(poly1305_block_size - 1));

        donna_poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        st->leftover += bytes;
    }
}

static int
crypto_onetimeauth_poly1305_donna(unsigned char *out, const unsigned char *m,
                                  unsigned long long   inlen,
                                  const unsigned char *key)
{
    CRYPTO_ALIGN(64) donna_poly1305_state_internal_t state;

    donna_poly1305_init(&state, key);
    donna_poly1305_update(&state, m, inlen);
    donna_poly1305_finish(&state, out);

    return 0;
}

static int
crypto_onetimeauth_poly1305_donna_init(crypto_onetimeauth_poly1305_state *state,
                                       const unsigned char *key)
{
    COMPILER_ASSERT(sizeof(crypto_onetimeauth_poly1305_state) >=
        sizeof(donna_poly1305_state_internal_t));
    donna_poly1305_init((donna_poly1305_state_internal_t *) (void *) state, key);

    return 0;
}

static int
crypto_onetimeauth_poly1305_donna_update(
    crypto_onetimeauth_poly1305_state *state, const unsigned char *in,
    unsigned long long inlen)
{
  donna_poly1305_update((donna_poly1305_state_internal_t *) (void *) state, in, inlen);

    return 0;
}

static int
crypto_onetimeauth_poly1305_donna_final(
    crypto_onetimeauth_poly1305_state *state, unsigned char *out)
{
  donna_poly1305_finish((donna_poly1305_state_internal_t *) (void *) state, out);

    return 0;
}

struct crypto_onetimeauth_poly1305_implementation
    crypto_onetimeauth_poly1305_donna_implementation = {
        .onetimeauth = crypto_onetimeauth_poly1305_donna,
        .onetimeauth_init = crypto_onetimeauth_poly1305_donna_init,
        .onetimeauth_update =
            crypto_onetimeauth_poly1305_donna_update,
        .onetimeauth_final = crypto_onetimeauth_poly1305_donna_final
    };

#undef poly1305_block_size
