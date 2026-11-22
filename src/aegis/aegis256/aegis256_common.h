/*
** Name:        aegis256_common.h
** Purpose:     Common implementation for AEGIS-256
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

#ifndef AEGIS_ENCRYPT_BULK
#    define AEGIS_ENCRYPT_BULK(dst, src, len, state)    0
#    define AEGIS_DECRYPT_BULK(dst, src, len, state)    0
#    define AEGIS_ABSORB_BULK(dst, src, len, state)     0
#    define AEGIS_STREAM_BULK(dst, src, len, state)     0
#    define AEGIS_STREAM_XOR_BULK(dst, src, len, state) 0
#endif

#define AEGIS_RATE      16
#define AEGIS_ALIGNMENT 16

#ifndef AEGIS_AES_BLOCK_ENC_BARRIER
#    define AEGIS_AES_BLOCK_ENC_BARRIER() (void) 0
#endif

typedef AEGIS_AES_BLOCK_T AEGIS_BLOCKS[6];

#define AEGIS_init               AEGIS_FUNC(init)
#define AEGIS_mac_finalize       AEGIS_FUNC(mac_finalize)
#define AEGIS_mac_tag            AEGIS_FUNC(mac_tag)
#define AEGIS_mac                AEGIS_FUNC(mac)
#define AEGIS_absorb_rate        AEGIS_FUNC(absorb_rate)
#define AEGIS_absorb             AEGIS_FUNC(absorb)
#define AEGIS_squeeze_keystream  AEGIS_FUNC(squeeze_keystream)
#define AEGIS_xor_keystream      AEGIS_FUNC(xor_keystream)
#define AEGIS_enc                AEGIS_FUNC(enc)
#define AEGIS_dec                AEGIS_FUNC(dec)
#define AEGIS_declast            AEGIS_FUNC(declast)

static inline void
AEGIS_init(const uint8_t *key, const uint8_t *nonce, AEGIS_AES_BLOCK_T *const state)
{
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH)
        const uint8_t c0_[AES_BLOCK_LENGTH] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
                                                0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 };
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH)
        const uint8_t c1_[AES_BLOCK_LENGTH] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
                                                0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };

    const AEGIS_AES_BLOCK_T c0    = AEGIS_AES_BLOCK_LOAD(c0_);
    const AEGIS_AES_BLOCK_T c1    = AEGIS_AES_BLOCK_LOAD(c1_);
    const AEGIS_AES_BLOCK_T k0    = AEGIS_AES_BLOCK_LOAD(key);
    const AEGIS_AES_BLOCK_T k1    = AEGIS_AES_BLOCK_LOAD(key + AES_BLOCK_LENGTH);
    const AEGIS_AES_BLOCK_T n0    = AEGIS_AES_BLOCK_LOAD(nonce);
    const AEGIS_AES_BLOCK_T n1    = AEGIS_AES_BLOCK_LOAD(nonce + AES_BLOCK_LENGTH);
    const AEGIS_AES_BLOCK_T k0_n0 = AEGIS_AES_BLOCK_XOR(k0, n0);
    const AEGIS_AES_BLOCK_T k1_n1 = AEGIS_AES_BLOCK_XOR(k1, n1);
    int               i;

    state[0] = k0_n0;
    state[1] = k1_n1;
    state[2] = c1;
    state[3] = c0;
    state[4] = AEGIS_AES_BLOCK_XOR(k0, c0);
    state[5] = AEGIS_AES_BLOCK_XOR(k1, c1);
    for (i = 0; i < 4; i++) {
        AEGIS_update(state, k0);
        AEGIS_update(state, k1);
        AEGIS_update(state, k0_n0);
        AEGIS_update(state, k1_n1);
    }
}

static inline void
AEGIS_mac_finalize(uint64_t adlen, uint64_t mlen, AEGIS_AES_BLOCK_T *const state)
{
    AEGIS_AES_BLOCK_T tmp;
    int         i;

    tmp = AEGIS_AES_BLOCK_LOAD_64x2(mlen << 3, adlen << 3);
    tmp = AEGIS_AES_BLOCK_XOR(tmp, state[3]);

    for (i = 0; i < 7; i++) {
        AEGIS_update(state, tmp);
    }
}

static inline void
AEGIS_mac_tag(uint8_t *mac, size_t maclen, const AEGIS_AES_BLOCK_T *state)
{
    AEGIS_AES_BLOCK_T tmp;

    if (maclen == 16) {
        tmp = AEGIS_AES_BLOCK_XOR(state[5], state[4]);
        tmp = AEGIS_AES_BLOCK_XOR(tmp, AEGIS_AES_BLOCK_XOR(state[3], state[2]));
        tmp = AEGIS_AES_BLOCK_XOR(tmp, AEGIS_AES_BLOCK_XOR(state[1], state[0]));
        AEGIS_AES_BLOCK_STORE(mac, tmp);
    } else if (maclen == 32) {
        tmp = AEGIS_AES_BLOCK_XOR(AEGIS_AES_BLOCK_XOR(state[2], state[1]), state[0]);
        AEGIS_AES_BLOCK_STORE(mac, tmp);
        tmp = AEGIS_AES_BLOCK_XOR(AEGIS_AES_BLOCK_XOR(state[5], state[4]), state[3]);
        AEGIS_AES_BLOCK_STORE(mac + 16, tmp);
    } else {
        memset(mac, 0, maclen);
    }
}

static inline void
AEGIS_mac(uint8_t *mac, size_t maclen, uint64_t adlen, uint64_t mlen, AEGIS_AES_BLOCK_T *const state)
{
    AEGIS_mac_finalize(adlen, mlen, state);
    AEGIS_mac_tag(mac, maclen, state);
}

static inline void
AEGIS_absorb(const uint8_t *const src, AEGIS_AES_BLOCK_T *const state)
{
    AEGIS_AES_BLOCK_T msg;

    msg = AEGIS_AES_BLOCK_LOAD(src);
    AEGIS_update(state, msg);
}

static inline void
AEGIS_absorb_rate(const uint8_t *const src, AEGIS_AES_BLOCK_T *const state)
{
    AEGIS_AES_BLOCK_T msg;

    msg = AEGIS_AES_BLOCK_LOAD(src);
    AEGIS_update(state, msg);
}

static inline void
AEGIS_squeeze_keystream(uint8_t *const dst, AEGIS_AES_BLOCK_T *const state)
{
    AEGIS_AES_BLOCK_T tmp;

    tmp = AEGIS_AES_BLOCK_XOR(state[5], state[4]);
    tmp = AEGIS_AES_BLOCK_XOR(tmp, state[1]);
    tmp = AEGIS_AES_BLOCK_XOR(tmp, AEGIS_AES_BLOCK_AND(state[2], state[3]));
    AEGIS_AES_BLOCK_STORE(dst, tmp);
}

static inline void
AEGIS_enc(uint8_t *const dst, const uint8_t *const src, AEGIS_AES_BLOCK_T *const state)
{
    AEGIS_AES_BLOCK_T msg;
    AEGIS_AES_BLOCK_T tmp;

    msg = AEGIS_AES_BLOCK_LOAD(src);
    tmp = AEGIS_AES_BLOCK_XOR(msg, state[5]);
    tmp = AEGIS_AES_BLOCK_XOR(tmp, state[4]);
    tmp = AEGIS_AES_BLOCK_XOR(tmp, state[1]);
    tmp = AEGIS_AES_BLOCK_XOR(tmp, AEGIS_AES_BLOCK_AND(state[2], state[3]));
    AEGIS_AES_BLOCK_STORE(dst, tmp);
    AEGIS_AES_BLOCK_ENC_BARRIER();

    AEGIS_update(state, msg);
}

static inline void
AEGIS_xor_keystream(uint8_t *const dst, const uint8_t *const src, AEGIS_AES_BLOCK_T *const state)
{
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH) const uint8_t zero_[AES_BLOCK_LENGTH] = { 0 };

    const AEGIS_AES_BLOCK_T zero = AEGIS_AES_BLOCK_LOAD(zero_);
    AEGIS_AES_BLOCK_T       msg;
    AEGIS_AES_BLOCK_T       tmp;

    msg = AEGIS_AES_BLOCK_LOAD(src);
    tmp = AEGIS_AES_BLOCK_XOR(msg, state[5]);
    tmp = AEGIS_AES_BLOCK_XOR(tmp, state[4]);
    tmp = AEGIS_AES_BLOCK_XOR(tmp, state[1]);
    tmp = AEGIS_AES_BLOCK_XOR(tmp, AEGIS_AES_BLOCK_AND(state[2], state[3]));
    AEGIS_AES_BLOCK_STORE(dst, tmp);
    AEGIS_AES_BLOCK_ENC_BARRIER();

    /* Don't absorb the input, so that the keystream stays the same as the one from AEGIS_stream(). */
    AEGIS_update(state, zero);
}

static inline void
AEGIS_dec(uint8_t *const dst, const uint8_t *const src, AEGIS_AES_BLOCK_T *const state)
{
    AEGIS_AES_BLOCK_T msg;

    msg = AEGIS_AES_BLOCK_LOAD(src);
    msg = AEGIS_AES_BLOCK_XOR(msg, state[5]);
    msg = AEGIS_AES_BLOCK_XOR(msg, state[4]);
    msg = AEGIS_AES_BLOCK_XOR(msg, state[1]);
    msg = AEGIS_AES_BLOCK_XOR(msg, AEGIS_AES_BLOCK_AND(state[2], state[3]));
    AEGIS_AES_BLOCK_STORE(dst, msg);

    AEGIS_update(state, msg);
}

static inline void
AEGIS_declast(uint8_t *const dst, const uint8_t *const src, size_t len, AEGIS_AES_BLOCK_T *const state)
{
    uint8_t     pad[AEGIS_RATE];
    AEGIS_AES_BLOCK_T msg;

    memset(pad, 0, sizeof pad);
    memcpy(pad, src, len);

    msg = AEGIS_AES_BLOCK_LOAD(pad);
    msg = AEGIS_AES_BLOCK_XOR(msg, state[5]);
    msg = AEGIS_AES_BLOCK_XOR(msg, state[4]);
    msg = AEGIS_AES_BLOCK_XOR(msg, state[1]);
    msg = AEGIS_AES_BLOCK_XOR(msg, AEGIS_AES_BLOCK_AND(state[2], state[3]));
    AEGIS_AES_BLOCK_STORE(pad, msg);

    memset(pad + len, 0, sizeof pad - len);
    memcpy(dst, pad, len);

    msg = AEGIS_AES_BLOCK_LOAD(pad);

    AEGIS_update(state, msg);
}

static int
AEGIS_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                 const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    AEGIS_BLOCKS                    state;
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t src[AEGIS_RATE];
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t dst[AEGIS_RATE];
    size_t                          i;

    AEGIS_init(k, npub, state);

    for (i = AEGIS_ABSORB_BULK(NULL, ad, adlen, state); i + AEGIS_RATE <= adlen; i += AEGIS_RATE) {
        AEGIS_absorb(ad + i, state);
    }
    if (adlen % AEGIS_RATE) {
        memset(src, 0, AEGIS_RATE);
        memcpy(src, ad + i, adlen % AEGIS_RATE);
        AEGIS_absorb(src, state);
    }
    for (i = AEGIS_ENCRYPT_BULK(c, m, mlen, state); i + AEGIS_RATE <= mlen; i += AEGIS_RATE) {
        AEGIS_enc(c + i, m + i, state);
    }
    if (mlen % AEGIS_RATE) {
        memset(src, 0, AEGIS_RATE);
        memcpy(src, m + i, mlen % AEGIS_RATE);
        AEGIS_enc(dst, src, state);
        memcpy(c + i, dst, mlen % AEGIS_RATE);
    }

    AEGIS_mac(mac, maclen, adlen, mlen, state);

    return 0;
}

static int
AEGIS_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac, size_t maclen,
                 const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    AEGIS_BLOCKS                    state;
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t src[AEGIS_RATE];
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t dst[AEGIS_RATE];
    CRYPTO_ALIGN(16) uint8_t        computed_mac[32];
    const size_t                    mlen = clen;
    size_t                          i;
    int                             ret;

    AEGIS_init(k, npub, state);

    for (i = AEGIS_ABSORB_BULK(NULL, ad, adlen, state); i + AEGIS_RATE <= adlen; i += AEGIS_RATE) {
        AEGIS_absorb(ad + i, state);
    }
    if (adlen % AEGIS_RATE) {
        memset(src, 0, AEGIS_RATE);
        memcpy(src, ad + i, adlen % AEGIS_RATE);
        AEGIS_absorb(src, state);
    }
    if (m != NULL) {
        for (i = AEGIS_DECRYPT_BULK(m, c, mlen, state); i + AEGIS_RATE <= mlen; i += AEGIS_RATE) {
            AEGIS_dec(m + i, c + i, state);
        }
    } else {
        for (i = 0; i + AEGIS_RATE <= mlen; i += AEGIS_RATE) {
            AEGIS_dec(dst, c + i, state);
        }
    }
    if (mlen % AEGIS_RATE) {
        if (m != NULL) {
            AEGIS_declast(m + i, c + i, mlen % AEGIS_RATE, state);
        } else {
            AEGIS_declast(dst, c + i, mlen % AEGIS_RATE, state);
        }
    }

    COMPILER_ASSERT(sizeof computed_mac >= 32);
    AEGIS_mac(computed_mac, maclen, adlen, mlen, state);
    ret = -1;
    if (maclen == 16) {
        ret = aegis_verify_16(computed_mac, mac);
    } else if (maclen == 32) {
        ret = aegis_verify_32(computed_mac, mac);
    }
    if (ret != 0 && m != NULL) {
        memset(m, 0, mlen);
    }
    return ret;
}

static void
AEGIS_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k)
{
    AEGIS_BLOCKS                    state;
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t src[AEGIS_RATE];
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t dst[AEGIS_RATE];
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t zero_nonce[aegis256_NPUBBYTES];
    size_t                          i;

    memset(src, 0, sizeof src);
    if (npub == NULL) {
        memset(zero_nonce, 0, sizeof zero_nonce);
        npub = zero_nonce;
    }

    AEGIS_init(k, npub, state);

    for (i = AEGIS_STREAM_BULK(out, src, len, state); i + AEGIS_RATE <= len; i += AEGIS_RATE) {
        AEGIS_enc(out + i, src, state);
    }
    if (len % AEGIS_RATE) {
        AEGIS_enc(dst, src, state);
        memcpy(out + i, dst, len % AEGIS_RATE);
    }
}

static void
AEGIS_stream_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t *npub, const uint8_t *k)
{
    AEGIS_BLOCKS                    state;
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t src[AEGIS_RATE];
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t dst[AEGIS_RATE];
    size_t                          i;

    AEGIS_init(k, npub, state);

    for (i = AEGIS_STREAM_XOR_BULK(out, in, len, state); i + AEGIS_RATE <= len; i += AEGIS_RATE) {
        AEGIS_xor_keystream(out + i, in + i, state);
    }
    if (len % AEGIS_RATE) {
        memset(src, 0, AEGIS_RATE);
        memcpy(src, in + i, len % AEGIS_RATE);
        AEGIS_xor_keystream(dst, src, state);
        memcpy(out + i, dst, len % AEGIS_RATE);
    }
}

static void
AEGIS_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen, const uint8_t *npub,
                        const uint8_t *k)
{
    AEGIS_BLOCKS                    state;
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t src[AEGIS_RATE];
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t dst[AEGIS_RATE];
    size_t                          i;

    AEGIS_init(k, npub, state);

    for (i = AEGIS_ENCRYPT_BULK(c, m, mlen, state); i + AEGIS_RATE <= mlen; i += AEGIS_RATE) {
        AEGIS_enc(c + i, m + i, state);
    }
    if (mlen % AEGIS_RATE) {
        memset(src, 0, AEGIS_RATE);
        memcpy(src, m + i, mlen % AEGIS_RATE);
        AEGIS_enc(dst, src, state);
        memcpy(c + i, dst, mlen % AEGIS_RATE);
    }
}

static void
AEGIS_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *npub,
                        const uint8_t *k)
{
    AEGIS_BLOCKS state;
    const size_t mlen = clen;
    size_t       i;

    AEGIS_init(k, npub, state);

    for (i = AEGIS_DECRYPT_BULK(m, c, mlen, state); i + AEGIS_RATE <= mlen; i += AEGIS_RATE) {
        AEGIS_dec(m + i, c + i, state);
    }
    if (mlen % AEGIS_RATE) {
        AEGIS_declast(m + i, c + i, mlen % AEGIS_RATE, state);
    }
}

typedef struct AEGIS_STATE {
    AEGIS_BLOCKS blocks;
    uint8_t      buf[AEGIS_RATE];
    uint64_t     adlen;
    uint64_t     mlen;
    size_t       pos;
} AEGIS_STATE;

typedef struct AEGIS_MAC_STATE {
    AEGIS_BLOCKS blocks;
    AEGIS_BLOCKS blocks0;
    uint8_t      buf[AEGIS_RATE];
    uint64_t     adlen;
    size_t       pos;
} AEGIS_MAC_STATE;

#ifndef AEGIS_OMIT_INCREMENTAL

static void
AEGIS_state_init(aegis256_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
           const uint8_t *k)
{
    AEGIS_BLOCKS           blocks;
    AEGIS_STATE *const st =
        (AEGIS_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                             ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    size_t i;

    COMPILER_ASSERT((sizeof *st) + AEGIS_ALIGNMENT <= sizeof *st_);
    st->mlen = 0;
    st->pos  = 0;

    AEGIS_init(k, npub, blocks);
    for (i = AEGIS_ABSORB_BULK(NULL, ad, adlen, blocks); i + AEGIS_RATE <= adlen; i += AEGIS_RATE) {
        AEGIS_absorb(ad + i, blocks);
    }
    if (adlen % AEGIS_RATE) {
        memset(st->buf, 0, AEGIS_RATE);
        memcpy(st->buf, ad + i, adlen % AEGIS_RATE);
        AEGIS_absorb(st->buf, blocks);
    }
    st->adlen = adlen;

    memset(st->buf, 0, sizeof st->buf);

    memcpy(st->blocks, blocks, sizeof blocks);
}

static int
AEGIS_state_encrypt_update(aegis256_state *st_, uint8_t *c, const uint8_t *m, size_t mlen)
{
    AEGIS_BLOCKS           blocks;
    AEGIS_STATE *const st =
        (AEGIS_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                             ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    size_t i = 0;
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    st->mlen += mlen;

    // Handle leftover keystream from previous call
    if (st->pos != 0) {
        const size_t available = AEGIS_RATE - st->pos;
        const size_t n         = mlen < available ? mlen : available;
        size_t       j;
        uint8_t      tmp;

        for (j = 0; j < n; j++) {
            tmp                  = m[j];
            c[j]                 = m[j] ^ st->buf[st->pos + j];
            st->buf[st->pos + j] = tmp;
        }
        st->pos += n;
        m += n;
        c += n;
        mlen -= n;

        if (st->pos < AEGIS_RATE) {
            // Still consuming keystream from previous call
            memcpy(st->blocks, blocks, sizeof blocks);
            return 0;
        }

        // Full block accumulated, update state
        AEGIS_absorb_rate(st->buf, blocks);
        st->pos = 0;
    }

    for (i = AEGIS_ENCRYPT_BULK(c, m, mlen, blocks); i + AEGIS_RATE <= mlen; i += AEGIS_RATE) {
        AEGIS_enc(c + i, m + i, blocks);
    }

    left = mlen - i;
    if (left != 0) {
        size_t  j;
        uint8_t tmp;

        // Generate keystream without updating state
        AEGIS_squeeze_keystream(st->buf, blocks);

        for (j = 0; j < left; j++) {
            tmp        = m[i + j];
            c[i + j]   = m[i + j] ^ st->buf[j];
            st->buf[j] = tmp;
        }
        st->pos = left;
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
AEGIS_state_encrypt_final(aegis256_state *st_, uint8_t *mac, size_t maclen)
{
    AEGIS_BLOCKS           blocks;
    AEGIS_STATE *const st =
        (AEGIS_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                             ~(uintptr_t) (AEGIS_ALIGNMENT - 1));

    memcpy(blocks, st->blocks, sizeof blocks);

    // Ciphertext was already output during _update; absorb cached plaintext into state
    if (st->pos != 0) {
        CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t tmp[AEGIS_RATE];
        memset(tmp, 0, sizeof tmp);
        memcpy(tmp, st->buf, st->pos);
        AEGIS_absorb_rate(tmp, blocks);
    }

    AEGIS_mac(mac, maclen, st->adlen, st->mlen, blocks);

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
AEGIS_state_decrypt_update(aegis256_state *st_, uint8_t *m, const uint8_t *c, size_t clen)
{
    AEGIS_BLOCKS           blocks;
    AEGIS_STATE *const st =
        (AEGIS_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                             ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    size_t i = 0;
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    st->mlen += clen;

    // Handle leftover keystream from previous call
    if (st->pos != 0) {
        const size_t available = AEGIS_RATE - st->pos;
        const size_t n         = clen < available ? clen : available;
        size_t       j;

        for (j = 0; j < n; j++) {
            if (m != NULL) {
                m[j]                 = c[j] ^ st->buf[st->pos + j];
                st->buf[st->pos + j] = m[j];
            } else {
                uint8_t plaintext    = c[j] ^ st->buf[st->pos + j];
                st->buf[st->pos + j] = plaintext;
            }
        }
        st->pos += n;
        if (m != NULL) {
            m += n;
        }
        c += n;
        clen -= n;

        if (st->pos < AEGIS_RATE) {
            // Still consuming keystream
            memcpy(st->blocks, blocks, sizeof blocks);
            return 0;
        }

        // Full block accumulated, update state
        AEGIS_absorb_rate(st->buf, blocks);
        st->pos = 0;
    }

    if (m != NULL) {
        for (i = AEGIS_DECRYPT_BULK(m, c, clen, blocks); i + AEGIS_RATE <= clen; i += AEGIS_RATE) {
            AEGIS_dec(m + i, c + i, blocks);
        }
    } else {
        CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t dst[AEGIS_RATE];
        for (i = 0; i + AEGIS_RATE <= clen; i += AEGIS_RATE) {
            AEGIS_dec(dst, c + i, blocks);
        }
    }

    left = clen - i;
    if (left != 0) {
        size_t j;

        // Generate keystream without updating state
        AEGIS_squeeze_keystream(st->buf, blocks);

        for (j = 0; j < left; j++) {
            if (m != NULL) {
                m[i + j]   = c[i + j] ^ st->buf[j];
                st->buf[j] = m[i + j];
            } else {
                uint8_t plaintext = c[i + j] ^ st->buf[j];
                st->buf[j]        = plaintext;
            }
        }
        st->pos = left;
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
AEGIS_state_decrypt_final(aegis256_state *st_, const uint8_t *mac, size_t maclen)
{
    AEGIS_BLOCKS             blocks;
    CRYPTO_ALIGN(16) uint8_t computed_mac[32];
    AEGIS_STATE *const   st =
        (AEGIS_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                             ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    int ret;

    memcpy(blocks, st->blocks, sizeof blocks);

    // Plaintext was already output during _update; absorb cached plaintext into state
    if (st->pos != 0) {
        CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t tmp[AEGIS_RATE];
        memset(tmp, 0, sizeof tmp);
        memcpy(tmp, st->buf, st->pos);
        AEGIS_absorb_rate(tmp, blocks);
    }

    AEGIS_mac(computed_mac, maclen, st->adlen, st->mlen, blocks);
    ret = -1;
    if (maclen == 16) {
        ret = aegis_verify_16(computed_mac, mac);
    } else if (maclen == 32) {
        ret = aegis_verify_32(computed_mac, mac);
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return ret;
}

#endif /* AEGIS_OMIT_INCREMENTAL */

#ifndef AEGIS_OMIT_MAC_API

static void
AEGIS_state_mac_init(aegis256_mac_state *st_, const uint8_t *npub, const uint8_t *k)
{
    AEGIS_BLOCKS                    blocks;
    CRYPTO_ALIGN(AEGIS_ALIGNMENT) uint8_t zero_nonce[32];
    AEGIS_MAC_STATE *const      st =
        (AEGIS_MAC_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                                  ~(uintptr_t) (AEGIS_ALIGNMENT - 1));

    COMPILER_ASSERT((sizeof *st) + AEGIS_ALIGNMENT <= sizeof *st_);
    st->pos = 0;

    memcpy(blocks, st->blocks, sizeof blocks);

    if (npub == NULL) {
        memset(zero_nonce, 0, sizeof zero_nonce);
        npub = zero_nonce;
    }

    AEGIS_init(k, npub, blocks);

    memcpy(st->blocks0, blocks, sizeof blocks);
    memcpy(st->blocks, blocks, sizeof blocks);
    st->adlen = 0;
}

static int
AEGIS_state_mac_update(aegis256_mac_state *st_, const uint8_t *ad, size_t adlen)
{
    AEGIS_BLOCKS           blocks;
    AEGIS_MAC_STATE *const st =
        (AEGIS_MAC_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                             ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    size_t i;
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    left = st->adlen % AEGIS_RATE;
    st->adlen += adlen;
    if (left != 0) {
        if (left + adlen < AEGIS_RATE) {
            memcpy(st->buf + left, ad, adlen);
            return 0;
        }
        memcpy(st->buf + left, ad, AEGIS_RATE - left);
        AEGIS_absorb(st->buf, blocks);
        ad += AEGIS_RATE - left;
        adlen -= AEGIS_RATE - left;
    }
    for (i = AEGIS_ABSORB_BULK(NULL, ad, adlen, blocks); i + AEGIS_RATE * 2 <= adlen; i += AEGIS_RATE * 2) {
        AEGIS_AES_BLOCK_T msg0, msg1;

        msg0 = AEGIS_AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 0);
        msg1 = AEGIS_AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 1);
        COMPILER_ASSERT(AES_BLOCK_LENGTH * 2 == AEGIS_RATE * 2);

        AEGIS_update(blocks, msg0);
        AEGIS_update(blocks, msg1);
    }
    for (; i + AEGIS_RATE <= adlen; i += AEGIS_RATE) {
        AEGIS_absorb(ad + i, blocks);
    }
    if (i < adlen) {
        memset(st->buf, 0, AEGIS_RATE);
        memcpy(st->buf, ad + i, adlen - i);
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
AEGIS_state_mac_final(aegis256_mac_state *st_, uint8_t *mac, size_t maclen)
{
    AEGIS_BLOCKS           blocks;
    AEGIS_MAC_STATE *const st =
        (AEGIS_MAC_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                             ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    left = st->adlen % AEGIS_RATE;
    if (left != 0) {
        memset(st->buf + left, 0, AEGIS_RATE - left);
        AEGIS_absorb(st->buf, blocks);
    }
    AEGIS_mac(mac, maclen, st->adlen, maclen, blocks);

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
AEGIS_state_mac_verify(aegis256_mac_state *st_, const uint8_t *mac, size_t maclen)
{
    uint8_t                    expected_mac[32];
    AEGIS_BLOCKS               blocks;
    AEGIS_MAC_STATE *const st =
        (AEGIS_MAC_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                                 ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    left = st->adlen % AEGIS_RATE;
    if (left != 0) {
        memset(st->buf + left, 0, AEGIS_RATE - left);
        AEGIS_absorb(st->buf, blocks);
    }
    AEGIS_mac_finalize(st->adlen, maclen, blocks);

    memcpy(st->blocks, blocks, sizeof blocks);

    if (maclen == 16) {
        AEGIS_mac_tag(expected_mac, 16, blocks);
        return aegis_tag_compare(expected_mac, mac, 16);
    }
    AEGIS_mac_tag(expected_mac, 32, blocks);
    return aegis_tag_compare(expected_mac, mac, 32);
}

static void
AEGIS_state_mac_reset(aegis256_mac_state *st_)
{
    AEGIS_MAC_STATE *const st =
        (AEGIS_MAC_STATE *) ((((uintptr_t) &st_->opaque) + (AEGIS_ALIGNMENT - 1)) &
                                  ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    st->adlen = 0;
    st->pos   = 0;
    memcpy(st->blocks, st->blocks0, sizeof(AEGIS_BLOCKS));
}

static void
AEGIS_state_mac_clone(aegis256_mac_state *dst, const aegis256_mac_state *src)
{
    AEGIS_MAC_STATE *const dst_ =
        (AEGIS_MAC_STATE *) ((((uintptr_t) &dst->opaque) + (AEGIS_ALIGNMENT - 1)) &
                             ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    const AEGIS_MAC_STATE *const src_ =
        (const AEGIS_MAC_STATE *) ((((uintptr_t) &src->opaque) + (AEGIS_ALIGNMENT - 1)) &
                                   ~(uintptr_t) (AEGIS_ALIGNMENT - 1));
    *dst_ = *src_;
}

#endif /* AEGIS_OMIT_MAC_API */

#undef AEGIS_RATE
#undef AEGIS_ALIGNMENT

#undef AEGIS_init
#undef AEGIS_mac_finalize
#undef AEGIS_mac_tag
#undef AEGIS_mac
#undef AEGIS_absorb_rate
#undef AEGIS_absorb
#undef AEGIS_squeeze_keystream
#undef AEGIS_xor_keystream
#undef AEGIS_enc
#undef AEGIS_dec
#undef AEGIS_declast

#undef AEGIS_ENCRYPT_BULK
#undef AEGIS_DECRYPT_BULK
#undef AEGIS_ABSORB_BULK
#undef AEGIS_STREAM_BULK
#undef AEGIS_STREAM_XOR_BULK
