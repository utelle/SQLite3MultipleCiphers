/*
** Name:        softaes.h
** Purpose:     Header for API of AES software implementation
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

#ifndef AEGIS_SOFTAES_H
#define AEGIS_SOFTAES_H

#include <stdint.h>

#include "common.h"

/* Use constant-time SIMD AES rounds on WebAssembly. */
#if defined(__wasm_simd128__) && !defined(AEGIS_NO_VECTOR_SBOX)
#    define SOFTAES_SIMD128 1
#endif

#ifdef SOFTAES_SIMD128

#    include <wasm_simd128.h>

typedef v128_t SoftAesBlock;

static inline SoftAesBlock
softaes_block_load(const uint8_t in[16])
{
    return wasm_v128_load(in);
}

static inline SoftAesBlock
softaes_block_load64x2(const uint64_t a, const uint64_t b)
{
    return wasm_u64x2_make(b, a);
}

static inline void
softaes_block_store(uint8_t out[16], const SoftAesBlock in)
{
    wasm_v128_store(out, in);
}

static inline SoftAesBlock
softaes_block_xor(const SoftAesBlock a, const SoftAesBlock b)
{
    return wasm_v128_xor(a, b);
}

static inline SoftAesBlock
softaes_block_and(const SoftAesBlock a, const SoftAesBlock b)
{
    return wasm_v128_and(a, b);
}

/* Relaxed swizzles are safe because these indices behave identically. */
#    if defined(__wasm_relaxed_simd__)
#        define SOFTAES_SWIZZLE(T, I) wasm_i8x16_relaxed_swizzle((T), (I))
#    else
#        define SOFTAES_SWIZZLE(T, I) wasm_i8x16_swizzle((T), (I))
#    endif

#    define SOFTAES_XOR3(A, B, C) wasm_v128_xor(wasm_v128_xor((A), (B)), (C))

enum {
    SOFTAES_TBL_IPT_LO,
    SOFTAES_TBL_IPT_HI,
    SOFTAES_TBL_INV,
    SOFTAES_TBL_INVA,
    SOFTAES_TBL_SBO_U,
    SOFTAES_TBL_SBO_T,
    SOFTAES_TBL_SBO2_U,
    SOFTAES_TBL_SBO2_T,
    SOFTAES_TBL_MC0,
    SOFTAES_TBL_MC1,
    SOFTAES_TBL_MC2,
    SOFTAES_TBL_MC3,
    SOFTAES_TBL_S0F,
    SOFTAES_TBL_C63,
    SOFTAES_TBL_COUNT
};

extern uint8_t libaegis_softaes_simd_tables[SOFTAES_TBL_COUNT][16];

/* Keep 0x63 outside the tables so out-of-range swizzles cannot skip it. */
static inline v128_t
softaes_block_aesl_nc(const v128_t x)
{
    const v128_t ipt_lo = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_IPT_LO]);
    const v128_t ipt_hi = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_IPT_HI]);
    const v128_t inv    = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_INV]);
    const v128_t inva   = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_INVA]);
    const v128_t sbo_u  = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_SBO_U]);
    const v128_t sbo_t  = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_SBO_T]);
    const v128_t sbo2_u = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_SBO2_U]);
    const v128_t sbo2_t = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_SBO2_T]);
    const v128_t mc0    = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_MC0]);
    const v128_t mc1    = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_MC1]);
    const v128_t mc2    = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_MC2]);
    const v128_t mc3    = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_MC3]);
    const v128_t s0f    = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_S0F]);

    /* Keep byte lanes independent without slower byte-shift masks. */
    const v128_t lo = wasm_v128_and(x, s0f);
    const v128_t hi = wasm_v128_and(wasm_u16x8_shr(x, 4), s0f);
    const v128_t t  = wasm_v128_xor(SOFTAES_SWIZZLE(ipt_lo, lo), SOFTAES_SWIZZLE(ipt_hi, hi));

    const v128_t k   = wasm_v128_and(t, s0f);
    const v128_t i   = wasm_v128_and(wasm_u16x8_shr(t, 4), s0f);
    const v128_t j   = wasm_v128_xor(k, i);
    const v128_t ak  = SOFTAES_SWIZZLE(inva, k);
    const v128_t iak = wasm_v128_xor(SOFTAES_SWIZZLE(inv, i), ak);
    const v128_t jak = wasm_v128_xor(SOFTAES_SWIZZLE(inv, j), ak);
    const v128_t io  = wasm_v128_xor(SOFTAES_SWIZZLE(inv, iak), j);
    const v128_t jo  = wasm_v128_xor(SOFTAES_SWIZZLE(inv, jak), i);

    const v128_t a  = wasm_v128_xor(SOFTAES_SWIZZLE(sbo_u, io), SOFTAES_SWIZZLE(sbo_t, jo));
    const v128_t a2 = wasm_v128_xor(SOFTAES_SWIZZLE(sbo2_u, io), SOFTAES_SWIZZLE(sbo2_t, jo));

    const v128_t m0 = SOFTAES_SWIZZLE(a2, mc0);
    const v128_t m1 = SOFTAES_SWIZZLE(wasm_v128_xor(a, a2), mc1);
    const v128_t m2 = SOFTAES_SWIZZLE(a, mc2);
    const v128_t m3 = SOFTAES_SWIZZLE(a, mc3);

    return wasm_v128_xor(wasm_v128_xor(m0, m1), wasm_v128_xor(m2, m3));
}

/* Walk backward to limit SIMD register pressure. */
static inline void
softaes_aegis_rotate(SoftAesBlock *st, const int blocks, const int lanes)
{
    const v128_t c63 = wasm_v128_load(libaegis_softaes_simd_tables[SOFTAES_TBL_C63]);
    v128_t       last[4];
    int          b, l;

    for (l = 0; l < lanes; l++) {
        last[l] = st[(blocks - 1) * lanes + l];
    }
    for (b = blocks - 1; b > 0; b--) {
        for (l = 0; l < lanes; l++) {
            st[b * lanes + l] = SOFTAES_XOR3(softaes_block_aesl_nc(st[(b - 1) * lanes + l]), c63,
                                             st[b * lanes + l]);
        }
    }
    for (l = 0; l < lanes; l++) {
        st[l] = SOFTAES_XOR3(softaes_block_aesl_nc(last[l]), c63, st[l]);
    }
}

static inline void
softaes_aegis_rotate8_x1(SoftAesBlock st[8])
{
    softaes_aegis_rotate(st, 8, 1);
}

static inline void
softaes_aegis_rotate8_x2(SoftAesBlock st[16])
{
    softaes_aegis_rotate(st, 8, 2);
}

static inline void
softaes_aegis_rotate8_x4(SoftAesBlock st[32])
{
    softaes_aegis_rotate(st, 8, 4);
}

static inline void
softaes_aegis_rotate6_x1(SoftAesBlock st[6])
{
    softaes_aegis_rotate(st, 6, 1);
}

static inline void
softaes_aegis_rotate6_x2(SoftAesBlock st[12])
{
    softaes_aegis_rotate(st, 6, 2);
}

static inline void
softaes_aegis_rotate6_x4(SoftAesBlock st[24])
{
    softaes_aegis_rotate(st, 6, 4);
}

/* Keep LLVM from interleaving output stores with the AES round. */
#    define AEGIS_AES_BLOCK_ENC_BARRIER() __asm__ __volatile__("" ::: "memory")

#else

typedef struct SoftAesBlock {
    uint32_t w0;
    uint32_t w1;
    uint32_t w2;
    uint32_t w3;
} SoftAesBlock;

/* Compute out[i] = AESRound(in[i]) ^ rk[i] for all blocks of an AEGIS state update at once.
 * out may alias rk, but in must not overlap with out. */
static void softaes_blocks_encrypt_x8(SoftAesBlock out[8], const SoftAesBlock in[8],
                                      const SoftAesBlock rk[8]);

static void softaes_blocks_encrypt_x6(SoftAesBlock out[6], const SoftAesBlock in[6],
                                      const SoftAesBlock rk[6]);

/*
 * In-place AEGIS state rotation: with the state as 8 (or 6) blocks of `lanes`
 * 16-byte pieces, replaces each block with AESRound(previous block) ^ block.
 */
static void softaes_aegis_rotate8_x1(SoftAesBlock st[8]);
static void softaes_aegis_rotate8_x2(SoftAesBlock st[16]);
static void softaes_aegis_rotate8_x4(SoftAesBlock st[32]);
static void softaes_aegis_rotate6_x1(SoftAesBlock st[6]);
static void softaes_aegis_rotate6_x2(SoftAesBlock st[12]);
static void softaes_aegis_rotate6_x4(SoftAesBlock st[24]);

static inline SoftAesBlock
softaes_block_load(const uint8_t in[16])
{
#    ifdef NATIVE_LITTLE_ENDIAN
    SoftAesBlock out;
    memcpy(&out, in, 16);
#    else
    const SoftAesBlock out = { AEGIS_LOAD32_LE(in + 0), AEGIS_LOAD32_LE(in + 4), AEGIS_LOAD32_LE(in + 8),
                               AEGIS_LOAD32_LE(in + 12) };
#    endif
    return out;
}

static inline SoftAesBlock
softaes_block_load64x2(const uint64_t a, const uint64_t b)
{
    const SoftAesBlock out = { (uint32_t) b, (uint32_t) (b >> 32), (uint32_t) a,
                               (uint32_t) (a >> 32) };
    return out;
}

static inline void
softaes_block_store(uint8_t out[16], const SoftAesBlock in)
{
#    ifdef NATIVE_LITTLE_ENDIAN
    memcpy(out, &in, 16);
#    else
    AEGIS_STORE32_LE(out + 0, in.w0);
    AEGIS_STORE32_LE(out + 4, in.w1);
    AEGIS_STORE32_LE(out + 8, in.w2);
    AEGIS_STORE32_LE(out + 12, in.w3);
#    endif
}

static inline SoftAesBlock
softaes_block_xor(const SoftAesBlock a, const SoftAesBlock b)
{
    const SoftAesBlock out = { a.w0 ^ b.w0, a.w1 ^ b.w1, a.w2 ^ b.w2, a.w3 ^ b.w3 };
    return out;
}

static inline SoftAesBlock
softaes_block_and(const SoftAesBlock a, const SoftAesBlock b)
{
    const SoftAesBlock out = { a.w0 & b.w0, a.w1 & b.w1, a.w2 & b.w2, a.w3 & b.w3 };
    return out;
}

#endif

#endif /* AEGIS_SOFTAES_H */
