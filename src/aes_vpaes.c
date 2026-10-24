/*
** Name:        aes_vpaes.c
** Purpose:     "vpaes" backend for aes_core.c: AES with vector permutes
**              (SSSE3, NEON/AArch64, WebAssembly SIMD128), constant time
**              (no table lookups that depend on key or data)
** Author:      Ulrich Telle
** Created:     2026-10-07
** Copyright:   (c) 2026 Ulrich Telle
** License:     MIT
*/

/*
** If the target has a vpaes backend, it defines SQLITE3MC_AES_VPAES
** and SQLITE3MC_VPAES_STATE_SIZE, which switches the vpaes backend on
** in aes_core.c. Options:
**   SQLITE3MC_AES_NO_VPAES       do not use vpaes at all
**   SQLITE3MC_AES_HARDWARE_ONLY  (see aes_core.c) implies no vpaes
**   SQLITE3MC_VPAES_HAS_SSSE3()  optional hook (x86 only): expression that
**                                tells at run time whether the CPU supports
**                                SSSE3, for example from hwcheck.c. By default
**                                the compiler/CPUID is used.
**   VPAES_ISA_ATTR               optional (x86 GCC/Clang): function attribute
**                                to enable SSSE3 for this file's functions,
**                                for example SQLITE3MC_FUNC_ISA("ssse3")
**
** Supported key lengths: 16 and 32 bytes (AES-192 is not needed and was
** removed from the port). Only little-endian targets are supported.
**
** The code is a C port of Botan's src/lib/block/aes/aes_vperm/aes_vperm.cpp
** (C) 2010,2016,2019 Jack Lloyd, released under the Simplified BSD License.
** Botan's code is based on public domain x86-64 assembly written by
** Mike Hamburg, described in "Accelerating AES with Vector Permute
** Instructions" (CHES 2009), https://crypto.stanford.edu/vpaes/
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
** 1. Redistributions of source code must retain the above copyright notice,
**    this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright notice,
**    this list of conditions and the following disclaimer in the documentation
**    and/or other materials provided with the distribution.
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) "AS IS" AND ANY EXPRESS OR IMPLIED
** WARRANTIES ARE DISCLAIMED. (Full text: Botan's license.txt)
**
** The CBC functions are new (not from Botan): encryption processes one
** block at a time (CBC is serial), decryption two blocks interleaved.
*/

#include "cipher_common.h"

#if !defined(SQLITE3MC_AES_NO_VPAES) && !defined(SQLITE3MC_AES_HARDWARE_ONLY)
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#define VPAES_BACKEND_SSSE3 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#define VPAES_BACKEND_NEON 1
#elif defined(__wasm_simd128__)
#define VPAES_BACKEND_WASM 1
#endif
#endif

#if defined(VPAES_BACKEND_SSSE3) || defined(VPAES_BACKEND_NEON) || defined(VPAES_BACKEND_WASM)

#define SQLITE3MC_AES_VPAES 1
/* Two key schedules (encryption and decryption) of 15 round keys of 16 bytes */
#define SQLITE3MC_VPAES_STATE_SIZE (2 * 15 * 16)

/*
** Minimal SIMD layer (replaces Botan's SIMD_4x32)
**
** - vp_load / vp_store      unaligned 16-byte load/store (little-endian)
** - vp_xor / vp_and
** - vp_shuf                 byte shuffle (table lookup); the index bytes are
**                           either < 16 or have bit 7 set (-> result is 0)
** - vp_hi_nibs              (x >> 4) & 0x0F per byte
** - vp_splat32 / vp_splat8  broadcast
** - vp_shl4 / vp_shl8       shift the whole register left by 4 / 8 bytes
*/

#if defined(VPAES_BACKEND_SSSE3)

#include <tmmintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

#ifndef VPAES_ISA_ATTR
#if (defined(__GNUC__) || defined(__clang__)) && !defined(__SSSE3__)
#define VPAES_ISA_ATTR SQLITE3MC_FUNC_ISA("ssse3")
#else
#define VPAES_ISA_ATTR
#endif
#endif
#define VPAES_TARGET VPAES_ISA_ATTR

typedef __m128i VpVar;

#define VPAES_INLINE static inline VPAES_TARGET

VPAES_INLINE VpVar vp_load(const void* p) { return _mm_loadu_si128((const __m128i*) p); }
VPAES_INLINE void vp_store(void* p, VpVar v) { _mm_storeu_si128((__m128i*) p, v); }
VPAES_INLINE VpVar vp_xor(VpVar a, VpVar b) { return _mm_xor_si128(a, b); }
VPAES_INLINE VpVar vp_and(VpVar a, VpVar b) { return _mm_and_si128(a, b); }
VPAES_INLINE VpVar vp_shuf(VpVar tbl, VpVar idx) { return _mm_shuffle_epi8(tbl, idx); }
VPAES_INLINE VpVar vp_splat32(uint32_t x) { return _mm_set1_epi32((int) x); }
VPAES_INLINE VpVar vp_splat8(unsigned char x) { return _mm_set1_epi8((char) x); }
VPAES_INLINE VpVar vp_hi_nibs(VpVar x) { return _mm_and_si128(_mm_srli_epi32(x, 4), _mm_set1_epi8(0x0F)); }
VPAES_INLINE VpVar vp_shl4(VpVar x) { return _mm_slli_si128(x, 4); }
VPAES_INLINE VpVar vp_shl8(VpVar x) { return _mm_slli_si128(x, 8); }

#elif defined(VPAES_BACKEND_NEON)

#if defined(USE_ARM64_NEON_H)
#include <arm64_neon.h>
#else
#include <arm_neon.h>
#endif

#define VPAES_TARGET

typedef uint8x16_t VpVar;

#define VPAES_INLINE static inline VPAES_TARGET

VPAES_INLINE VpVar vp_load(const void* p) { return vld1q_u8((const uint8_t*) p); }
VPAES_INLINE void vp_store(void* p, VpVar v) { vst1q_u8((uint8_t*) p, v); }
VPAES_INLINE VpVar vp_xor(VpVar a, VpVar b) { return veorq_u8(a, b); }
VPAES_INLINE VpVar vp_and(VpVar a, VpVar b) { return vandq_u8(a, b); }
VPAES_INLINE VpVar vp_shuf(VpVar tbl, VpVar idx) { return vqtbl1q_u8(tbl, idx); }
VPAES_INLINE VpVar vp_splat32(uint32_t x) { return vreinterpretq_u8_u32(vdupq_n_u32(x)); }
/* Broadcast via a replicated 32-bit value (as in Botan; avoids a MSVC ARM64 miscompilation) */
VPAES_INLINE VpVar vp_splat8(unsigned char x) { return vreinterpretq_u8_u32(vdupq_n_u32((uint32_t) x * 0x01010101U)); }
VPAES_INLINE VpVar vp_hi_nibs(VpVar x) { return vshrq_n_u8(x, 4); }
VPAES_INLINE VpVar vp_shl4(VpVar x) { return vextq_u8(vdupq_n_u8(0), x, 12); }
VPAES_INLINE VpVar vp_shl8(VpVar x) { return vextq_u8(vdupq_n_u8(0), x, 8); }

#elif defined(VPAES_BACKEND_WASM)

#include <wasm_simd128.h>

#define VPAES_TARGET

typedef v128_t VpVar;

#define VPAES_INLINE static inline VPAES_TARGET

VPAES_INLINE VpVar vp_load(const void* p) { return wasm_v128_load(p); }
VPAES_INLINE void vp_store(void* p, VpVar v) { wasm_v128_store(p, v); }
VPAES_INLINE VpVar vp_xor(VpVar a, VpVar b) { return wasm_v128_xor(a, b); }
VPAES_INLINE VpVar vp_and(VpVar a, VpVar b) { return wasm_v128_and(a, b); }
VPAES_INLINE VpVar vp_shuf(VpVar tbl, VpVar idx) { return wasm_i8x16_swizzle(tbl, idx); }
VPAES_INLINE VpVar vp_splat32(uint32_t x) { return wasm_u32x4_splat(x); }
VPAES_INLINE VpVar vp_splat8(unsigned char x) { return wasm_u8x16_splat(x); }
VPAES_INLINE VpVar vp_hi_nibs(VpVar x) { return wasm_u8x16_shr(x, 4); }
VPAES_INLINE VpVar vp_shl4(VpVar x)
{
  return wasm_i8x16_shuffle(x, wasm_u32x4_const_splat(0), 16, 16, 16, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
}
VPAES_INLINE VpVar vp_shl8(VpVar x)
{
  return wasm_i8x16_shuffle(x, wasm_u32x4_const_splat(0), 16, 16, 16, 16, 16, 16, 16, 16, 0, 1, 2, 3, 4, 5, 6, 7);
}

#endif

/*
** Constants (128-bit tables, given as 4 little-endian 32-bit words)
*/

typedef struct _VpConst { uint32_t w[4]; } VpConst;

#define VP_LOAD_CONST(c) vp_load(&(c))

static const VpConst vp_sr[4] =
{
  {{0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C}},
  {{0x0F0A0500, 0x030E0904, 0x07020D08, 0x0B06010C}},
  {{0x0B020900, 0x0F060D04, 0x030A0108, 0x070E050C}},
  {{0x070A0D00, 0x0B0E0104, 0x0F020508, 0x0306090C}},
};

static const VpConst vp_k_ipt1 = {{0x5A2A7000, 0xC2B2E898, 0x52227808, 0xCABAE090}};
static const VpConst vp_k_ipt2 = {{0x317C4D00, 0x4C01307D, 0xB0FDCC81, 0xCD80B1FC}};
static const VpConst vp_k_inv1 = {{0x0D080180, 0x0E05060F, 0x0A0B0C02, 0x04070309}};
static const VpConst vp_k_inv2 = {{0x0F0B0780, 0x01040A06, 0x02050809, 0x030D0E0C}};

static const VpConst vp_sb1u = {{0xCB503E00, 0xB19BE18F, 0x142AF544, 0xA5DF7A6E}};
static const VpConst vp_sb1t = {{0xFAE22300, 0x3618D415, 0x0D2ED9EF, 0x3BF7CCC1}};
static const VpConst vp_sb2u = {{0x0B712400, 0xE27A93C6, 0xBC982FCD, 0x5EB7E955}};
static const VpConst vp_sb2t = {{0x0AE12900, 0x69EB8840, 0xAB82234A, 0xC2A163C8}};
static const VpConst vp_sbou = {{0x6FBDC700, 0xD0D26D17, 0xC502A878, 0x15AABF7A}};
static const VpConst vp_sbot = {{0x5FBB6A00, 0xCFE474A5, 0x412B35FA, 0x8E1E90D1}};

static const VpConst vp_mc_forward[4] =
{
  {{0x00030201, 0x04070605, 0x080B0A09, 0x0C0F0E0D}},
  {{0x04070605, 0x080B0A09, 0x0C0F0E0D, 0x00030201}},
  {{0x080B0A09, 0x0C0F0E0D, 0x00030201, 0x04070605}},
  {{0x0C0F0E0D, 0x00030201, 0x04070605, 0x080B0A09}},
};
static const VpConst vp_mc_backward[4] =
{
  {{0x02010003, 0x06050407, 0x0A09080B, 0x0E0D0C0F}},
  {{0x0E0D0C0F, 0x02010003, 0x06050407, 0x0A09080B}},
  {{0x0A09080B, 0x0E0D0C0F, 0x02010003, 0x06050407}},
  {{0x06050407, 0x0A09080B, 0x0E0D0C0F, 0x02010003}},
};

static const VpConst vp_k_dipt1 = {{0x0B545F00, 0x0F505B04, 0x114E451A, 0x154A411E}};
static const VpConst vp_k_dipt2 = {{0x60056500, 0x86E383E6, 0xF491F194, 0x12771772}};

static const VpConst vp_mcx[4] =
{
  {{0x0C0F0E0D, 0x00030201, 0x04070605, 0x080B0A09}},
  {{0x080B0A09, 0x0C0F0E0D, 0x00030201, 0x04070605}},
  {{0x04070605, 0x080B0A09, 0x0C0F0E0D, 0x00030201}},
  {{0x00030201, 0x04070605, 0x080B0A09, 0x0C0F0E0D}},
};

static const VpConst vp_sbbu = {{0x96B44200, 0xD0226492, 0xB0F2D404, 0x602646F6}};
static const VpConst vp_sbbt = {{0xCD596700, 0xC19498A6, 0x3255AA6B, 0xF3FF0C3E}};
static const VpConst vp_sbdu = {{0xE6B1A200, 0x7D57CCDF, 0x882A4439, 0xF56E9B13}};
static const VpConst vp_sbdt = {{0x24C6CB00, 0x3CE2FAF7, 0x15DEEFD3, 0x2931180D}};
static const VpConst vp_sbeu = {{0x26D4D000, 0x46F29296, 0x64B4F6B0, 0x22426004}};
static const VpConst vp_sbet = {{0xFFAAC100, 0x0C55A6CD, 0x98593E32, 0x9467F36B}};
static const VpConst vp_sb9u = {{0x9A86D600, 0x851C0353, 0x4F994CC9, 0xCAD51F50}};
static const VpConst vp_sb9t = {{0xECD74900, 0xC03B1789, 0xB2FBA565, 0x725E2C9E}};

static const VpConst vp_sboud = {{0x7EF94000, 0x1387EA53, 0xD4943E2D, 0xC7AA6DB9}};
static const VpConst vp_sbotd = {{0x93441D00, 0x12D7560F, 0xD8C58E9C, 0xCA4B8159}};

/* key schedule */
static const VpConst vp_dsk[8] =
{
  {{0x7ED9A700, 0xB6116FC8, 0x82255BFC, 0x4AED9334}},
  {{0x27143300, 0x45765162, 0xE9DAFDCE, 0x8BB89FAC}},
  {{0xCCA86400, 0x27438FEB, 0xADC90561, 0x4622EE8A}},
  {{0x4F92DD00, 0x815C13CE, 0xBD602FF2, 0x73AEE13C}},
  {{0x01C6C700, 0x03C4C502, 0xFA3D3CFB, 0xF83F3EF9}},
  {{0x38CFF700, 0xEE1921D6, 0x7384BC4B, 0xA5526A9D}},
  {{0x53732000, 0xE3C390B0, 0x10306343, 0xA080D3F3}},
  {{0x036982E8, 0xA0CA214B, 0x8CE60D67, 0x2F45AEC4}},
};
static const VpConst vp_out_tr1 = {{0xD6B66000, 0xFF9F4929, 0xDEBE6808, 0xF7974121}};
static const VpConst vp_out_tr2 = {{0x50BCEC00, 0x01EDBD51, 0xB05C0CE0, 0xE10D5DB1}};
static const VpConst vp_deskew1 = {{0x47A4E300, 0x07E4A340, 0x5DBEF91A, 0x1DFEB95A}};
static const VpConst vp_deskew2 = {{0x83EA6900, 0x5F36B5DC, 0xF49D1E77, 0x2841C2AB}};

static const VpConst vp_rcon[10] =
{
  {{0x00000070, 0x00000000, 0x00000000, 0x00000000}},
  {{0x0000002A, 0x00000000, 0x00000000, 0x00000000}},
  {{0x00000098, 0x00000000, 0x00000000, 0x00000000}},
  {{0x00000008, 0x00000000, 0x00000000, 0x00000000}},
  {{0x0000004D, 0x00000000, 0x00000000, 0x00000000}},
  {{0x0000007C, 0x00000000, 0x00000000, 0x00000000}},
  {{0x0000007D, 0x00000000, 0x00000000, 0x00000000}},
  {{0x00000081, 0x00000000, 0x00000000, 0x00000000}},
  {{0x0000001F, 0x00000000, 0x00000000, 0x00000000}},
  {{0x00000083, 0x00000000, 0x00000000, 0x00000000}},
};

/*
** Round functions
*/

VPAES_INLINE VpVar vp_shiftrows(VpVar x, unsigned r)
{
  return vp_shuf(x, VP_LOAD_CONST(vp_sr[r]));
}

VPAES_INLINE VpVar vp_lo_nibs(VpVar x)
{
  return vp_and(x, vp_splat8(0x0F));
}

VPAES_INLINE VpVar vp_enc_first_round(VpVar B, VpVar K)
{
  return vp_xor(vp_xor(vp_shuf(VP_LOAD_CONST(vp_k_ipt1), vp_lo_nibs(B)), vp_shuf(VP_LOAD_CONST(vp_k_ipt2), vp_hi_nibs(B))), K);
}

VPAES_INLINE void vp_decompose_kinv(VpVar B, VpVar* t5, VpVar* t6)
{
  const VpVar kinv1 = VP_LOAD_CONST(vp_k_inv1);
  const VpVar kinv2 = VP_LOAD_CONST(vp_k_inv2);
  const VpVar Bh = vp_hi_nibs(B);
  VpVar Bl = vp_lo_nibs(B);
  const VpVar t2 = vp_shuf(kinv2, Bl);
  Bl = vp_xor(Bl, Bh);

  *t5 = vp_xor(Bl, vp_shuf(kinv1, vp_xor(t2, vp_shuf(kinv1, Bh))));
  *t6 = vp_xor(Bh, vp_shuf(kinv1, vp_xor(t2, vp_shuf(kinv1, Bl))));
}

VPAES_INLINE VpVar vp_enc_round(VpVar B, VpVar K, unsigned r)
{
  VpVar t5, t6;
  const VpVar mcf = VP_LOAD_CONST(vp_mc_forward[r % 4]);
  const VpVar mcb = VP_LOAD_CONST(vp_mc_backward[r % 4]);

  vp_decompose_kinv(B, &t5, &t6);

  {
    const VpVar t7 = vp_xor(vp_xor(vp_shuf(VP_LOAD_CONST(vp_sb1t), t6), vp_shuf(VP_LOAD_CONST(vp_sb1u), t5)), K);
    const VpVar t8 = vp_xor(vp_xor(vp_shuf(VP_LOAD_CONST(vp_sb2t), t6), vp_shuf(VP_LOAD_CONST(vp_sb2u), t5)), vp_shuf(t7, mcf));
    return vp_xor(vp_xor(vp_shuf(t8, mcf), vp_shuf(t7, mcb)), t8);
  }
}

VPAES_INLINE VpVar vp_enc_last_round(VpVar B, VpVar K, unsigned r)
{
  VpVar t5, t6;
  vp_decompose_kinv(B, &t5, &t6);
  return vp_shiftrows(vp_xor(vp_xor(vp_shuf(VP_LOAD_CONST(vp_sbou), t5), vp_shuf(VP_LOAD_CONST(vp_sbot), t6)), K), r % 4);
}

VPAES_INLINE VpVar vp_dec_first_round(VpVar B, VpVar K)
{
  return vp_xor(vp_xor(vp_shuf(VP_LOAD_CONST(vp_k_dipt1), vp_lo_nibs(B)), vp_shuf(VP_LOAD_CONST(vp_k_dipt2), vp_hi_nibs(B))), K);
}

VPAES_INLINE VpVar vp_dec_round(VpVar B, VpVar K, unsigned r)
{
  VpVar t5, t6;
  const VpVar mc = VP_LOAD_CONST(vp_mcx[(r - 1) % 4]);

  vp_decompose_kinv(B, &t5, &t6);

  {
    const VpVar t8 = vp_xor(vp_xor(vp_shuf(VP_LOAD_CONST(vp_sb9t), t6), vp_shuf(VP_LOAD_CONST(vp_sb9u), t5)), K);
    const VpVar t9 = vp_xor(vp_xor(vp_shuf(t8, mc), vp_shuf(VP_LOAD_CONST(vp_sbdu), t5)), vp_shuf(VP_LOAD_CONST(vp_sbdt), t6));
    const VpVar t12 = vp_xor(vp_xor(vp_shuf(t9, mc), vp_shuf(VP_LOAD_CONST(vp_sbbu), t5)), vp_shuf(VP_LOAD_CONST(vp_sbbt), t6));
    return vp_xor(vp_xor(vp_shuf(t12, mc), vp_shuf(VP_LOAD_CONST(vp_sbeu), t5)), vp_shuf(VP_LOAD_CONST(vp_sbet), t6));
  }
}

VPAES_INLINE VpVar vp_dec_last_round(VpVar B, VpVar K, unsigned r)
{
  VpVar t5, t6;
  const unsigned which_sr = ((((r - 1) << 4) ^ 48) & 48) / 16;

  vp_decompose_kinv(B, &t5, &t6);

  return vp_shiftrows(vp_xor(vp_xor(vp_shuf(VP_LOAD_CONST(vp_sboud), t5), vp_shuf(VP_LOAD_CONST(vp_sbotd), t6)), K), which_sr);
}

#define VP_LOAD_RK(rk, i) vp_load((const uint8_t*) (rk) + 16 * (i))

VPAES_INLINE int vp_encrypt_blocks(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk, unsigned rounds)
{
  const size_t blocks2 = blocks - (blocks % 2);
  size_t i;
  unsigned r;

  for (i = 0; i != blocks2; i += 2)
  {
    VpVar B0 = vp_load(in + i * 16);
    VpVar B1 = vp_load(in + (i + 1) * 16);

    B0 = vp_enc_first_round(B0, VP_LOAD_RK(rk, 0));
    B1 = vp_enc_first_round(B1, VP_LOAD_RK(rk, 0));

    for (r = 1; r != rounds; ++r)
    {
      const VpVar K = VP_LOAD_RK(rk, r);
      B0 = vp_enc_round(B0, K, r);
      B1 = vp_enc_round(B1, K, r);
    }

    B0 = vp_enc_last_round(B0, VP_LOAD_RK(rk, rounds), rounds);
    B1 = vp_enc_last_round(B1, VP_LOAD_RK(rk, rounds), rounds);

    vp_store(out + i * 16, B0);
    vp_store(out + (i + 1) * 16, B1);
  }

  for (i = blocks2; i < blocks; ++i)
  {
    VpVar B = vp_load(in + i * 16);

    B = vp_enc_first_round(B, VP_LOAD_RK(rk, 0));
    for (r = 1; r != rounds; ++r)
    {
      B = vp_enc_round(B, VP_LOAD_RK(rk, r), r);
    }
    B = vp_enc_last_round(B, VP_LOAD_RK(rk, rounds), rounds);
    vp_store(out + i * 16, B);
  }

  return 0;
}

VPAES_INLINE void vp_decrypt_blocks(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk, unsigned rounds)
{
  const size_t blocks2 = blocks - (blocks % 2);
  size_t i;
  unsigned r;

  for (i = 0; i != blocks2; i += 2)
  {
    VpVar B0 = vp_load(in + i * 16);
    VpVar B1 = vp_load(in + (i + 1) * 16);

    B0 = vp_dec_first_round(B0, VP_LOAD_RK(rk, 0));
    B1 = vp_dec_first_round(B1, VP_LOAD_RK(rk, 0));

    for (r = 1; r != rounds; ++r)
    {
      const VpVar K = VP_LOAD_RK(rk, r);
      B0 = vp_dec_round(B0, K, r);
      B1 = vp_dec_round(B1, K, r);
    }

    B0 = vp_dec_last_round(B0, VP_LOAD_RK(rk, rounds), rounds);
    B1 = vp_dec_last_round(B1, VP_LOAD_RK(rk, rounds), rounds);

    vp_store(out + i * 16, B0);
    vp_store(out + (i + 1) * 16, B1);
  }

  for (i = blocks2; i < blocks; ++i)
  {
    VpVar B = vp_load(in + i * 16);

    B = vp_dec_first_round(B, VP_LOAD_RK(rk, 0));
    for (r = 1; r != rounds; ++r)
    {
      B = vp_dec_round(B, VP_LOAD_RK(rk, r), r);
    }
    B = vp_dec_last_round(B, VP_LOAD_RK(rk, rounds), rounds);
    vp_store(out + i * 16, B);
  }
}

/*
** Key schedule
*/

VPAES_INLINE VpVar vp_schedule_transform(VpVar input, const VpConst* table1, const VpConst* table2)
{
  return vp_xor(vp_shuf(VP_LOAD_CONST(*table1), vp_lo_nibs(input)), vp_shuf(VP_LOAD_CONST(*table2), vp_hi_nibs(input)));
}

VPAES_INLINE VpVar vp_schedule_transform_init(VpVar input)
{
  return vp_enc_first_round(input, vp_splat32(0));
}

VPAES_INLINE VpVar vp_schedule_mangle(VpVar k, unsigned round_no)
{
  const VpVar mcf0 = VP_LOAD_CONST(vp_mc_forward[0]);
  VpVar t = vp_shuf(vp_xor(k, vp_splat8(0x5B)), mcf0);
  VpVar t2 = t;
  t = vp_shuf(t, mcf0);
  t2 = vp_xor(vp_xor(t, t2), vp_shuf(t, mcf0));
  return vp_shiftrows(t2, round_no % 4);
}

VPAES_INLINE VpVar vp_schedule_mangle_dec(VpVar k, unsigned round_no)
{
  const VpVar mcf0 = VP_LOAD_CONST(vp_mc_forward[0]);
  VpVar t = vp_schedule_transform(k, &vp_dsk[0], &vp_dsk[1]);
  VpVar output = vp_shuf(t, mcf0);

  t = vp_schedule_transform(t, &vp_dsk[2], &vp_dsk[3]);
  output = vp_shuf(vp_xor(t, output), mcf0);

  t = vp_schedule_transform(t, &vp_dsk[4], &vp_dsk[5]);
  output = vp_shuf(vp_xor(t, output), mcf0);

  t = vp_schedule_transform(t, &vp_dsk[6], &vp_dsk[7]);
  output = vp_shuf(vp_xor(t, output), mcf0);

  return vp_shiftrows(output, round_no % 4);
}

VPAES_INLINE VpVar vp_schedule_mangle_last(VpVar k, unsigned round_no)
{
  k = vp_xor(vp_shiftrows(k, round_no % 4), vp_splat8(0x5B));
  return vp_schedule_transform(k, &vp_out_tr1, &vp_out_tr2);
}

VPAES_INLINE VpVar vp_schedule_mangle_last_dec(VpVar k)
{
  k = vp_xor(k, vp_splat8(0x5B));
  return vp_schedule_transform(k, &vp_deskew1, &vp_deskew2);
}

VPAES_INLINE VpVar vp_schedule_round(VpVar input1, VpVar input2)
{
  VpVar t5, t6;
  VpVar smeared = vp_xor(input2, vp_shl4(input2));
  smeared = vp_xor(smeared, vp_shl8(smeared));
  smeared = vp_xor(smeared, vp_splat8(0x5B));

  vp_decompose_kinv(input1, &t5, &t6);

  return vp_xor(vp_xor(smeared, vp_shuf(VP_LOAD_CONST(vp_sb1u), t5)), vp_shuf(VP_LOAD_CONST(vp_sb1t), t6));
}

VPAES_INLINE VpVar vp_schedule_round_rcon(unsigned rc, VpVar input1, VpVar input2)
{
  /* This byte shuffle is equivalent to alignr<1>(shuffle32(input1, (3,3,3,3))) */
  const VpVar shuffle3333_15 = vp_splat32(0x0C0F0E0D);
  return vp_schedule_round(vp_shuf(input1, shuffle3333_15), vp_xor(input2, VP_LOAD_CONST(vp_rcon[rc])));
}

VPAES_INLINE void vp_key_schedule_128(const uint8_t* keyb, uint32_t* ek, uint32_t* dk)
{
  unsigned i;
  VpVar key = vp_load(keyb);

  vp_store(&dk[4 * 10], vp_shiftrows(key, 2));

  key = vp_schedule_transform_init(key);
  vp_store(&ek[0], key);

  for (i = 1; i != 10; ++i)
  {
    key = vp_schedule_round_rcon(i - 1, key, key);
    vp_store(&ek[4 * i], vp_schedule_mangle(key, (12 - i) % 4));
    vp_store(&dk[4 * (10 - i)], vp_schedule_mangle_dec(key, (10 - i) % 4));
  }

  key = vp_schedule_round_rcon(9, key, key);
  vp_store(&ek[4 * 10], vp_schedule_mangle_last(key, 2));
  vp_store(&dk[0], vp_schedule_mangle_last_dec(key));
}

VPAES_INLINE void vp_key_schedule_256(const uint8_t* keyb, uint32_t* ek, uint32_t* dk)
{
  unsigned i;
  VpVar key1 = vp_load(keyb);
  VpVar key2 = vp_load(keyb + 16);
  const VpVar shuffle3333 = vp_splat32(0x0F0E0D0C);

  vp_store(&dk[4 * 14], vp_shiftrows(key1, 2));

  key1 = vp_schedule_transform_init(key1);
  key2 = vp_schedule_transform_init(key2);

  vp_store(&ek[0], key1);
  vp_store(&ek[4], vp_schedule_mangle(key2, 3));

  vp_store(&dk[4 * 13], vp_schedule_mangle_dec(key2, 1));

  for (i = 2; i != 14; i += 2)
  {
    const VpVar k_t = key2;
    key1 = key2 = vp_schedule_round_rcon((i / 2) - 1, key2, key1);

    vp_store(&ek[4 * i], vp_schedule_mangle(key2, i % 4));
    vp_store(&dk[4 * (14 - i)], vp_schedule_mangle_dec(key2, (i + 2) % 4));

    key2 = vp_schedule_round(vp_shuf(key2, shuffle3333), k_t);

    vp_store(&ek[4 * (i + 1)], vp_schedule_mangle(key2, (i - 1) % 4));
    vp_store(&dk[4 * (13 - i)], vp_schedule_mangle_dec(key2, (i + 1) % 4));
  }

  key2 = vp_schedule_round_rcon(6, key2, key1);

  vp_store(&ek[4 * 14], vp_schedule_mangle_last(key2, 2));
  vp_store(&dk[0], vp_schedule_mangle_last_dec(key2));
}

/*
** CBC
*/

/* CBC encryption in place; len is a multiple of 16; rounds is 10 or 14 */
VPAES_INLINE int vp_cbc_encrypt(const unsigned char* rk, unsigned rounds, const unsigned char* iv,
                          unsigned char* buf, size_t len)
{
  VpVar prev = vp_load(iv);
  for (; len >= 16; len -= 16, buf += 16)
  {
    unsigned r;
    VpVar B = vp_xor(vp_load(buf), prev);
    B = vp_enc_first_round(B, VP_LOAD_RK(rk, 0));
    for (r = 1; r != rounds; ++r)
    {
      B = vp_enc_round(B, VP_LOAD_RK(rk, r), r);
    }
    B = vp_enc_last_round(B, VP_LOAD_RK(rk, rounds), rounds);
    vp_store(buf, B);
    prev = B;
  }
  return 0;
}

/* CBC decryption in place; len is a multiple of 16; two blocks are processed interleaved */
VPAES_INLINE int vp_cbc_decrypt(const unsigned char* rk, unsigned rounds, const unsigned char* iv,
                          unsigned char* buf, size_t len)
{
  VpVar prev = vp_load(iv);
  unsigned r;

  for (; len >= 32; len -= 32, buf += 32)
  {
    const VpVar C0 = vp_load(buf);
    const VpVar C1 = vp_load(buf + 16);
    VpVar B0 = vp_dec_first_round(C0, VP_LOAD_RK(rk, 0));
    VpVar B1 = vp_dec_first_round(C1, VP_LOAD_RK(rk, 0));

    for (r = 1; r != rounds; ++r)
    {
      const VpVar K = VP_LOAD_RK(rk, r);
      B0 = vp_dec_round(B0, K, r);
      B1 = vp_dec_round(B1, K, r);
    }

    B0 = vp_dec_last_round(B0, VP_LOAD_RK(rk, rounds), rounds);
    B1 = vp_dec_last_round(B1, VP_LOAD_RK(rk, rounds), rounds);

    vp_store(buf, vp_xor(B0, prev));
    vp_store(buf + 16, vp_xor(B1, C0));
    prev = C1;
  }

  if (len >= 16)
  {
    const VpVar C = vp_load(buf);
    VpVar B = vp_dec_first_round(C, VP_LOAD_RK(rk, 0));
    for (r = 1; r != rounds; ++r)
    {
      B = vp_dec_round(B, VP_LOAD_RK(rk, r), r);
    }
    B = vp_dec_last_round(B, VP_LOAD_RK(rk, rounds), rounds);
    vp_store(buf, vp_xor(B, prev));
  }
  return 0;
}

/*
** Interface for aes_core.c
*/

/* Is the vpaes backend usable on this machine? */
SQLITE_PRIVATE int
sqlite3mcVpaesAvailable(void)
{
#if defined(VPAES_BACKEND_SSSE3)
  return (sqlite3mcCpuFeatures() & SQLITE3MC_CPU_SSSE3) != 0;
#else
  return 1; /* NEON (AArch64) and WASM SIMD128 are fixed at compile time */
#endif
}

/*
** Key setup; state has SQLITE3MC_VPAES_STATE_SIZE bytes (at least 4-byte aligned).
** Both key schedules are always created (flags is not needed).
** Returns 0 on success, -1 for a key length other than 16 or 32.
*/
SQLITE_PRIVATE VPAES_TARGET int
sqlite3mcVpaesInit(void* state, const unsigned char* key, int keyLen, int flags)
{
  uint32_t* ek = (uint32_t*) state;
  uint32_t* dk = ek + 15 * 4;
  (void) flags;
  if (keyLen == 16)
  {
    vp_key_schedule_128(key, ek, dk);
  }
  else if (keyLen == 32)
  {
    vp_key_schedule_256(key, ek, dk);
  }
  else
  {
    return -1;
  }
  return 0;
}

SQLITE_PRIVATE VPAES_TARGET int
sqlite3mcVpaesCbcEncrypt(const void* state, int rounds, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return vp_cbc_encrypt((const unsigned char*) state, (unsigned) rounds, iv, buf, len);
}

SQLITE_PRIVATE VPAES_TARGET int
sqlite3mcVpaesCbcDecrypt(const void* state, int rounds, const unsigned char iv[16], unsigned char* buf, size_t len)
{
  return vp_cbc_decrypt((const unsigned char*) state + 15 * 16, (unsigned) rounds, iv, buf, len);
}

SQLITE_PRIVATE VPAES_TARGET int
sqlite3mcVpaesEncryptBlocks(const void* state, int rounds, const unsigned char* in, unsigned char* out, size_t blocks)
{
  return vp_encrypt_blocks(in, out, blocks, (const uint32_t*)state, rounds);
}

#endif /* VPAES_BACKEND_* */
