/*
** Name:        aegis256x4_avx512.c
** Purpose:     Implementation of AEGIS-256x4 - AES-NI AVX512VL (256-bit halves)
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

#include "../common/aeshardware.h"

#if HAS_AEGIS_AES_HARDWARE == AEGIS_AES_HARDWARE_NI
#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../common/common.h"
#include "aegis256x4.h"
#include "aegis256x4_avx512vl.h"

#ifdef HAVE_VAESINTRIN_H

#ifdef __clang__
#  pragma clang attribute push(__attribute__((target("aes,vaes,avx512f,avx512vl"))), apply_to=function)
#elif defined(__GNUC__)
#  pragma GCC target("aes,vaes,avx512f,avx512vl")
#endif

#include <immintrin.h>

#define AES_BLOCK_LENGTH 64

/*
** Some CPUs run 512-bit AVX-512 instructions as two 256-bit passes internally.
** Splitting the state into real 256-bit halves gives those CPUs twice as many
** independent chains to work with, and AVX-512VL still provides the extra
** registers and ternary-logic instructions of full-width AVX-512.
*/
typedef struct {
    __m256i b0;
    __m256i b1;
} aegis256_avx512vl_aes_block_t;

#define AEGIS_AES_BLOCK_T aegis256_avx512vl_aes_block_t
#define AEGIS_BLOCKS      aegis256x4_avx512vl_blocks
#define AEGIS_STATE      _aegis256x4_avx512vl_state
#define AEGIS_MAC_STATE  _aegis256x4_avx512vl_mac_state

#define AEGIS_FUNC_PREFIX  aegis256_avx512vl_impl

#include "../common/func_names_define.h"

static inline AEGIS_AES_BLOCK_T
AEGIS_AES_BLOCK_XOR(const AEGIS_AES_BLOCK_T a, const AEGIS_AES_BLOCK_T b)
{
    return (AEGIS_AES_BLOCK_T) { _mm256_xor_si256(a.b0, b.b0), _mm256_xor_si256(a.b1, b.b1) };
}

static inline AEGIS_AES_BLOCK_T
AEGIS_AES_BLOCK_XOR3(const AEGIS_AES_BLOCK_T a, const AEGIS_AES_BLOCK_T b, const AEGIS_AES_BLOCK_T c)
{
    return (AEGIS_AES_BLOCK_T) { _mm256_ternarylogic_epi64(a.b0, b.b0, c.b0, 0x96),
                                 _mm256_ternarylogic_epi64(a.b1, b.b1, c.b1, 0x96) };
}

static inline AEGIS_AES_BLOCK_T
AEGIS_AES_BLOCK_AND(const AEGIS_AES_BLOCK_T a, const AEGIS_AES_BLOCK_T b)
{
    return (AEGIS_AES_BLOCK_T) { _mm256_and_si256(a.b0, b.b0), _mm256_and_si256(a.b1, b.b1) };
}

static inline AEGIS_AES_BLOCK_T
AEGIS_AES_BLOCK_LOAD(const uint8_t *a)
{
    return (AEGIS_AES_BLOCK_T) { _mm256_loadu_si256((const __m256i *) (const void *) a),
                                 _mm256_loadu_si256((const __m256i *) (const void *) (a + 32)) };
}

static inline AEGIS_AES_BLOCK_T
AEGIS_AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const __m256i t = _mm256_broadcastsi128_si256(_mm_set_epi64x((long long) a, (long long) b));
    return (AEGIS_AES_BLOCK_T) { t, t };
}

static inline AEGIS_AES_BLOCK_T
AEGIS_AES_BLOCK_BROADCAST128(const uint8_t *a)
{
    const __m256i t =
        _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) (const void *) a));
    return (AEGIS_AES_BLOCK_T) { t, t };
}

static inline void
AEGIS_AES_BLOCK_STORE(uint8_t *a, const AEGIS_AES_BLOCK_T b)
{
    _mm256_storeu_si256((__m256i *) (void *) a, b.b0);
    _mm256_storeu_si256((__m256i *) (void *) (a + 32), b.b1);
}

static inline AEGIS_AES_BLOCK_T
AEGIS_AES_ENC(const AEGIS_AES_BLOCK_T a, const AEGIS_AES_BLOCK_T b)
{
    return (AEGIS_AES_BLOCK_T) { _mm256_aesenc_epi128(a.b0, b.b0), _mm256_aesenc_epi128(a.b1, b.b1) };
}

static inline AEGIS_AES_BLOCK_T
AEGIS_AES_ENC0(const AEGIS_AES_BLOCK_T a)
{
    return (AEGIS_AES_BLOCK_T) { _mm256_aesenc_epi128(a.b0, _mm256_setzero_si256()),
                                 _mm256_aesenc_epi128(a.b1, _mm256_setzero_si256()) };
}

static inline void
AEGIS_update(AEGIS_AES_BLOCK_T *const state, const AEGIS_AES_BLOCK_T d)
{
    AEGIS_AES_BLOCK_T tmp;

    tmp      = state[5];
    state[5] = AEGIS_AES_ENC(state[4], state[5]);
    state[4] = AEGIS_AES_ENC(state[3], state[4]);
    state[3] = AEGIS_AES_ENC(state[2], state[3]);
    state[2] = AEGIS_AES_ENC(state[1], state[2]);
    state[1] = AEGIS_AES_ENC(state[0], state[1]);
    /* AESENC(x, k) is the same as AESENC(x, 0) XORed with k.
     * That lets this round start without waiting on the earlier XOR, and folds the two XORs into
     * one instruction. */
    state[0] = AEGIS_AES_BLOCK_XOR3(AEGIS_AES_ENC0(tmp), state[0], d);
}

#define AEGIS256X4_UPDATE_NODATA_DEFINED
static inline void
AEGIS_update_nodata(AEGIS_AES_BLOCK_T *const state)
{
    AEGIS_AES_BLOCK_T tmp;

    tmp      = state[5];
    state[5] = AEGIS_AES_ENC(state[4], state[5]);
    state[4] = AEGIS_AES_ENC(state[3], state[4]);
    state[3] = AEGIS_AES_ENC(state[2], state[3]);
    state[2] = AEGIS_AES_ENC(state[1], state[2]);
    state[1] = AEGIS_AES_ENC(state[0], state[1]);
    state[0] = AEGIS_AES_ENC(tmp, state[0]);
}

/* 32 vector registers: four blocks in flight pay off here. */
#if defined(__x86_64__) || defined(_M_AMD64)
#define AEGIS_UNROLL_X4 1
#endif
#define AEGIS_HAS_BLOCK_BROADCAST128

#include "aegis256x4_common.h"

AEGIS_API
struct aegis256x4_implementation aegis256x4_avx512vl_implementation = {
#include "../common/func_table.h"
};

#include "../common/type_names_undefine.h"
#include "../common/func_names_undefine.h"

#ifdef __clang__
#  pragma clang attribute pop
#endif

#endif /* HAVE_VAESINTRIN_H */

#endif
#endif
