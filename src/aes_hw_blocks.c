/*
** Name:        aes_hw_blocks.c
** Purpose:     AES algorithms based on AES NI
** Author:      Ulrich Telle
** Created:     2026-02-16
** Copyright:   (c) 2026 Ulrich Telle
** License:     MIT
*/

/*
** AES multi-block encryption (ECB) with hardware instructions
** -----------------------------------------------------------
**
**   sqlite3mcAesHwEncryptBlocks(in, out, nblocks, roundKeys, rounds)
**
** Encrypts nblocks independent 16-byte blocks (in == out is allowed) with
** AES-NI (x86, x86-64) or the ARMv8 crypto extension (AArch64). Eight blocks
** are processed in an interleaved fashion to hide the latency of the AES
** instructions; counter modes (AES-GCM) are the main user.
**
** roundKeys points to the expanded encryption key in the standard layout of
** FIPS 197: (rounds + 1) round keys of 16 bytes each, round key 0 first
** (176 / 208 / 240 bytes for AES-128 / AES-192 / AES-256, rounds = 10 / 12 / 14).
** This is the layout produced by the key expansion of the hardware backend
** and consumed by its CBC functions, as far as these use the same layout.
**
** The caller must have checked at run time that the instructions exist
** (aesHardwareAvailable()); this file does not do any CPU detection.
**
** The code is selected with the macros of hwcheck.c (HAS_AES_HARDWARE, USE_ARM64_NEON_H,
** SQLITE3MC_FUNC_ISA), which must precede this file. The macro AES_HW_BLOCKS_AVAILABLE
** is defined if the function is compiled in (AES-NI, or AArch64 with the crypto extension).
** On other platforms (for example 32-bit ARM) it is not defined, and the generic
** block-by-block function of aes_core.c is used.
**
** The functions use compiler intrinsics with function level target
** attributes (GCC/Clang) and do not need assembler or global compiler flags.
*/

#if defined(HAS_AES_HARDWARE) && !defined(SQLITE3MC_AES_NO_HW_BLOCKS)
#  if HAS_AES_HARDWARE == AES_HARDWARE_NI
#    define AES_HW_BLOCKS_AVAILABLE 1
#    define AES_HW_BLOCKS_NI 1
#    if defined(_MSC_VER) && !defined(__clang__)
#      include <intrin.h>
#    endif
#    include <immintrin.h>
#    define AES_HW_TARGET SQLITE3MC_FUNC_ISA("aes,sse2")
#  elif HAS_AES_HARDWARE == AES_HARDWARE_NEON \
        && (defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC))
#    define AES_HW_BLOCKS_AVAILABLE 1
#    define AES_HW_BLOCKS_NEON 1
#    if defined(USE_ARM64_NEON_H)
#      include <arm64_neon.h>
#    else
#      include <arm_neon.h>
#    endif
#    if defined(__clang__)
#      define AES_HW_TARGET SQLITE3MC_FUNC_ISA("aes")
#    elif defined(__GNUC__)
#      define AES_HW_TARGET SQLITE3MC_FUNC_ISA("+crypto")
#    else
#      define AES_HW_TARGET
#    endif
#  endif
#endif

#ifdef AES_HW_BLOCKS_NI

AES_HW_TARGET SQLITE_PRIVATE int
sqlite3mcAesHwEncryptBlocks(const unsigned char* in, unsigned char* out, size_t nblocks,
                            const unsigned char* rk, int rounds)
{
  int r;
  while (nblocks >= 8)
  {
    __m128i k = _mm_loadu_si128((const __m128i*) rk);
    __m128i b0 = _mm_xor_si128(_mm_loadu_si128((const __m128i*) (in)), k);
    __m128i b1 = _mm_xor_si128(_mm_loadu_si128((const __m128i*) (in + 16)), k);
    __m128i b2 = _mm_xor_si128(_mm_loadu_si128((const __m128i*) (in + 32)), k);
    __m128i b3 = _mm_xor_si128(_mm_loadu_si128((const __m128i*) (in + 48)), k);
    __m128i b4 = _mm_xor_si128(_mm_loadu_si128((const __m128i*) (in + 64)), k);
    __m128i b5 = _mm_xor_si128(_mm_loadu_si128((const __m128i*) (in + 80)), k);
    __m128i b6 = _mm_xor_si128(_mm_loadu_si128((const __m128i*) (in + 96)), k);
    __m128i b7 = _mm_xor_si128(_mm_loadu_si128((const __m128i*) (in + 112)), k);
    for (r = 1; r < rounds; r++)
    {
      k = _mm_loadu_si128((const __m128i*) (rk + 16 * r));
      b0 = _mm_aesenc_si128(b0, k);
      b1 = _mm_aesenc_si128(b1, k);
      b2 = _mm_aesenc_si128(b2, k);
      b3 = _mm_aesenc_si128(b3, k);
      b4 = _mm_aesenc_si128(b4, k);
      b5 = _mm_aesenc_si128(b5, k);
      b6 = _mm_aesenc_si128(b6, k);
      b7 = _mm_aesenc_si128(b7, k);
    }
    k = _mm_loadu_si128((const __m128i*) (rk + 16 * rounds));
    _mm_storeu_si128((__m128i*) (out), _mm_aesenclast_si128(b0, k));
    _mm_storeu_si128((__m128i*) (out + 16), _mm_aesenclast_si128(b1, k));
    _mm_storeu_si128((__m128i*) (out + 32), _mm_aesenclast_si128(b2, k));
    _mm_storeu_si128((__m128i*) (out + 48), _mm_aesenclast_si128(b3, k));
    _mm_storeu_si128((__m128i*) (out + 64), _mm_aesenclast_si128(b4, k));
    _mm_storeu_si128((__m128i*) (out + 80), _mm_aesenclast_si128(b5, k));
    _mm_storeu_si128((__m128i*) (out + 96), _mm_aesenclast_si128(b6, k));
    _mm_storeu_si128((__m128i*) (out + 112), _mm_aesenclast_si128(b7, k));
    in += 128;
    out += 128;
    nblocks -= 8;
  }
  while (nblocks > 0)
  {
    __m128i b = _mm_xor_si128(_mm_loadu_si128((const __m128i*) in), _mm_loadu_si128((const __m128i*) rk));
    for (r = 1; r < rounds; r++)
    {
      b = _mm_aesenc_si128(b, _mm_loadu_si128((const __m128i*) (rk + 16 * r)));
    }
    b = _mm_aesenclast_si128(b, _mm_loadu_si128((const __m128i*) (rk + 16 * rounds)));
    _mm_storeu_si128((__m128i*) out, b);
    in += 16;
    out += 16;
    nblocks--;
  }
  return 0;
}

#endif /* AES_HW_BLOCKS_NI */

#ifdef AES_HW_BLOCKS_NEON

/*
** AESE performs AddRoundKey (XOR) followed by SubBytes and ShiftRows, AESMC
** performs MixColumns. Rounds 0 .. rounds-2 are AESE+AESMC, the last but one
** is only AESE, followed by the XOR with the final round key.
*/
AES_HW_TARGET SQLITE_PRIVATE int
sqlite3mcAesHwEncryptBlocks(const unsigned char* in, unsigned char* out, size_t nblocks,
                            const unsigned char* rk, int rounds)
{
  int r;
  while (nblocks >= 8)
  {
    uint8x16_t b0 = vld1q_u8(in);
    uint8x16_t b1 = vld1q_u8(in + 16);
    uint8x16_t b2 = vld1q_u8(in + 32);
    uint8x16_t b3 = vld1q_u8(in + 48);
    uint8x16_t b4 = vld1q_u8(in + 64);
    uint8x16_t b5 = vld1q_u8(in + 80);
    uint8x16_t b6 = vld1q_u8(in + 96);
    uint8x16_t b7 = vld1q_u8(in + 112);
    uint8x16_t k;
    for (r = 0; r < rounds - 1; r++)
    {
      k = vld1q_u8(rk + 16 * r);
      b0 = vaesmcq_u8(vaeseq_u8(b0, k));
      b1 = vaesmcq_u8(vaeseq_u8(b1, k));
      b2 = vaesmcq_u8(vaeseq_u8(b2, k));
      b3 = vaesmcq_u8(vaeseq_u8(b3, k));
      b4 = vaesmcq_u8(vaeseq_u8(b4, k));
      b5 = vaesmcq_u8(vaeseq_u8(b5, k));
      b6 = vaesmcq_u8(vaeseq_u8(b6, k));
      b7 = vaesmcq_u8(vaeseq_u8(b7, k));
    }
    k = vld1q_u8(rk + 16 * (rounds - 1));
    b0 = vaeseq_u8(b0, k);
    b1 = vaeseq_u8(b1, k);
    b2 = vaeseq_u8(b2, k);
    b3 = vaeseq_u8(b3, k);
    b4 = vaeseq_u8(b4, k);
    b5 = vaeseq_u8(b5, k);
    b6 = vaeseq_u8(b6, k);
    b7 = vaeseq_u8(b7, k);
    k = vld1q_u8(rk + 16 * rounds);
    vst1q_u8(out, veorq_u8(b0, k));
    vst1q_u8(out + 16, veorq_u8(b1, k));
    vst1q_u8(out + 32, veorq_u8(b2, k));
    vst1q_u8(out + 48, veorq_u8(b3, k));
    vst1q_u8(out + 64, veorq_u8(b4, k));
    vst1q_u8(out + 80, veorq_u8(b5, k));
    vst1q_u8(out + 96, veorq_u8(b6, k));
    vst1q_u8(out + 112, veorq_u8(b7, k));
    in += 128;
    out += 128;
    nblocks -= 8;
  }
  while (nblocks > 0)
  {
    uint8x16_t b = vld1q_u8(in);
    for (r = 0; r < rounds - 1; r++)
    {
      b = vaesmcq_u8(vaeseq_u8(b, vld1q_u8(rk + 16 * r)));
    }
    b = vaeseq_u8(b, vld1q_u8(rk + 16 * (rounds - 1)));
    vst1q_u8(out, veorq_u8(b, vld1q_u8(rk + 16 * rounds)));
    in += 16;
    out += 16;
    nblocks--;
  }
  return 0;
}

#endif /* AES_HW_BLOCKS_NEON */
