/*
** Name:        aes_gcm.c
** Purpose:     AES-GCM building blocks
** Author:      Ulrich Telle
** Created:     2026-10-07
** Copyright:   (c) 2026 Ulrich Telle
** License:     MIT
*/

/*
** AES-GCM building blocks: XAES-256-GCM (as used by SQLCipher 5)
** --------------------------------------------------------------
**
** XAES-256-GCM (https://c2sp.org/XAES-256-GCM) extends AES-256-GCM with a
** 192-bit nonce: the first 96 bits of the nonce are used, together with the
** main key, to derive a one-time AES-256 key (CMAC-based key derivation),
** the last 96 bits are the GCM IV.
**
** API (all functions use the AES context AesCtx of aes_core.c):
**
**   sqlite3mcAesXaesInit(ctx, key)               main key (32 bytes)
**   sqlite3mcAesXaesInitImpl(ctx, key, impl)     explicit AES implementation
**   sqlite3mcAesXaesSeal(ctx, nonce, aad, aadLen, in, len, out, tag)
**   sqlite3mcAesXaesOpen(ctx, nonce, aad, aadLen, in, len, tag, out)
**   sqlite3mcAesXaesPageSeal(ctx, pgno, in, len, out, reserve)   SQLCipher 5 page
**   sqlite3mcAesXaesPageOpen(ctx, pgno, in, len, out, reserve)
**   sqlite3mcAesGhashGet(impl) / sqlite3mcAesGhashSelect(impl)   GHASH variants
**
** The main key context is an AesCtx that is set up for encryption only
** (AES_FOR_ENCRYPT); it holds the key schedule of the main key and the
** CMAC subkey K1 (AesCtx::m_k1, AesCtx::m_xaes). It is read-only during
** Seal/Open and can be shared by all pages. For every call a temporary
** AesCtx with the derived key is set up (same AES implementation as the
** main context) and wiped afterwards.
**
** All AES operations go through sqlite3mcAesEncryptBlocks(), so a backend
** with an optimized multi-block function (m_encryptBlocks) speeds up the
** counter mode. The counter blocks are processed AES_GCM_CTR_BLOCKS (8) at a
** time.
**
** Seal/Open work in place (in == out is allowed). Open verifies the tag
** before any plaintext is produced; on a mismatch the output buffer is
** zeroed and AES_GCM_TAG_MISMATCH is returned.
**
** Page layout (SQLCipher 5, default settings): the reserve area (48 bytes)
** at the end of each page contains nonce[24] | tag[16] | 8 spare bytes. The
** caller fills reserve[0..24) with random bytes before PageSeal and
** reserve[40..48) with random bytes afterwards. The additional authenticated
** data is the page number as 4 bytes in big-endian order. len is
** page size - 48 (page size - 48 - 16 on page 1, where the first 16 bytes of
** the database file hold the key salt and are not encrypted).
**
** GHASH variants (selected at run time, best available by default):
**   AES_GHASH_BITWISE  reference, slow
**   AES_GHASH_CTMUL64  portable, constant time (64-bit integer multiplications)
**   AES_GHASH_PCLMUL   x86 PCLMULQDQ (compiler intrinsics, no assembler)
**   AES_GHASH_PMULL    AArch64 PMULL (compiler intrinsics, no assembler)
** Compile-time options: SQLITE3MC_AES_NO_PCLMUL, SQLITE3MC_AES_NO_PMULL
** (both are implied by SQLITE3MC_OMIT_AES_HARDWARE_SUPPORT).
*/

#define AES_GCM_CTR_BLOCKS      8
#define AES_XAES_NONCE_SIZE     24
#define AES_XAES_TAG_SIZE       16
#define AES_XAES_RESERVE_SIZE   48
#define AES_GCM_TAG_MISMATCH    SQLITE_CORRUPT

/* GHASH implementation identifiers */
#define AES_GHASH_AUTO    0
#define AES_GHASH_BITWISE 1
#define AES_GHASH_CTMUL64 2
#define AES_GHASH_PCLMUL  3
#define AES_GHASH_PMULL   4

/*
** y <- GHASH update of y with nblocks full 16-byte blocks (h: hash key);
** y and h are in the usual big-endian GCM representation.
*/
typedef void (*AesGhashFn)(unsigned char y[16], const unsigned char h[16],
                           const unsigned char* data, size_t nblocks);

/*
** "Omit hardware support" also switches off the hardware GHASH variants
*/
#ifdef SQLITE3MC_OMIT_AES_HARDWARE_SUPPORT
# ifndef SQLITE3MC_AES_NO_PCLMUL
#  define SQLITE3MC_AES_NO_PCLMUL 1
# endif
# ifndef SQLITE3MC_AES_NO_PMULL
#  define SQLITE3MC_AES_NO_PMULL 1
# endif
#endif

#if defined(SQLITE3MC_TARGET_X86) && !defined(SQLITE3MC_AES_NO_PCLMUL)
#  define AES_GHASH_HAVE_PCLMUL 1
#  include <immintrin.h>
#  if defined(_MSC_VER) && !defined(__clang__)
#    define AES_GHASH_TARGET
#  else
#    define AES_GHASH_TARGET SQLITE3MC_FUNC_ISA("pclmul,ssse3,sse2")
#  endif
#endif

#if defined(SQLITE3MC_TARGET_ARM64) && (defined(__GNUC__) || defined(__clang__)) \
    && defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) \
    && !defined(SQLITE3MC_AES_NO_PMULL)
#  define AES_GHASH_HAVE_PMULL 1
#  include <arm_neon.h>
#  if defined(__clang__)
#    define AES_GHASH_TARGET_PMULL SQLITE3MC_FUNC_ISA("aes")
#  else
#    define AES_GHASH_TARGET_PMULL SQLITE3MC_FUNC_ISA("+crypto")
#  endif
#endif

static uint64_t aesGhLoad64be(const uint8_t *p)
{
  return ((uint64_t) p[0] << 56) | ((uint64_t) p[1] << 48) |
         ((uint64_t) p[2] << 40) | ((uint64_t) p[3] << 32) |
         ((uint64_t) p[4] << 24) | ((uint64_t) p[5] << 16) |
         ((uint64_t) p[6] << 8)  |  (uint64_t) p[7];
}

static void aesGhStore64be(uint8_t *p, uint64_t v)
{
  int i;
  for (i = 7; i >= 0; i--)
  {
    p[i] = (uint8_t) v; v >>= 8;
  }
}

/*
** 1. Bitwise reference (NIST SP 800-38D, Algorithm 1)
*/

static void aesGhashBitwise(uint8_t y[16], const uint8_t h[16],
                            const uint8_t *data, size_t nblocks)
{
  uint64_t yhi = aesGhLoad64be(y), ylo = aesGhLoad64be(y + 8);
  const uint64_t hhi = aesGhLoad64be(h), hlo = aesGhLoad64be(h + 8);

  while (nblocks--)
  {
    uint64_t xhi = yhi ^ aesGhLoad64be(data), xlo = ylo ^ aesGhLoad64be(data + 8);
    uint64_t zhi = 0, zlo = 0, vhi = hhi, vlo = hlo;
    int i;
    for (i = 0; i < 128; i++)
    {
      uint64_t bit = (i < 64) ? ((xhi >> (63 - i)) & 1) : ((xlo >> (127 - i)) & 1);
      uint64_t m = (uint64_t) 0 - bit;
      uint64_t carry = (uint64_t) 0 - (vlo & 1);
      zhi ^= vhi & m;
      zlo ^= vlo & m;
      vlo = (vlo >> 1) | (vhi << 63);
      vhi = (vhi >> 1) ^ (0xe100000000000000ULL & carry);
    }
    yhi = zhi;
    ylo = zlo;
    data += 16;
  }
  aesGhStore64be(y, yhi);
  aesGhStore64be(y + 8, ylo);
}

/*
** 2. Portable constant time variant (64-bit integer multiplications)
*/

/*
** Idea: a carry-less product can be computed with ordinary integer
** multiplications if the operands are split into 4 groups of bits that are
** 4 positions apart. Within a group the integer sums of partial products
** cannot overflow into the neighbouring bit position of the same group
** (at most 15 terms, 4 bit "holes"), so the lowest bit of each 4-bit field
** is the carry-less (XOR) sum. Only the low 64 bits of the product are
** obtained this way; the high 64 bits are obtained by bit-reversing the
** operands and the result.
**
** GCM represents the coefficient of x^0 as the most significant bit, so
** field elements are bit-reversed (128 bit) into the usual "x^i = bit i"
** form, multiplied as polynomials, reduced modulo x^128 + x^7 + x^2 + x + 1
** and reversed back.
*/

static uint64_t aesGhRev64(uint64_t x)
{
  x = ((x & 0x5555555555555555ULL) << 1) | ((x >> 1) & 0x5555555555555555ULL);
  x = ((x & 0x3333333333333333ULL) << 2) | ((x >> 2) & 0x3333333333333333ULL);
  x = ((x & 0x0f0f0f0f0f0f0f0fULL) << 4) | ((x >> 4) & 0x0f0f0f0f0f0f0f0fULL);
  x = ((x & 0x00ff00ff00ff00ffULL) << 8) | ((x >> 8) & 0x00ff00ff00ff00ffULL);
  x = ((x & 0x0000ffff0000ffffULL) << 16) | ((x >> 16) & 0x0000ffff0000ffffULL);
  return (x << 32) | (x >> 32);
}

/* low 64 bits of the carry-less product x*y */
static uint64_t aesGhBmul64(uint64_t x, uint64_t y)
{
  const uint64_t m0 = 0x1111111111111111ULL, m1 = 0x2222222222222222ULL,
                 m2 = 0x4444444444444444ULL, m3 = 0x8888888888888888ULL;
  uint64_t x0 = x & m0, x1 = x & m1, x2 = x & m2, x3 = x & m3;
  uint64_t y0 = y & m0, y1 = y & m1, y2 = y & m2, y3 = y & m3;
  uint64_t z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
  uint64_t z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
  uint64_t z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
  uint64_t z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
  return (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3);
}

/*
** full 128 bit carry-less product of a and b; ra, rb are the bit reversals
*/
static void aesGhClmul64(uint64_t a, uint64_t ra, uint64_t b, uint64_t rb,
                    uint64_t *lo, uint64_t *hi)
{
  *lo = aesGhBmul64(a, b);
  *hi = aesGhRev64(aesGhBmul64(ra, rb)) >> 1;
}

static void aesGhashCtmul64(uint8_t y[16], const uint8_t h[16],
                            const uint8_t *data, size_t nblocks)
{
  /* H in polynomial form: b0 = rev(W0), b1 = rev(W1); reversed images are W0, W1 */
  const uint64_t rb0 = aesGhLoad64be(h), rb1 = aesGhLoad64be(h + 8);
  const uint64_t b0 = aesGhRev64(rb0), b1 = aesGhRev64(rb1);
  const uint64_t bs = b0 ^ b1, rbs = rb0 ^ rb1;
  uint64_t w0 = aesGhLoad64be(y), w1 = aesGhLoad64be(y + 8);

  while (nblocks--)
  {
    uint64_t ra0, ra1, a0, a1, as, ras;
    uint64_t z0l, z0h, z2l, z2h, z1l, z1h;
    uint64_t p0, p1, p2, p3;
    uint64_t t0, t1, ov, f;
    uint64_t r0, r1;

    ra0 = w0 ^ aesGhLoad64be(data);
    ra1 = w1 ^ aesGhLoad64be(data + 8);
    a0 = aesGhRev64(ra0);
    a1 = aesGhRev64(ra1);
    as = a0 ^ a1;
    ras = ra0 ^ ra1;

    /* Karatsuba: three 64x64 -> 128 bit carry-less products */
    aesGhClmul64(a0, ra0, b0, rb0, &z0l, &z0h);
    aesGhClmul64(a1, ra1, b1, rb1, &z2l, &z2h);
    aesGhClmul64(as, ras, bs, rbs, &z1l, &z1h);
    z1l ^= z0l ^ z2l;
    z1h ^= z0h ^ z2h;

    p0 = z0l;
    p1 = z0h ^ z1l;
    p2 = z2l ^ z1h;
    p3 = z2h;

    /* reduce: (p3:p2) * x^128 = (p3:p2) * (x^7 + x^2 + x + 1) */
    t0 = p2 ^ (p2 << 1) ^ (p2 << 2) ^ (p2 << 7);
    t1 = p3 ^ ((p3 << 1) | (p2 >> 63)) ^ ((p3 << 2) | (p2 >> 62))
            ^ ((p3 << 7) | (p2 >> 57));
    ov = (p3 >> 63) ^ (p3 >> 62) ^ (p3 >> 57);     /* bits shifted out above x^127 */
    f = ov ^ (ov << 1) ^ (ov << 2) ^ (ov << 7);
    r0 = p0 ^ t0 ^ f;
    r1 = p1 ^ t1;

    w0 = aesGhRev64(r0);
    w1 = aesGhRev64(r1);
    data += 16;
  }
  aesGhStore64be(y, w0);
  aesGhStore64be(y + 8, w1);
}

/*
** 3. x86 PCLMULQDQ (compiler intrinsics, runtime detection)
*/

#ifdef AES_GHASH_HAVE_PCLMUL

static int aesGhHasPclmul(void)
{
  /* PCLMULQDQ for the multiplication, SSSE3 (pshufb) for the byte reversal */
  unsigned int need = SQLITE3MC_CPU_PCLMUL | SQLITE3MC_CPU_SSSE3;
  return (sqlite3mcCpuFeatures() & need) == need;
}

/*
** Operands are byte-reversed (so that the GCM bit order becomes the natural
** "reflected" order of the carry-less multiplier). The 255 bit product then
** needs a left shift by one bit before the reduction.
*/

AES_GHASH_TARGET
static __m128i aesGhBswap128(__m128i x)
{
  const __m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
  return _mm_shuffle_epi8(x, mask);
}

/*
** unreduced 256 bit carry-less product of a and b
*/
AES_GHASH_TARGET
static void aesGhClmul256(__m128i a, __m128i b, __m128i *lo, __m128i *hi)
{
  __m128i t0 = _mm_clmulepi64_si128(a, b, 0x00);
  __m128i t1 = _mm_clmulepi64_si128(a, b, 0x10);
  __m128i t2 = _mm_clmulepi64_si128(a, b, 0x01);
  __m128i t3 = _mm_clmulepi64_si128(a, b, 0x11);
  t1 = _mm_xor_si128(t1, t2);
  t2 = _mm_slli_si128(t1, 8);
  t1 = _mm_srli_si128(t1, 8);
  *lo = _mm_xor_si128(t0, t2);
  *hi = _mm_xor_si128(t3, t1);
}

/*
** shift the 256 bit value (hi:lo) left by one bit and reduce modulo
** x^128 + x^127 + x^126 + x^121 + 1 (reflected GCM polynomial)
*/
AES_GHASH_TARGET
static __m128i aesGhReduce256(__m128i lo, __m128i hi)
{
  __m128i t7, t8, t9, t2, t4, t5;

  t7 = _mm_srli_epi32(lo, 31);
  t8 = _mm_srli_epi32(hi, 31);
  lo = _mm_slli_epi32(lo, 1);
  hi = _mm_slli_epi32(hi, 1);
  t9 = _mm_srli_si128(t7, 12);
  t8 = _mm_slli_si128(t8, 4);
  t7 = _mm_slli_si128(t7, 4);
  lo = _mm_or_si128(lo, t7);
  hi = _mm_or_si128(hi, t8);
  hi = _mm_or_si128(hi, t9);

  t7 = _mm_slli_epi32(lo, 31);
  t8 = _mm_slli_epi32(lo, 30);
  t9 = _mm_slli_epi32(lo, 25);
  t7 = _mm_xor_si128(_mm_xor_si128(t7, t8), t9);
  t8 = _mm_srli_si128(t7, 4);
  t7 = _mm_slli_si128(t7, 12);
  lo = _mm_xor_si128(lo, t7);

  t2 = _mm_srli_epi32(lo, 1);
  t4 = _mm_srli_epi32(lo, 2);
  t5 = _mm_srli_epi32(lo, 7);
  t2 = _mm_xor_si128(_mm_xor_si128(t2, t4), _mm_xor_si128(t5, t8));
  lo = _mm_xor_si128(lo, t2);
  return _mm_xor_si128(hi, lo);
}

AES_GHASH_TARGET
static __m128i aesGhGfmul(__m128i a, __m128i b)
{
  __m128i lo, hi;
  aesGhClmul256(a, b, &lo, &hi);
  return aesGhReduce256(lo, hi);
}

AES_GHASH_TARGET
static void aesGhashPclmul(uint8_t y[16], const uint8_t h[16],
                           const uint8_t *data, size_t nblocks)
{
  __m128i h1 = aesGhBswap128(_mm_loadu_si128((const __m128i *) h));
  __m128i h2 = aesGhGfmul(h1, h1);
  __m128i h3 = aesGhGfmul(h2, h1);
  __m128i h4 = aesGhGfmul(h2, h2);
  __m128i acc = aesGhBswap128(_mm_loadu_si128((const __m128i *) y));

  /* aggregated reduction: four blocks per reduction */
  while (nblocks >= 4)
  {
    __m128i x0 = _mm_xor_si128(acc, aesGhBswap128(_mm_loadu_si128((const __m128i *) data)));
    __m128i x1 = aesGhBswap128(_mm_loadu_si128((const __m128i *) (data + 16)));
    __m128i x2 = aesGhBswap128(_mm_loadu_si128((const __m128i *) (data + 32)));
    __m128i x3 = aesGhBswap128(_mm_loadu_si128((const __m128i *) (data + 48)));
    __m128i l, hh, sl, sh;

    aesGhClmul256(x0, h4, &sl, &sh);
    aesGhClmul256(x1, h3, &l, &hh);
    sl = _mm_xor_si128(sl, l);
    sh = _mm_xor_si128(sh, hh);
    aesGhClmul256(x2, h2, &l, &hh);
    sl = _mm_xor_si128(sl, l);
    sh = _mm_xor_si128(sh, hh);
    aesGhClmul256(x3, h1, &l, &hh);
    sl = _mm_xor_si128(sl, l);
    sh = _mm_xor_si128(sh, hh);
    acc = aesGhReduce256(sl, sh);

    data += 64;
    nblocks -= 4;
  }
  while (nblocks--)
  {
    __m128i x = _mm_xor_si128(acc, aesGhBswap128(_mm_loadu_si128((const __m128i *) data)));
    acc = aesGhGfmul(x, h1);
    data += 16;
  }
  _mm_storeu_si128((__m128i *) y, aesGhBswap128(acc));
}

#endif /* AES_GHASH_HAVE_PCLMUL */

/*
** 4. AArch64 PMULL (NEON intrinsics, runtime detection)
*/

/*
** Same algorithm as the PCLMULQDQ variant (byte-reversed operands, 256 bit
** carry-less product, shift left by one bit, reduction), expressed with NEON
** operations: vmull_p64 / vmull_high_p64 for the 64x64 bit products, vext for
** whole-register byte shifts and 32 bit lane shifts.
** Little-endian AArch64 only. PMULL on 64 bit polynomials is the optional
** "PMULL" (FEAT_PMULL) part of the crypto extension.
*/

#ifdef AES_GHASH_HAVE_PMULL

static int aesGhHasPmull(void)
{
  return (sqlite3mcCpuFeatures() & SQLITE3MC_CPU_ARMPMULL) != 0;
}

/* whole-register byte shifts (like SSE2 _mm_slli_si128 / _mm_srli_si128) */
#define AES_GHASH_BSL(x, n) vextq_u8(vdupq_n_u8(0), (x), 16 - (n))
#define AES_GHASH_BSR(x, n) vextq_u8((x), vdupq_n_u8(0), (n))
#define AES_GHASH_SHL32(x, n) vreinterpretq_u8_u32(vshlq_n_u32(vreinterpretq_u32_u8(x), (n)))
#define AES_GHASH_SHR32(x, n) vreinterpretq_u8_u32(vshrq_n_u32(vreinterpretq_u32_u8(x), (n)))

AES_GHASH_TARGET_PMULL
static uint8x16_t aesGhPmullBswap128(uint8x16_t x)
{
  x = vrev64q_u8(x);          /* reverse bytes inside each 64 bit lane */
  return vextq_u8(x, x, 8);   /* swap the two lanes */
}

/* unreduced 256 bit carry-less product of a and b */
AES_GHASH_TARGET_PMULL
static void aesGhPmullClmul256(uint8x16_t a, uint8x16_t b, uint8x16_t *lo, uint8x16_t *hi)
{
  poly64x2_t pa = vreinterpretq_p64_u8(a), pb = vreinterpretq_p64_u8(b);
  poly64_t a0 = vgetq_lane_p64(pa, 0), a1 = vgetq_lane_p64(pa, 1);
  poly64_t b0 = vgetq_lane_p64(pb, 0), b1 = vgetq_lane_p64(pb, 1);
  uint8x16_t zero = vdupq_n_u8(0);
  uint8x16_t t0 = vreinterpretq_u8_p128(vmull_p64(a0, b0));
  uint8x16_t t1 = vreinterpretq_u8_p128(vmull_p64(a0, b1));
  uint8x16_t t2 = vreinterpretq_u8_p128(vmull_p64(a1, b0));
  uint8x16_t t3 = vreinterpretq_u8_p128(vmull_high_p64(pa, pb));
  t1 = veorq_u8(t1, t2);
  t2 = AES_GHASH_BSL(t1, 8);
  t1 = vextq_u8(t1, zero, 8);
  *lo = veorq_u8(t0, t2);
  *hi = veorq_u8(t3, t1);
}

AES_GHASH_TARGET_PMULL
static uint8x16_t aesGhPmullReduce256(uint8x16_t lo, uint8x16_t hi)
{
  uint8x16_t t2, t4, t5, t7, t8, t9;

  t7 = AES_GHASH_SHR32(lo, 31);
  t8 = AES_GHASH_SHR32(hi, 31);
  lo = AES_GHASH_SHL32(lo, 1);
  hi = AES_GHASH_SHL32(hi, 1);
  t9 = AES_GHASH_BSR(t7, 12);
  t8 = AES_GHASH_BSL(t8, 4);
  t7 = AES_GHASH_BSL(t7, 4);
  lo = vorrq_u8(lo, t7);
  hi = vorrq_u8(hi, t8);
  hi = vorrq_u8(hi, t9);

  t7 = AES_GHASH_SHL32(lo, 31);
  t8 = AES_GHASH_SHL32(lo, 30);
  t9 = AES_GHASH_SHL32(lo, 25);
  t7 = veorq_u8(veorq_u8(t7, t8), t9);
  t8 = AES_GHASH_BSR(t7, 4);
  t7 = AES_GHASH_BSL(t7, 12);
  lo = veorq_u8(lo, t7);

  t2 = AES_GHASH_SHR32(lo, 1);
  t4 = AES_GHASH_SHR32(lo, 2);
  t5 = AES_GHASH_SHR32(lo, 7);
  t2 = veorq_u8(veorq_u8(t2, t4), veorq_u8(t5, t8));
  lo = veorq_u8(lo, t2);
  return veorq_u8(hi, lo);
}

AES_GHASH_TARGET_PMULL
static uint8x16_t aesGhPmullGfmul(uint8x16_t a, uint8x16_t b)
{
  uint8x16_t lo, hi;
  aesGhPmullClmul256(a, b, &lo, &hi);
  return aesGhPmullReduce256(lo, hi);
}

AES_GHASH_TARGET_PMULL
static void aesGhashPmull(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t nblocks)
{
  uint8x16_t h1 = aesGhPmullBswap128(vld1q_u8(h));
  uint8x16_t h2 = aesGhPmullGfmul(h1, h1);
  uint8x16_t h3 = aesGhPmullGfmul(h2, h1);
  uint8x16_t h4 = aesGhPmullGfmul(h2, h2);
  uint8x16_t acc = aesGhPmullBswap128(vld1q_u8(y));

  /* aggregated reduction: four blocks per reduction */
  while (nblocks >= 4)
  {
    uint8x16_t x0 = veorq_u8(acc, aesGhPmullBswap128(vld1q_u8(data)));
    uint8x16_t x1 = aesGhPmullBswap128(vld1q_u8(data + 16));
    uint8x16_t x2 = aesGhPmullBswap128(vld1q_u8(data + 32));
    uint8x16_t x3 = aesGhPmullBswap128(vld1q_u8(data + 48));
    uint8x16_t l, hh, sl, sh;

    aesGhPmullClmul256(x0, h4, &sl, &sh);
    aesGhPmullClmul256(x1, h3, &l, &hh);
    sl = veorq_u8(sl, l);
    sh = veorq_u8(sh, hh);
    aesGhPmullClmul256(x2, h2, &l, &hh);
    sl = veorq_u8(sl, l);
    sh = veorq_u8(sh, hh);
    aesGhPmullClmul256(x3, h1, &l, &hh);
    sl = veorq_u8(sl, l);
    sh = veorq_u8(sh, hh);
    acc = aesGhPmullReduce256(sl, sh);

    data += 64;
    nblocks -= 4;
  }
  while (nblocks--)
  {
    uint8x16_t x = veorq_u8(acc, aesGhPmullBswap128(vld1q_u8(data)));
    acc = aesGhPmullGfmul(x, h1);
    data += 16;
  }
  vst1q_u8(y, aesGhPmullBswap128(acc));
}

#endif /* AES_GHASH_HAVE_PMULL */

/*
** Dispatch
*/

SQLITE_PRIVATE AesGhashFn
sqlite3mcAesGhashGet(int impl)
{
  switch (impl) {
    case AES_GHASH_BITWISE: return aesGhashBitwise;
    case AES_GHASH_CTMUL64: return aesGhashCtmul64;
    case AES_GHASH_PCLMUL:
#ifdef AES_GHASH_HAVE_PCLMUL
      return aesGhHasPclmul() ? aesGhashPclmul : NULL;
#else
      return NULL;
#endif
    case AES_GHASH_PMULL:
#ifdef AES_GHASH_HAVE_PMULL
      return aesGhHasPmull() ? aesGhashPmull : NULL;
#else
      return NULL;
#endif
    case AES_GHASH_AUTO:
    default: {
      AesGhashFn f = sqlite3mcAesGhashGet(AES_GHASH_PCLMUL);
      if (!f) f = sqlite3mcAesGhashGet(AES_GHASH_PMULL);
      return f ? f : aesGhashCtmul64;
    }
  }
}

/*
** Not synchronised: select the implementation once at start-up.
** Concurrent lazy initialisation stores the same pointer value,
** so it is benign in practice (formally a data race).
*/
static AesGhashFn aesGhashCurrentFn = NULL;

static AesGhashFn
aesGhashCurrent(void)
{
  AesGhashFn f = aesGhashCurrentFn;
  if (!f)
  {
    f = sqlite3mcAesGhashGet(AES_GHASH_AUTO);
    aesGhashCurrentFn = f;
  }
  return f;
}

SQLITE_PRIVATE int
sqlite3mcAesGhashSelect(int impl)
{
  AesGhashFn f = sqlite3mcAesGhashGet(impl);
  if (!f) return -1;
  aesGhashCurrentFn = f;
  return 0;
}

/*
** XAES-256-GCM and AES-256-GCM
** ----------------------------
*/

static void
aesGcmCounterBlock(unsigned char ctr[16], const unsigned char iv[12], uint32_t c)
{
  memcpy(ctr, iv, 12);
  ctr[12] = (unsigned char) (c >> 24);
  ctr[13] = (unsigned char) (c >> 16);
  ctr[14] = (unsigned char) (c >> 8);
  ctr[15] = (unsigned char) c;
}

/*
** CTR keystream starting with the counter value 2 (counter 1 is used for the
** tag). The counter blocks are collected in a buffer of AES_GCM_CTR_BLOCKS
** blocks and encrypted with one call of sqlite3mcAesEncryptBlocks().
*/
static int
aesGcmCtrXor(const AesCtx* aes, const unsigned char iv[12], const unsigned char* in, size_t len, unsigned char* out)
{
  unsigned char ctr[16 * AES_GCM_CTR_BLOCKS];
  unsigned char ks[16 * AES_GCM_CTR_BLOCKS];
  uint32_t c = 2;
  size_t off = 0;
  int rc = SQLITE_OK;

  while (off < len && rc == SQLITE_OK)
  {
    size_t remain = len - off;
    size_t nblk = (remain + 15) / 16;
    size_t n, i, j;
    if (nblk > AES_GCM_CTR_BLOCKS)
    {
      nblk = AES_GCM_CTR_BLOCKS;
    }
    for (j = 0; j < nblk; j++)
    {
      aesGcmCounterBlock(ctr + 16 * j, iv, c + (uint32_t) j);
    }
    c += (uint32_t) nblk;
    rc = sqlite3mcAesEncryptBlocks(aes, ctr, ks, nblk);
    if (rc == SQLITE_OK)
    {
      n = (remain < nblk * 16) ? remain : nblk * 16;
      for (i = 0; i < n; i++)
      {
        out[off + i] = (unsigned char) (in[off + i] ^ ks[i]);
      }
      off += n;
    }
  }
  sqlite3mcSecureZeroMemory(ctr, sizeof(ctr));
  sqlite3mcSecureZeroMemory(ks, sizeof(ks));
  return rc;
}

/*
** y = GHASH-update(y, data); a trailing partial block is zero padded
*/
static void
aesGcmGhashData(AesGhashFn f, unsigned char y[16], const unsigned char h[16], const unsigned char* data, size_t len)
{
  size_t nb = len / 16;
  size_t rem = len % 16;
  if (nb > 0)
  {
    f(y, h, data, nb);
  }
  if (rem > 0)
  {
    unsigned char blk[16];
    memset(blk, 0, sizeof(blk));
    memcpy(blk, data + nb * 16, rem);
    f(y, h, blk, 1);
  }
}

static int
aesGcmTag(const AesCtx* aes, const unsigned char iv[12], const unsigned char* aad, size_t aadLen,
          const unsigned char* ct, size_t ctLen, unsigned char tag[16])
{
  AesGhashFn ghash = aesGhashCurrent();
  unsigned char blk[32];
  unsigned char enc[32];
  unsigned char lenblk[16];
  unsigned char y[16];
  const unsigned char* h = enc;        /* H     = E_K(0^128)           */
  const unsigned char* ek = enc + 16;  /* E(J0) = E_K(IV || 0^31 || 1) */
  int i;
  int rc;

  memset(blk, 0, 16);
  aesGcmCounterBlock(blk + 16, iv, 1);
  rc = sqlite3mcAesEncryptBlocks(aes, blk, enc, 2);
  if (rc == SQLITE_OK)
  {
    memset(y, 0, sizeof(y));
    aesGcmGhashData(ghash, y, h, aad, aadLen);
    aesGcmGhashData(ghash, y, h, ct, ctLen);
    aesGhStore64be(lenblk, (uint64_t) aadLen * 8);
    aesGhStore64be(lenblk + 8, (uint64_t) ctLen * 8);
    ghash(y, h, lenblk, 1);
    for (i = 0; i < 16; i++)
    {
      tag[i] = (unsigned char) (ek[i] ^ y[i]);
    }
  }
  sqlite3mcSecureZeroMemory(enc, sizeof(enc));
  sqlite3mcSecureZeroMemory(y, sizeof(y));
  return rc;
}

/*
** Set up the main key context for XAES-256-GCM: key schedule (encryption
** direction) plus the CMAC subkey K1 = (E_K(0^128) << 1) [xor 0x87].
**
** key points to 32 bytes. impl: AES_IMPL_AUTO or an explicit implementation.
** Returns SQLITE_OK or the error code of sqlite3mcAesCbcInitImpl().
*/
SQLITE_PRIVATE int
sqlite3mcAesXaesInitImpl(AesCtx* ctx, const unsigned char* key, int impl)
{
  unsigned char zero[16];
  unsigned char l[16];
  int i;
  int msb;
  int rc = sqlite3mcAesCbcInitImpl(ctx, key, 32, AES_FOR_ENCRYPT, impl);
  if (rc != SQLITE_OK)
  {
    return rc;
  }
  memset(zero, 0, sizeof(zero));
  rc = sqlite3mcAesEncryptBlocks(ctx, zero, l, 1);
  if (rc != SQLITE_OK)
  {
    sqlite3mcAesCbcWipe(ctx);
    return rc;
  }
  msb = l[0] >> 7;
  for (i = 0; i < 15; i++)
  {
    ctx->m_k1[i] = (unsigned char) ((l[i] << 1) | (l[i + 1] >> 7));
  }
  ctx->m_k1[15] = (unsigned char) ((l[15] << 1) ^ (0x87 & -msb));
  ctx->m_xaes = 1;
  sqlite3mcSecureZeroMemory(l, sizeof(l));
  return SQLITE_OK;
}

SQLITE_PRIVATE int
sqlite3mcAesXaesInit(AesCtx* ctx, const unsigned char* key)
{
  return sqlite3mcAesXaesInitImpl(ctx, key, AES_IMPL_AUTO);
}

/*
** Derive the one-time AES-256 key and the GCM IV for a nonce:
**   subkey = AES(M1 xor K1) || AES(M2 xor K1),  Mi = 00 || i || 'X' || 00 || N[0..12)
**   iv     = N[12..24)
** and set up a temporary context for the subkey (same implementation as the
** main context). The caller must wipe the context.
*/
static int
aesXaesDerive(const AesCtx* mainCtx, const unsigned char nonce[24], AesCtx* subCtx, unsigned char iv[12])
{
  unsigned char m[32];
  unsigned char subkey[32];
  int n;
  int i;
  int rc;

  for (n = 0; n < 2; n++)
  {
    unsigned char* mi = m + 16 * n;
    mi[0] = 0x00;
    mi[1] = (unsigned char) (n + 1);
    mi[2] = 0x58;
    mi[3] = 0x00;
    memcpy(mi + 4, nonce, 12);
    for (i = 0; i < 16; i++)
    {
      mi[i] ^= mainCtx->m_k1[i];
    }
  }
  rc = sqlite3mcAesEncryptBlocks(mainCtx, m, subkey, 2);
  if (rc == SQLITE_OK)
  {
    rc = sqlite3mcAesCbcInitImpl(subCtx, subkey, 32, AES_FOR_ENCRYPT, mainCtx->m_impl->m_id);
    memcpy(iv, nonce + 12, 12);
  }
  sqlite3mcSecureZeroMemory(m, sizeof(m));
  sqlite3mcSecureZeroMemory(subkey, sizeof(subkey));
  return rc;
}

/*
** XAES-256-GCM encryption: nonce is 24 bytes, tag 16 bytes.
** Returns SQLITE_OK, SQLITE_MISUSE if ctx is not a main key context set up
** with sqlite3mcAesXaesInit(), or an error code of the AES backend.
*/
SQLITE_PRIVATE int
sqlite3mcAesXaesSeal(const AesCtx* mainCtx, const unsigned char nonce[24],
                     const unsigned char* aad, size_t aadLen,
                     const unsigned char* in, size_t len,
                     unsigned char* out, unsigned char tag[16])
{
  AesCtx subCtx;
  unsigned char iv[12];
  int rc;

  if (mainCtx->m_impl == NULL || !mainCtx->m_xaes)
  {
    return SQLITE_MISUSE;
  }
  rc = aesXaesDerive(mainCtx, nonce, &subCtx, iv);
  if (rc == SQLITE_OK)
  {
    rc = aesGcmCtrXor(&subCtx, iv, in, len, out);
  }
  if (rc == SQLITE_OK)
  {
    rc = aesGcmTag(&subCtx, iv, aad, aadLen, out, len, tag);
  }
  sqlite3mcAesCbcWipe(&subCtx);
  return rc;
}

/*
** XAES-256-GCM decryption. The tag is verified before the plaintext is produced.
** Returns SQLITE_OK, AES_GCM_TAG_MISMATCH (out is zeroed), SQLITE_MISUSE
** or an error code of the AES backend.
*/
SQLITE_PRIVATE int
sqlite3mcAesXaesOpen(const AesCtx* mainCtx, const unsigned char nonce[24],
                     const unsigned char* aad, size_t aadLen,
                     const unsigned char* in, size_t len, const unsigned char tag[16],
                     unsigned char* out)
{
  AesCtx subCtx;
  unsigned char iv[12];
  unsigned char calc[16];
  unsigned char diff = 0;
  int i;
  int rc;

  if (mainCtx->m_impl == NULL || !mainCtx->m_xaes)
  {
    return SQLITE_MISUSE;
  }
  rc = aesXaesDerive(mainCtx, nonce, &subCtx, iv);
  if (rc == SQLITE_OK)
  {
    rc = aesGcmTag(&subCtx, iv, aad, aadLen, in, len, calc);
  }
  if (rc == SQLITE_OK)
  {
    for (i = 0; i < 16; i++)
    {
      diff |= (unsigned char) (calc[i] ^ tag[i]);
    }
    if (diff != 0)
    {
      if (len > 0)
      {
        memset(out, 0, len);
      }
      rc = AES_GCM_TAG_MISMATCH;
    }
    else
    {
      rc = aesGcmCtrXor(&subCtx, iv, in, len, out);
    }
  }
  sqlite3mcAesCbcWipe(&subCtx);
  return rc;
}

static void
aesXaesPageAad(unsigned char aad[4], uint32_t pgno)
{
  aad[0] = (unsigned char) (pgno >> 24);
  aad[1] = (unsigned char) (pgno >> 16);
  aad[2] = (unsigned char) (pgno >> 8);
  aad[3] = (unsigned char) pgno;
}

/*
** Encrypt a database page (SQLCipher 5 layout, see above). reserve[0..24)
** must contain the random nonce; the tag is written to reserve[24..40).
*/
SQLITE_PRIVATE int
sqlite3mcAesXaesPageSeal(const AesCtx* mainCtx, uint32_t pgno, const unsigned char* in, size_t len,
                         unsigned char* out, unsigned char reserve[AES_XAES_RESERVE_SIZE])
{
  unsigned char aad[4];
  aesXaesPageAad(aad, pgno);
  return sqlite3mcAesXaesSeal(mainCtx, reserve, aad, sizeof(aad), in, len, out, reserve + AES_XAES_NONCE_SIZE);
}

/*
** Decrypt and authenticate a database page. Returns SQLITE_OK or
** AES_GCM_TAG_MISMATCH (wrong key, wrong page number or damaged page).
*/
SQLITE_PRIVATE int
sqlite3mcAesXaesPageOpen(const AesCtx* mainCtx, uint32_t pgno, const unsigned char* in, size_t len,
                         unsigned char* out, const unsigned char reserve[AES_XAES_RESERVE_SIZE])
{
  unsigned char aad[4];
  aesXaesPageAad(aad, pgno);
  return sqlite3mcAesXaesOpen(mainCtx, reserve, aad, sizeof(aad), in, len, reserve + AES_XAES_NONCE_SIZE, out);
}
