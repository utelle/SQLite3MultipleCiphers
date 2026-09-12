
#include "onetimeauth_poly1305.h"
#include "private/common.h"

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64)) && !defined(HAVE_TI_MODE)

#include <intrin.h>

typedef struct {
  uint64_t lo;
  uint64_t hi;
} uint128_t;

static __forceinline uint128_t
u128_mul(uint64_t x, uint64_t y)
{
  uint128_t r;
#if defined(_M_X64)
  r.lo = _umul128(x, y, &r.hi);
#else /* _M_ARM64 */
  r.hi = __umulh(x, y);
  r.lo = x * y;
#endif
  return r;
}

static __forceinline uint64_t
addc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out)
{
  uint64_t sum = a + carry_in;
  uint64_t c1 = (sum < a);
  sum += b;
  uint64_t c2 = (sum < b);
  *carry_out = c1 | c2;
  return sum;
}

static __forceinline uint128_t
u128_add(uint128_t a, uint128_t b)
{
  uint128_t r;
  uint64_t  carry;
  r.lo = addc64(a.lo, b.lo, 0, &carry);
  r.hi = addc64(a.hi, b.hi, carry, &carry);
  return r;
}

static __forceinline uint128_t
u128_addlo(uint128_t a, uint64_t b)
{
  uint128_t r;
  uint64_t  carry;
  r.lo = addc64(a.lo, b, 0, &carry);
  r.hi = addc64(a.hi, 0, carry, &carry);
  return r;
}

static __forceinline uint64_t
u128_lo(uint128_t v) { return v.lo; }

static __forceinline uint64_t
u128_shr(uint128_t v, int shift)
{
  if (shift == 0)  return v.lo;
  if (shift < 64)  return (v.lo >> shift) | (v.hi << (64 - shift));
  return v.hi >> (shift - 64);
}

#define SODIUM_MUL(out, x, y) out = u128_mul((uint64_t) (x), (uint64_t) (y))
#define SODIUM_ADD(out, in)   out = u128_add((out), (in))
#define SODIUM_ADDLO(out, in) out = u128_addlo((out), (uint64_t) (in))
#define SODIUM_SHR(in, shift) u128_shr((in), (shift))
#define SODIUM_LO(in)         u128_lo(in)

#define SQLITE3MC_POLY1305_HAVE_128BIT 1

#endif

#include "donna/poly1305_donna.c"
#if defined(SQLITE3MC_TARGET_X86)
/*
#if defined(HAVE_TI_MODE) && defined(HAVE_EMMINTRIN_H)
*/

#include "sse2/poly1305_sse2.c"

/*
#endif
*/
#endif
