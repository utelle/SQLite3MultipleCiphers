/*
** Name:        inner.h
** Purpose:     Minimal replacement for BearSSL's internal header "inner.h"
** License:     MIT
*/

/*
** This header provides only what the unmodified BearSSL files aes_ct64.c,
** aes_ct64_enc.c and aes_ct64_dec.c need. All functions are declared
** static: the BearSSL files define them without a storage-class specifier,
** so they inherit internal linkage from these declarations (C99 6.2.2)
** and do not clash with other code when linked.
*/

#ifndef SQLITE3MC_BEARSSL_INNER_H_
#define SQLITE3MC_BEARSSL_INNER_H_

#include <stddef.h>
#include <string.h>
#include "../mystdint.h"

/* Little-endian decoding and encoding of 32-bit words */

static uint32_t
br_dec32le(const void* src)
{
  const unsigned char* buf = (const unsigned char*) src;
  return (uint32_t) buf[0]
       | ((uint32_t) buf[1] << 8)
       | ((uint32_t) buf[2] << 16)
       | ((uint32_t) buf[3] << 24);
}

static void
br_enc32le(void* dst, uint32_t x)
{
  unsigned char* buf = (unsigned char*) dst;
  buf[0] = (unsigned char) x;
  buf[1] = (unsigned char) (x >> 8);
  buf[2] = (unsigned char) (x >> 16);
  buf[3] = (unsigned char) (x >> 24);
}

static void
br_range_dec32le(uint32_t* v, size_t num, const void* src)
{
  const unsigned char* buf = (const unsigned char*) src;
  while (num-- > 0)
  {
    *v++ = br_dec32le(buf);
    buf += 4;
  }
}

static void
br_range_enc32le(void* dst, const uint32_t* v, size_t num)
{
  unsigned char* buf = (unsigned char*) dst;
  while (num-- > 0)
  {
    br_enc32le(buf, *v++);
    buf += 4;
  }
}

/* Bitsliced constant-time AES on 64-bit words (see the BearSSL sources) */

static void br_aes_ct64_ortho(uint64_t* q);
static void br_aes_ct64_interleave_in(uint64_t* q0, uint64_t* q1, const uint32_t* w);
static void br_aes_ct64_interleave_out(uint32_t* w, uint64_t q0, uint64_t q1);
static void br_aes_ct64_bitslice_Sbox(uint64_t* q);
static void br_aes_ct64_bitslice_invSbox(uint64_t* q);
static void br_aes_ct64_bitslice_encrypt(unsigned num_rounds, const uint64_t* skey, uint64_t* q);
static void br_aes_ct64_bitslice_decrypt(unsigned num_rounds, const uint64_t* skey, uint64_t* q);
static unsigned br_aes_ct64_keysched(uint64_t* comp_skey, const void* key, size_t key_len);
static void br_aes_ct64_skey_expand(uint64_t* skey, unsigned num_rounds, const uint64_t* comp_skey);

#endif /* SQLITE3MC_BEARSSL_INNER_H_ */
