/*
** Name:        libaegis.c
** Purpose:     Amalgamation of the AEGIS library
** Copyright:   (c) 2024-2026 Ulrich Telle
** SPDX-License-Identifier: MIT
*/

/*
** AEGIS library source code
*/

#ifndef AEGIS_API
#define AEGIS_API
#endif
#ifndef AEGIS_PRIVATE
#define AEGIS_PRIVATE static
#endif

/* Namespacing to avoid conflicts with libsodium 1.0.21+ */

/* Base Implementation Structs */
#define aegis128l_implementation             sqlite3mc_aegis128l_implementation
#define aegis128lx2_implementation           sqlite3mc_aegis128lx2_implementation
#define aegis128lx4_implementation           sqlite3mc_aegis128lx4_implementation
#define aegis256_implementation              sqlite3mc_aegis256_implementation
#define aegis256x2_implementation            sqlite3mc_aegis256x2_implementation
#define aegis256x4_implementation            sqlite3mc_aegis256x4_implementation

/* Variants without hardware acceleration */
#define aegis128l_soft_implementation        sqlite3mc_aegis128l_soft_implementation
#define aegis128x2_soft_implementation       sqlite3mc_aegis128x2_soft_implementation
#define aegis128x4_soft_implementation       sqlite3mc_aegis128x4_soft_implementation
#define aegis256_soft_implementation         sqlite3mc_aegis256_soft_implementation
#define aegis256x2_soft_implementation       sqlite3mc_aegis256x2_soft_implementation
#define aegis256x4_soft_implementation       sqlite3mc_aegis256x4_soft_implementation

#define softaes_block_encrypt                sqlite3mc_softaes_block_encrypt

/* Variants with support for AES and AVX instruction sets */
#define aegis128l_aesni_implementation       sqlite3mc_aegis128l_aesni_implementation
#define aegis128x2_aesni_implementation      sqlite3mc_aegis128x2_aesni_implementation
#define aegis128x4_aesni_implementation      sqlite3mc_aegis128x4_aesni_implementation
#define aegis256_aesni_implementation        sqlite3mc_aegis256_aesni_implementation
#define aegis256x2_aesni_implementation      sqlite3mc_aegis256x2_aesni_implementation
#define aegis256x4_aesni_implementation      sqlite3mc_aegis256x4_aesni_implementation

/* Variants with support for VAES and AVX2 instruction sets */
#define aegis128x2_avx2_implementation       sqlite3mc_aegis128x2_avx2_implementation
#define aegis128x4_avx2_implementation       sqlite3mc_aegis128x4_avx2_implementation
#define aegis256x2_avx2_implementation       sqlite3mc_aegis256x2_avx2_implementation
#define aegis256x4_avx2_implementation       sqlite3mc_aegis256x4_avx2_implementation

/* Variants with support for AVX512F instruction sets */
#define aegis128x4_avx512_implementation     sqlite3mc_aegis128x4_avx512_implementation
#define aegis256x4_avx512_implementation     sqlite3mc_aegis256x4_avx512_implementation

/* Variants with support for AltiVec instruction sets */
#define aegis128l_altivec_implementation     sqlite3mc_aegis128l_altivec_implementation
#define aegis128x2_altivec_implementation    sqlite3mc_aegis128x2_altivec_implementation
#define aegis128x4_altivec_implementation    sqlite3mc_aegis128x4_altivec_implementation
#define aegis256_altivec_implementation      sqlite3mc_aegis256_altivec_implementation
#define aegis256x2_altivec_implementation    sqlite3mc_aegis256x2_altivec_implementation
#define aegis256x4_altivec_implementation    sqlite3mc_aegis256x4_altivec_implementation

/* Variants with support for ARM Neon instruction sets */
#define aegis128l_armcrypto_implementation   sqlite3mc_aegis128l_armcrypto_implementation
#define aegis128x2_armcrypto_implementation  sqlite3mc_aegis128x2_armcrypto_implementation
#define aegis128x4_armcrypto_implementation  sqlite3mc_aegis128x4_armcrypto_implementation
#define aegis256_armcrypto_implementation    sqlite3mc_aegis256_armcrypto_implementation
#define aegis256x2_armcrypto_implementation  sqlite3mc_aegis256x2_armcrypto_implementation
#define aegis256x4_armcrypto_implementation  sqlite3mc_aegis256x4_armcrypto_implementation

/* Internal Tables (can conflict under -flto) */
#define _aes_lut                             sqlite3mc_aegis_aes_lut

#include "common/cpu.h"

/* AEGIS common functions */
#include "common/common.c"
#include "common/cpu.c"
#include "common/softaes.c"

#if defined(__GNUC__)
#  pragma GCC push_options
#endif

/* Variants of implementation headers */
#include "aegis128l/implementations.h"
#include "aegis128x2/implementations.h"
#include "aegis128x4/implementations.h"
#include "aegis256/implementations.h"
#include "aegis256x2/implementations.h"
#include "aegis256x4/implementations.h"

/* Variants without hardware acceleration */
#include "aegis128l/aegis128l_soft.c"
#include "aegis128x2/aegis128x2_soft.c"
#include "aegis128x4/aegis128x4_soft.c"
#include "aegis256/aegis256_soft.c"
#include "aegis256x2/aegis256x2_soft.c"
#include "aegis256x4/aegis256x4_soft.c"

/* Variants with support for AES and AVX instruction sets */
#include "aegis128l/aegis128l_aesni.c"
#include "aegis128x2/aegis128x2_aesni.c"
#include "aegis128x4/aegis128x4_aesni.c"
#include "aegis256/aegis256_aesni.c"
#include "aegis256x2/aegis256x2_aesni.c"
#include "aegis256x4/aegis256x4_aesni.c"

/* Variants with support for VAES and AVX2 instruction sets */
#include "aegis128x2/aegis128x2_avx2.c"
#include "aegis128x4/aegis128x4_avx2.c"
#include "aegis256x2/aegis256x2_avx2.c"
#include "aegis256x4/aegis256x4_avx2.c"

/* Variants with support for AVX512F instruction sets */
#include "aegis128x4/aegis128x4_avx512.c"
#include "aegis256x4/aegis256x4_avx512.c"

/* Variants with support for AltiVec instruction sets */
#include "aegis128l/aegis128l_altivec.c"
#include "aegis128x2/aegis128x2_altivec.c"
#include "aegis128x4/aegis128x4_altivec.c"
#include "aegis256/aegis256_altivec.c"
#include "aegis256x2/aegis256x2_altivec.c"
#include "aegis256x4/aegis256x4_altivec.c"

/* Variants with support for ARM Neon instruction sets */
#include "aegis128l/aegis128l_armcrypto.c"
#include "aegis128x2/aegis128x2_armcrypto.c"
#include "aegis128x4/aegis128x4_armcrypto.c"
#include "aegis256/aegis256_armcrypto.c"
#include "aegis256x2/aegis256x2_armcrypto.c"
#include "aegis256x4/aegis256x4_armcrypto.c"

/* Control functions for the AEGIS variants */
#include "aegis128l/aegis128l.c"
#include "aegis128x2/aegis128x2.c"
#include "aegis128x4/aegis128x4.c"
#include "aegis256/aegis256.c"
#include "aegis256x2/aegis256x2.c"
#include "aegis256x4/aegis256x4.c"

#if defined(__GNUC__)
#  pragma GCC pop_options
#endif
