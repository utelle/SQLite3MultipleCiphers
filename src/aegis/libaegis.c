/*
** Name:        libaegis.c
** Purpose:     Amalgamation of the AEGIS library
** Copyright:   (c) 2024-2025 Ulrich Telle
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
