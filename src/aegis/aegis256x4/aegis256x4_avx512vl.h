/*
** Name:        aegis256x4_avx512vl.h
** Purpose:     Header for implementation structure of AEGIS-256x4 - AES-NI AVX512VL
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

#ifndef AEGIS256X4_AVX512VL_H
#define AEGIS256X4_AVX512VL_H

#include "../common/common.h"
#include "implementations.h"

#ifdef HAVE_VAESINTRIN_H
AEGIS_EXTERN struct aegis256x4_implementation aegis256x4_avx512vl_implementation;
#endif

#endif /* AEGIS256X4_AVX512VL_H */
