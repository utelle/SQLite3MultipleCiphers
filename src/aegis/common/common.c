/*
** Name:        common.c
** Purpose:     Implementation of common utility functions
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "cpu.h"

#if !defined(__GNUC__) && !defined(__clang__)
static volatile uint16_t optblocker_u16;
#endif

static inline int
aegis_verify_n(const uint8_t *x, const uint8_t *y, const int n)
{
#if !defined(__GNUC__) && !defined(__clang__)
    volatile uint16_t d;
#endif
    uint16_t acc = 0U;
    int      i   = 0;

#if defined(__GNUC__) || defined(__clang__)
    {
        uint64_t acc64 = 0U;
        uint64_t x64, y64;

        for (i = 0; i < n; i += 8) {
            memcpy(&x64, x + i, sizeof x64);
            memcpy(&y64, y + i, sizeof y64);
            acc64 |= x64 ^ y64;
        }
        acc64 |= acc64 >> 32;
        acc64 |= acc64 >> 16;
        acc64 |= acc64 >> 8;
        acc = (uint16_t) (acc64 & 0xff);
    }
#else
    for (; i < n; i++) {
        acc |= x[i] ^ y[i];
    }
#endif
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(acc) :);
    acc--;
    acc >>= 15;

    return (int) acc - 1;
#else
    d = acc;
    d--;
    d = ((d >> 13) ^ optblocker_u16) >> 2;

    return (int) d - 1;
#endif
}

AEGIS_API
int
aegis_verify_16(const uint8_t *x, const uint8_t *y)
{
    return aegis_verify_n(x, y, 16);
}

AEGIS_API
int
aegis_verify_32(const uint8_t *x, const uint8_t *y)
{
    return aegis_verify_n(x, y, 32);
}

AEGIS_PRIVATE int aegis128l_pick_best_implementation(void);
AEGIS_PRIVATE int aegis128x2_pick_best_implementation(void);
AEGIS_PRIVATE int aegis128x4_pick_best_implementation(void);
AEGIS_PRIVATE int aegis256_pick_best_implementation(void);
AEGIS_PRIVATE int aegis256x2_pick_best_implementation(void);
AEGIS_PRIVATE int aegis256x4_pick_best_implementation(void);

AEGIS_API
int
aegis_init(void)
{
    static int initialized = 0;

    if (initialized) {
        return 0;
    }
    if (aegis_runtime_get_cpu_features() != 0) {
        return 0;
    }
    if (aegis128l_pick_best_implementation() != 0 || aegis128x2_pick_best_implementation() != 0 ||
        aegis128x4_pick_best_implementation() != 0 || aegis256_pick_best_implementation() != 0 ||
        aegis256x2_pick_best_implementation() != 0 || aegis256x4_pick_best_implementation() != 0) {
        return -1;
    }
    initialized = 1;

    return 0;
}

#if 0
#if defined(_MSC_VER)
#    pragma section(".CRT$XCU", read)
static void __cdecl _do_aegis_init(void);
__declspec(allocate(".CRT$XCU")) void (*aegis_init_constructor)(void) = _do_aegis_init;
#else
static void _do_aegis_init(void) __attribute__((constructor));
#endif

static void
_do_aegis_init(void)
{
    (void) aegis_init();
}
#endif
