/*
** Name:        cpu.c
** Purpose:     Implementation of CPU feature identification
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

#include "cpu.h"
#include "common.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef HAVE_ANDROID_GETCPUFEATURES
#    include <cpu-features.h>
#endif
#ifdef __APPLE__
#    include <mach/machine.h>
#    include <sys/sysctl.h>
#    include <sys/types.h>
#endif
#ifdef HAVE_SYS_AUXV_H
#    include <sys/auxv.h>
#endif
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#    include <intrin.h>
#endif

typedef struct CPUFeatures_ {
    int initialized;
    int has_neon;
    int has_neon_aes;
    int has_neon_sha3;
    int has_sve2_aes;
    int has_avx;
    int has_avx2;
    int has_avx512f;
    int has_avx512vl;
    int has_narrow_avx512;
    int has_aesni;
    int has_vaes;
    int has_altivec;
} CPUFeatures;

static CPUFeatures _cpu_features;

#define CPUID_EBX_AVX2     0x00000020
#define CPUID_EBX_AVX512F  0x00010000
#define CPUID_EBX_AVX512VL 0x80000000

#define CPUID_ECX_AESNI   0x02000000
#define CPUID_ECX_XSAVE   0x04000000
#define CPUID_ECX_OSXSAVE 0x08000000
#define CPUID_ECX_AVX     0x10000000
#define CPUID_ECX_VAES    0x00000200

#define XCR0_SSE       0x00000002
#define XCR0_AVX       0x00000004
#define XCR0_OPMASK    0x00000020
#define XCR0_ZMM_HI256 0x00000040
#define XCR0_HI16_ZMM  0x00000080

// Define hwcap values ourselves: building with an old auxv header where these
// hwcap values are not defined should not prevent features from being enabled.

// Arm hwcaps.
#define AEGIS_ARM_HWCAP_NEON (1L << 12)
#define AEGIS_ARM_HWCAP2_AES (1L << 0)

// AArch64 hwcaps.
#define AEGIS_AARCH64_HWCAP_ASIMD   (1L << 1)
#define AEGIS_AARCH64_HWCAP_AES     (1L << 3)
#define AEGIS_AARCH64_HWCAP_SHA3    (1L << 17)
#define AEGIS_AARCH64_HWCAP2_SVEAES (1L << 2)

#if defined(__APPLE__) && defined(CPU_TYPE_ARM64) && defined(CPU_SUBTYPE_ARM64E)
// sysctlbyname() parameter documentation for instruction set characteristics:
// https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/determining_instruction_set_characteristics
static inline int __attribute__((unused))
_have_arm_feature(const char *feature)
{
    int64_t feature_present = 0;
    size_t  size            = sizeof(feature_present);
    if (sysctlbyname(feature, &feature_present, &size, NULL, 0) != 0) {
        return 0;
    }
    return feature_present;
}

#elif (defined(__arm__) || defined(__aarch64__) || defined(_M_ARM64)) && defined(AT_HWCAP)
static inline int
_have_hwcap(int hwcap_id, int bit)
{
    unsigned long buf = 0;
#    ifdef HAVE_GETAUXVAL
    buf = getauxval(hwcap_id);
#    elif defined(HAVE_ELF_AUX_INFO)
    if (elf_aux_info(hwcap_id, (void *) &buf, (int) sizeof buf) != 0) {
        return 0;
    }
#    endif
    return (buf & bit) != 0;
}
#endif

static int
_runtime_arm_cpu_features(CPUFeatures *const cpu_features)
{
#ifndef __ARM_ARCH
    return -1; /* LCOV_EXCL_LINE */
#endif

#if defined(__ARM_NEON) || defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)
    cpu_features->has_neon = 1;
#elif defined(HAVE_ANDROID_GETCPUFEATURES) && defined(ANDROID_CPU_ARM_FEATURE_NEON)
    cpu_features->has_neon = (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON) != 0x0;
#elif (defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)) && defined(AT_HWCAP)
    cpu_features->has_neon = _have_hwcap(AT_HWCAP, AEGIS_AARCH64_HWCAP_ASIMD);
#elif defined(__arm__) && defined(AT_HWCAP)
    cpu_features->has_neon = _have_hwcap(AT_HWCAP, AEGIS_ARM_HWCAP_NEON);
#endif

    if (cpu_features->has_neon == 0) {
        return 0;
    }

#if __ARM_FEATURE_CRYPTO || __ARM_FEATURE_AES
    cpu_features->has_neon_aes = 1;
#elif defined(_M_ARM64) || defined(_M_ARM64EC)
    // Assuming all CPUs supported by Arm Windows have the crypto extensions.
    cpu_features->has_neon_aes = 1;
#elif defined(__APPLE__) && defined(CPU_TYPE_ARM64) && defined(CPU_SUBTYPE_ARM64E)
    cpu_features->has_neon_aes = _have_arm_feature("hw.optional.arm.FEAT_AES");
#elif defined(HAVE_ANDROID_GETCPUFEATURES) && defined(ANDROID_CPU_ARM_FEATURE_AES)
    cpu_features->has_neon_aes = (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_AES) != 0x0;
#elif (defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)) && defined(AT_HWCAP)
    cpu_features->has_neon_aes = _have_hwcap(AT_HWCAP, AEGIS_AARCH64_HWCAP_AES);
#elif defined(__arm__) && defined(AT_HWCAP2)
    cpu_features->has_neon_aes = _have_hwcap(AT_HWCAP2, AEGIS_ARM_HWCAP2_AES);
#endif

    // The FEAT_SHA3 implementation assumes that FEAT_AES is also present.
    if (cpu_features->has_neon_aes == 0) {
        return 0;
    }

    // At the time of writing Windows does not provide a mechanism for
    // detecting FEAT_SHA3, however FEAT_SHA3 is mandatory if FEAT_SVE_AES is
    // also implemented, so test that instead.
#if __ARM_FEATURE_SHA3
    cpu_features->has_neon_sha3 = 1;
#elif defined(_M_ARM64) && defined(PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE)
    cpu_features->has_neon_sha3 = IsProcessorFeaturePresent(PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE);
#elif defined(__APPLE__) && defined(CPU_TYPE_ARM64) && defined(CPU_SUBTYPE_ARM64E)
    cpu_features->has_neon_sha3 = _have_arm_feature("hw.optional.arm.FEAT_SHA3");
#elif (defined(__aarch64__) || defined(_M_ARM64)) && defined(AT_HWCAP)
    cpu_features->has_neon_sha3 = _have_hwcap(AT_HWCAP, AEGIS_AARCH64_HWCAP_SHA3);
#endif

    // The FEAT_SVE_AES implementation assumes that FEAT_AES and FEAT_SHA3 are
    // also present.
    if (cpu_features->has_neon_sha3 == 0) {
        return 0;
    }

    // At the time of writing Apple Silicon platforms do not provide a
    // mechanism for detecting FEAT_SVE_AES.
#if __ARM_FEATURE_SVE2_AES
    cpu_features->has_sve2_aes = 1;
#elif defined(_M_ARM64) && defined(PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE)
    cpu_features->has_sve2_aes = IsProcessorFeaturePresent(PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE);
#elif (defined(__aarch64__) || defined(_M_ARM64)) && defined(AT_HWCAP)
    cpu_features->has_sve2_aes = _have_hwcap(AT_HWCAP2, AEGIS_AARCH64_HWCAP2_SVEAES);
#endif

    return 0;
}

static void
_cpuid(unsigned int cpu_info[4U], const unsigned int cpu_info_type)
{
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    (__cpuid)((int *) cpu_info, cpu_info_type);
#elif defined(HAVE_CPUID)
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
#    ifdef __i386__
    __asm__ __volatile__(
        "pushfl; pushfl; "
        "popl %0; "
        "movl %0, %1; xorl %2, %0; "
        "pushl %0; "
        "popfl; pushfl; popl %0; popfl"
        : "=&r"(cpu_info[0]), "=&r"(cpu_info[1])
        : "i"(0x200000));
    if (((cpu_info[0] ^ cpu_info[1]) & 0x200000) == 0x0) {
        return; /* LCOV_EXCL_LINE */
    }
#    endif
#    ifdef __i386__
    __asm__ __volatile__("xchgl %%ebx, %k1; cpuid; xchgl %%ebx, %k1"
                         : "=a"(cpu_info[0]), "=&r"(cpu_info[1]), "=c"(cpu_info[2]),
                           "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
#    elif defined(__x86_64__)
    __asm__ __volatile__("xchgq %%rbx, %q1; cpuid; xchgq %%rbx, %q1"
                         : "=a"(cpu_info[0]), "=&r"(cpu_info[1]), "=c"(cpu_info[2]),
                           "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
#    else
    __asm__ __volatile__("cpuid"
                         : "=a"(cpu_info[0]), "=b"(cpu_info[1]), "=c"(cpu_info[2]),
                           "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
#    endif
#else
    (void) cpu_info_type;
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
#endif
}

static int
_runtime_intel_cpu_features(CPUFeatures *const cpu_features)
{
    unsigned int cpu_info[4];
    uint32_t     xcr0 = 0U;

    _cpuid(cpu_info, 0x0);
    if (cpu_info[0] == 0U) {
        return -1; /* LCOV_EXCL_LINE */
    }
    _cpuid(cpu_info, 0x00000001);

    (void) xcr0;
#ifdef HAVE_AVXINTRIN_H
    if ((cpu_info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
        (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) {
        xcr0 = 0U;
#    if defined(HAVE__XGETBV) || \
        (defined(_MSC_VER) && defined(_XCR_XFEATURE_ENABLED_MASK) && _MSC_FULL_VER >= 160040219)
        xcr0 = (uint32_t) _xgetbv(0);
#    elif defined(_MSC_VER) && defined(_M_IX86)
        /*
         * Visual Studio documentation states that eax/ecx/edx don't need to
         * be preserved in inline assembly code. But that doesn't seem to
         * always hold true on Visual Studio 2010.
         */
        __asm {
            push eax
            push ecx
            push edx
            xor ecx, ecx
            _asm _emit 0x0f _asm _emit 0x01 _asm _emit 0xd0
            mov xcr0, eax
            pop edx
            pop ecx
            pop eax
        }
#    elif defined(HAVE_AVX_ASM)
        __asm__ __volatile__(".byte 0x0f, 0x01, 0xd0" /* XGETBV */
                             : "=a"(xcr0)
                             : "c"((uint32_t) 0U)
                             : "%edx");
#    endif
        if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX)) {
            cpu_features->has_avx = 1;
        }
    }
#endif

#ifdef HAVE_WMMINTRIN_H
    cpu_features->has_aesni = ((cpu_info[2] & CPUID_ECX_AESNI) != 0x0);
#endif

#ifdef HAVE_AVX2INTRIN_H
    if (cpu_features->has_avx) {
        unsigned int cpu_info7[4];

        _cpuid(cpu_info7, 0x00000007);
        cpu_features->has_avx2 = ((cpu_info7[1] & CPUID_EBX_AVX2) != 0x0);
        cpu_features->has_vaes =
            cpu_features->has_aesni && ((cpu_info7[2] & CPUID_ECX_VAES) != 0x0);
    }
#endif

    cpu_features->has_avx512f       = 0;
    cpu_features->has_avx512vl      = 0;
    cpu_features->has_narrow_avx512 = 0;
#ifdef HAVE_AVX512FINTRIN_H
    if (cpu_features->has_avx2) {
        unsigned int cpu_info7[4];

        _cpuid(cpu_info7, 0x00000007);
        /* LCOV_EXCL_START */
        if ((cpu_info7[1] & CPUID_EBX_AVX512F) == CPUID_EBX_AVX512F &&
            (xcr0 & (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)) ==
                (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)) {
            cpu_features->has_avx512f = 1;
            cpu_features->has_avx512vl =
                ((cpu_info7[1] & CPUID_EBX_AVX512VL) == CPUID_EBX_AVX512VL);
        }
        /* LCOV_EXCL_STOP */
    }

    /* LCOV_EXCL_START */
    if (cpu_features->has_avx512f) {
        unsigned int vendor_info[4];

        _cpuid(vendor_info, 0x0);
        /* "AuthenticAMD" */
        if (vendor_info[1] == 0x68747541 && vendor_info[3] == 0x69746e65 &&
            vendor_info[2] == 0x444d4163) {
            unsigned int ext_info[4];

            _cpuid(ext_info, 0x80000000);
            if (ext_info[0] >= 0x8000001a) {
                _cpuid(ext_info, 0x8000001a);
                /* A clear bit means the CPU runs 512-bit AVX-512 as two 256-bit passes.
                 * Only AEGIS-256X4 gets faster with the narrower backend there; AEGIS-128X4
                 * measured slower on Zen 4 and stays on the 512-bit one. */
                if ((ext_info[0] & 0x00000008) == 0x0) {
                    cpu_features->has_narrow_avx512 = 1;
                }
            }
        }
        /* Intel has no equivalent bit to check, but every Intel chip that supports AVX-512 today
         * runs it at full width anyway, so there's nothing to detect yet. Worth revisiting if that
         * ever changes. */
    }
    /* LCOV_EXCL_STOP */
#endif

    return 0;
}

static int
_runtime_powerpc_cpu_features(CPUFeatures *const cpu_features)
{
    cpu_features->has_altivec = 0;
#if defined(__ALTIVEC__) && defined(__CRYPTO__)
    cpu_features->has_altivec = 1;
#endif
    return 0;
}

AEGIS_PRIVATE
int
aegis_runtime_get_cpu_features(void)
{
    int ret = -1;

    memset(&_cpu_features, 0, sizeof _cpu_features);

    ret &= _runtime_arm_cpu_features(&_cpu_features);
    ret &= _runtime_intel_cpu_features(&_cpu_features);
    ret &= _runtime_powerpc_cpu_features(&_cpu_features);
    _cpu_features.initialized = 1;

    return ret;
}

AEGIS_PRIVATE
int
aegis_runtime_has_neon(void)
{
    return _cpu_features.has_neon;
}

AEGIS_PRIVATE
int
aegis_runtime_has_neon_aes(void)
{
    return _cpu_features.has_neon_aes;
}

int
aegis_runtime_has_neon_sha3(void)
{
    return _cpu_features.has_neon_sha3;
}

int
aegis_runtime_has_sve2_aes(void)
{
    return _cpu_features.has_sve2_aes;
}

AEGIS_PRIVATE
int
aegis_runtime_has_avx(void)
{
    return _cpu_features.has_avx;
}

AEGIS_PRIVATE
int
aegis_runtime_has_avx2(void)
{
    return _cpu_features.has_avx2;
}

AEGIS_PRIVATE
int
aegis_runtime_has_avx512f(void)
{
    return _cpu_features.has_avx512f;
}

AEGIS_PRIVATE
int
aegis_runtime_has_avx512vl(void)
{
    return _cpu_features.has_avx512vl;
}

int
aegis_runtime_has_narrow_avx512(void)
{
    return _cpu_features.has_narrow_avx512;
}

int
aegis_runtime_has_aesni(void)
{
    return _cpu_features.has_aesni;
}

AEGIS_PRIVATE
int
aegis_runtime_has_vaes(void)
{
    return _cpu_features.has_vaes;
}

AEGIS_PRIVATE
int
aegis_runtime_has_altivec(void)
{
    return _cpu_features.has_altivec;
}
