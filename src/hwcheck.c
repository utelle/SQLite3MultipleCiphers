/*
** Name:        hwcheck.c
** Purpose:     Check hardware features
** Author:      Ulrich Telle
** Copyright:   (c) 2026 Ulrich Telle
** License:     MIT
*/

/*
** Identify target architecture
*/

#if defined(__ARM_NEON) || defined(__arm__) || defined(__aarch64__) || defined(_M_ARM) || defined(_M_ARM64) || defined(_M_ARM64EC)
#  define SQLITE3MC_TARGET_ARM 1
#elif defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64)
#  define SQLITE3MC_TARGET_X86 1
#elif defined(__powerpc__) || defined(__PPC__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
#  define SQLITE3MC_TARGET_PPC 1
#elif defined(__wasm__) || defined(__wasi__)
#  define SQLITE3MC_TARGET_WASM 1
#else
#  define SQLITE3MC_TARGET_UNKNOWN 1
#endif

/*
** Determine hardware support for AES
*/

#define AES_HARDWARE_NONE  0
#define AES_HARDWARE_NI    1
#define AES_HARDWARE_NEON  2

#ifndef SQLITE3MC_OMIT_AES_HARDWARE_SUPPORT
/*
** Use AES hardware, if available
*/

#  if defined(__clang__)
     /* --- CLang --- */
#    if __has_attribute(target) && __has_include(<wmmintrin.h>) && (defined(__x86_64__) || defined(__i386__))
#      define HAS_AES_HARDWARE AES_HARDWARE_NI
#    elif __has_attribute(target) && __has_include(<arm_neon.h>) && (defined(__aarch64__))
#      define HAS_AES_HARDWARE AES_HARDWARE_NEON
       /* Crypto extension in AArch64 can be enabled using __attribute__((target)) */
#      define USE_CLANG_ATTR_TARGET_AARCH64
#    endif
#  elif defined(__GNUC__)
     /* --- GNU C/C++ */
#    if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)) && (defined(__x86_64__) || defined(__i386__))
#      define HAS_AES_HARDWARE AES_HARDWARE_NI
#    elif defined(__ARM_FEATURE_CRYPTO) && defined(__aarch64__)
#      define HAS_AES_HARDWARE AES_HARDWARE_NEON
#    endif
#  elif defined (_MSC_VER)
     /* --- Visual C/C++ --- */
#    if defined(_M_ARM64) || defined(_M_ARM64EC)
       /* Architecture: ARM 64-bit */
#      define HAS_AES_HARDWARE AES_HARDWARE_NEON
       /* Use header <arm64_neon.h> instead of <arm_neon.h> */
#      define USE_ARM64_NEON_H
#    elif (defined(_M_X64) || defined(_M_IX86)) && _MSC_FULL_VER >= 150030729
       /* Architecture: x86 or x86_64 */
#      define HAS_AES_HARDWARE AES_HARDWARE_NI
#    elif defined _M_ARM
       /* Architecture: ARM 32-bit */
#      define HAS_AES_HARDWARE AES_HARDWARE_NEON
       /* The following #define is required to enable intrinsic definitions
          that do not omit one of the parameters for vaes[ed]q_u8 */
#      define _ARM_USE_NEW_NEON_INTRINSICS
#    endif
#  elif defined(__ARM_FEATURE_CRYPTO)
#    define HAS_AES_HARDWARE AES_HARDWARE_NEON
#  elif defined(SQLITE3MC_TARGET_WASM)
#    define HAS_AES_HARDWARE AES_HARDWARE_NONE
#  else
#    define HAS_AES_HARDWARE AES_HARDWARE_NONE
#  endif
#else /* SQLITE3MC_OMIT_AES_HARDWARE_SUPPORT defined */
  /* Omit AES hardware support */
#  define HAS_AES_HARDWARE AES_HARDWARE_NONE
#endif /* SQLITE3MC_OMIT_AES_HARDWARE_SUPPORT */

/*
** Determine CPU features at runtime
*/

#define SQLITE3MC_CPU_NONE      0x0000
#define SQLITE3MC_CPU_SSE2      0x0001
#define SQLITE3MC_CPU_SSSE3     0x0002
#define SQLITE3MC_CPU_SSE41     0x0004
#define SQLITE3MC_CPU_SSE42     0x0008
#define SQLITE3MC_CPU_AVX       0x0010
#define SQLITE3MC_CPU_AVX2      0x0020
#define SQLITE3MC_CPU_AVX512F   0x0040
#define SQLITE3MC_CPU_AESNI     0x0080
#define SQLITE3MC_CPU_NEON      0x0100
#define SQLITE3MC_CPU_ARMCRYPTO 0x0200
#define SQLITE3MC_CPU_ALTIVEC   0x0400

#if defined(SQLITE3MC_TARGET_ARM)
/*
** ARM
*/

#  if defined(__linux__)

#include <sys/auxv.h>
#include <asm/hwcap.h>

static int
aesHardwareAvailableOnPlatform()
{
#if defined HWCAP_AES
  return getauxval(AT_HWCAP) & HWCAP_AES;
#elif defined HWCAP2_AES
  return getauxval(AT_HWCAP2) & HWCAP2_AES;
#else
  return 0;
#endif
}

#  elif (defined(__FreeBSD__) || defined(__OpenBSD__) /*|| defined(__NetBSD__)*/) && defined(__aarch64__)

#include <sys/param.h>

/* 
 * Feature detection for elf_aux_info():
 * - FreeBSD: Available since version 12.0 (__FreeBSD_version >= 1200000)
 * - OpenBSD: Available since Version 7.6 (OpenBSD >= 202410)
 */
#if (defined(__FreeBSD__) && defined(__FreeBSD_version) && __FreeBSD_version >= 1200000) || \
    (defined(__OpenBSD__) && defined(OpenBSD) && OpenBSD >= 202410)
#define HAVE_ELF_AUX_INFO 1
#include <sys/auxv.h>
#endif

#ifndef HWCAP_AES
#  define HWCAP_AES (1UL << 3)
#endif

static int
aesHardwareAvailableOnPlatform()
{
#ifdef HAVE_ELF_AUX_INFO
  unsigned long hwcap;
  if (elf_aux_info(AT_HWCAP, &hwcap, sizeof(hwcap)) != 0)
    return 0;
  return (hwcap & HWCAP_AES) != 0;
#else
  return 0;
#endif    
}

#  elif defined(__APPLE__) && defined(__aarch64__)     /* macOS/iOS Apple Silicon */

static int
aesHardwareAvailableOnPlatform()
{
  return 1;   /* ARMv8-Crypto mandatory on Apple Silicon */
}

#  elif defined(_WIN32) && (defined _M_ARM || defined _M_ARM64 || defined(_M_ARM64EC))

static int
aesHardwareAvailableOnPlatform()
{
  return (int) IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);
}

#  else

static int
aesHardwareAvailableOnPlatform()
{
  return 0;
}

#  endif
#endif

#if defined(SQLITE3MC_TARGET_ARM)

static unsigned int
mcCpuFeaturesArm(void)
{
  unsigned int features = SQLITE3MC_CPU_NONE;
#if defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)
  features |= SQLITE3MC_CPU_NEON;   /* mandatory on AArch64 architecture */
#elif defined(__ARM_NEON)
  features |= SQLITE3MC_CPU_NEON;   /* 32-Bit: selected as compile target */
#endif
  if (aesHardwareAvailableOnPlatform())
    features |= SQLITE3MC_CPU_ARMCRYPTO;
  return features;
}

#elif defined(SQLITE3MC_TARGET_X86)
/*
** Intel
*/

/* Define SQLITE3MC_COMPILER_HAS_ATTRIBUTE */
#if defined(__has_attribute)
  #define SQLITE3MC_COMPILER_HAS_ATTRIBUTE(x) __has_attribute(x)
  #define SQLITE3MC_COMPILER_ATTRIBUTE(x) __attribute__((x))
#else
  #define SQLITE3MC_COMPILER_HAS_ATTRIBUTE(x) 0
  #define SQLITE3MC_COMPILER_ATTRIBUTE(x) /**/
#endif

/* Define SQLITE3MC_FORCE_INLINE */
#if !defined(SQLITE3MC_FORCE_INLINE)
  #if SQLITE3MC_COMPILER_HAS_ATTRIBUTE(always_inline)
    #define SQLITE3MC_FORCE_INLINE inline SQLITE3MC_COMPILER_ATTRIBUTE(always_inline)
  #elif defined(_MSC_VER)
    #define SQLITE3MC_FORCE_INLINE __forceinline
  #else
    #define SQLITE3MC_FORCE_INLINE inline
  #endif
#endif

/* Define SQLITE3MC_FUNC_ISA */
#if SQLITE3MC_COMPILER_HAS_ATTRIBUTE(target)
  #define SQLITE3MC_FUNC_ISA(isa) SQLITE3MC_COMPILER_ATTRIBUTE(target(isa))
#else
  #define SQLITE3MC_FUNC_ISA(isa)
#endif

/* Define SQLITE3MC_FUNC_ISA_INLINE */
#define SQLITE3MC_FUNC_ISA_INLINE(isa) SQLITE3MC_FUNC_ISA(isa) SQLITE3MC_FORCE_INLINE


#if defined(__clang__) || defined(__GNUC__)
#include <cpuid.h>
#include <immintrin.h>

SQLITE3MC_FUNC_ISA("xsave")
static unsigned int
mcCpuFeaturesX86(void)
{
  unsigned int features = SQLITE3MC_CPU_NONE;
  unsigned int eax, ebx, ecx, edx;

  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx))
  {
    if (edx & (1u << 26)) features |= SQLITE3MC_CPU_SSE2;
    if (ecx & (1u <<  9)) features |= SQLITE3MC_CPU_SSSE3;
    if (ecx & (1u << 19)) features |= SQLITE3MC_CPU_SSE41;
    if (ecx & (1u << 20)) features |= SQLITE3MC_CPU_SSE42;
    /* Bisherige AES-Bedingung (Bit 25 UND Bit 19) bleibt inhaltlich erhalten,
       ergibt sich jetzt aus AESNI- und SSE41-Flag gemeinsam */
    if (ecx & (1u << 25)) features |= SQLITE3MC_CPU_AESNI;

    if (ecx & (1u << 27)) /* OSXSAVE */
    {
      unsigned long long xcr0 = _xgetbv(0);
      int osAvx    = (xcr0 & 0x6)  == 0x6;
      int osAvx512 = (xcr0 & 0xE6) == 0xE6;

      if (osAvx && (ecx & (1u << 28))) features |= SQLITE3MC_CPU_AVX;

      if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
      {
        if (osAvx    && (ebx & (1u <<  5))) features |= SQLITE3MC_CPU_AVX2;
        if (osAvx512 && (ebx & (1u << 16))) features |= SQLITE3MC_CPU_AVX512F;
      }
    }
  }
  return features;
}
#elif defined(_MSC_VER)
#include <intrin.h>

static unsigned int
mcCpuFeaturesX86(void)
{
  unsigned int features = SQLITE3MC_CPU_NONE;
  int cpuInfo[4];

  __cpuid(cpuInfo, 1);
  if (cpuInfo[3] & (1u << 26)) features |= SQLITE3MC_CPU_SSE2;
  if (cpuInfo[2] & (1u <<  9)) features |= SQLITE3MC_CPU_SSSE3;
  if (cpuInfo[2] & (1u << 19)) features |= SQLITE3MC_CPU_SSE41;
  if (cpuInfo[2] & (1u << 20)) features |= SQLITE3MC_CPU_SSE42;
  if (cpuInfo[2] & (1u << 25)) features |= SQLITE3MC_CPU_AESNI;

  if (cpuInfo[2] & (1u << 27)) /* OSXSAVE */
  {
    unsigned long long xcr0 = _xgetbv(0);
    int osAvx    = (xcr0 & 0x6)  == 0x6;
    int osAvx512 = (xcr0 & 0xE6) == 0xE6;

    if (osAvx && (cpuInfo[2] & (1u << 28))) features |= SQLITE3MC_CPU_AVX;

    __cpuidex(cpuInfo, 7, 0);
    if (osAvx    && (cpuInfo[1] & (1u <<  5))) features |= SQLITE3MC_CPU_AVX2;
    if (osAvx512 && (cpuInfo[1] & (1u << 16))) features |= SQLITE3MC_CPU_AVX512F;
  }
  return features;
}
#else
/* Unknown compiler: no hardware detection, safe fallback */
static unsigned int
mcCpuFeaturesX86(void)
{
  return SQLITE3MC_CPU_NONE;
}
#endif

#elif defined(SQLITE3MC_TARGET_PPC)
/*
** PowerPC / POWER
*/

static unsigned int
mcCpuFeaturesPpc(void)
{
#if defined(__ALTIVEC__) && defined(__CRYPTO__)
  return SQLITE3MC_CPU_ALTIVEC;
#else
  return SQLITE3MC_CPU_NONE;
#endif
}

#elif defined(SQLITE3MC_TARGET_WASM)
/*
** WASM
*/

static unsigned int
mcCpuFeaturesWasm(void)
{
#if defined(__wasm_simd128__)
  return SQLITE3MC_CPU_SSE2; /* funktional aequivalente Ebene: 128-Bit-Generic-SIMD */
#else
  return SQLITE3MC_CPU_NONE;
#endif
}

#endif

static unsigned int
mcCpuFeaturesDetect(void)
{
#if defined(SQLITE3MC_TARGET_WASM)
  return mcCpuFeaturesWasm();
#elif defined(SQLITE3MC_TARGET_ARM)
  return mcCpuFeaturesArm();
#elif defined(SQLITE3MC_TARGET_X86)
  unsigned int features = mcCpuFeaturesX86();
# if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
  features |= SQLITE3MC_CPU_SSE2; /* zusaetzlich architektonisch garantiert */
# endif
  return features;
#elif defined(SQLITE3MC_TARGET_PPC)
  return mcCpuFeaturesPpc();
#else
  return SQLITE3MC_CPU_NONE;
#endif
}

static unsigned int
sqlite3mcCpuFeatures(void)
{
  static int mcCpuFeaturesCached = -1; /* -1 = not yet determined */
  if (mcCpuFeaturesCached < 0)
    mcCpuFeaturesCached = (int) mcCpuFeaturesDetect();
  return (unsigned int) mcCpuFeaturesCached;
}

/*
** The top-level selection function, caching the results of
** aesHardwareCheck() so it only has to run once.
*/
static int
aesHardwareAvailable()
{
  static int initialized = 0;
  static int hwAvailable = 0;
  if (!initialized)
  {
    unsigned int features = sqlite3mcCpuFeatures();
    int x86Ok = (features & (SQLITE3MC_CPU_AESNI | SQLITE3MC_CPU_SSE42))
             == (SQLITE3MC_CPU_AESNI | SQLITE3MC_CPU_SSE42);
    int armOk = (features & SQLITE3MC_CPU_ARMCRYPTO) != 0;
    hwAvailable = x86Ok || armOk;
    initialized = 1;
  }
  return hwAvailable;
}

typedef struct _FeatureTag
{
  int flag;
  const char* name;
} FeatureTag;

static const char*
sqlite3mcHardwareInfo()
{
  FeatureTag featureTags[] =
  {
  { SQLITE3MC_CPU_SSE2,      "sse2"      },
  { SQLITE3MC_CPU_SSSE3,     "ssse3"     },
  { SQLITE3MC_CPU_SSE41,     "sse41"     },
  { SQLITE3MC_CPU_SSE42,     "sse42"     },
  { SQLITE3MC_CPU_AVX,       "avx"       },
  { SQLITE3MC_CPU_AVX2,      "avx2"      },
  { SQLITE3MC_CPU_AVX512F,   "avx512f"   },
  { SQLITE3MC_CPU_AESNI,     "aesni"     },
  { SQLITE3MC_CPU_NEON,      "neon"      },
  { SQLITE3MC_CPU_ARMCRYPTO, "armcrypto" },
  { SQLITE3MC_CPU_ALTIVEC,   "altivec"   },
  { 0,                       ""          }  /* Sentinel, do NOT delete */
  };
  static char hwInfoBuf[256];
  static int  hwInfoBuilt = 0;

  if (!hwInfoBuilt)
  {
    int k = 0;
    int offset = 0;
    unsigned int features = sqlite3mcCpuFeatures();
    while (featureTags[k].flag != 0)
    {
      if (features & featureTags[k].flag)
      {
        offset += snprintf(hwInfoBuf + offset, sizeof(hwInfoBuf) - offset,
                           (k == 0) ? "%s" : ", %s", featureTags[k].name);
      }
      ++k;
    }
  }
  return hwInfoBuf;
}
