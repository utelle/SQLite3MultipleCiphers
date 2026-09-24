---
layout: default
title: Hardware Acceleration
parent: Features
nav_order: 4
---
# Hardware Acceleration
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Introduction

Encryption algorithms often require a significant amount of computational power, which can have a major impact on overall performance. It therefore makes sense to take advantage of the specialized instructions found in most modern processors to speed up the execution of cryptographic algorithms.

In _SQLite3 Multiple Ciphers_, this was used for the _AES_ based cipher schemes almost from the very beginning, initially for x86 processors and shortly thereafter for ARM processors as well.

Version **2.0.0** introduced the new _AEGIS_ cipher scheme. It includes specialized implementations for a wide variety of processor generations, ensuring efficient execution. The implementation best suited for the given architecture is selected at runtime.

Special implementations were also introduced in version **2.6.0** for the `ChaCha20-Poly1305` default cipher scheme. The implementations were taken from the well-known [libsodium](https://github.com/jedisct1/libsodium) library and adapted for integration into _SQLite3 Multiple Ciphers_ (to be compilable in the source amalgamation).

## Information about CPU capabilities

Starting with version 2.6.0, a `PRAGMA` statement is available that can be used to query the available CPU features:

```sql
PRAGMA mc_cpu_info = { passphrase | 'passphrase' };
```
The result is a string containing a list of the detected CPU features.

| Feature Id  | Platform    |
| :---        | :---        |
| `sse2`      | x86, x86_64 |
| `ssse3`     | x86, x86_64 |
| `sse41`     | x86, x86_64 |
| `sse42`     | x86, x86_64 |
| `avx`       | x86, x86_64 |
| `avx2`      | x86, x86_64 |
| `avx512f`   | x86, x86_64 |
| `aesni`     | x86, x86_64 |
| `neon`      | ARM, ARM64  |
| `armcrypto` | ARM, ARM64  |
| `altivec`   | AltiVec     |

However, just because the CPU supports certain features does not mean that implementations capable of taking advantage of those features are actually available.

## Information about AES hardware support

Starting with version 2.6.0, a `PRAGMA` statement is available that can be used to query whether AES algorithms use hardware acceleration:

```sql
PRAGMA mc_aes_info;
```

The result is a string containing either `hardware` or `software`.

`hardware` means that hardware acceleration is used for the AES algorithms of the cipher schemes `aes128cbc`, `aes256cbc`, and `sqlcipher`. In contrast,  `software` means that a table-based implementation is used for the AES algorithms.

## Configuration of hardware support for `chacha20`

Starting with version 2.6.0, a `PRAGMA` statement is available that can be used to query or to set which one of available CPU features should be used for accelerating the `chacha20` cipher scheme:

```sql
PRAGMA mc_chacha20_hwaccel [ = newValue ];
```

where `newValue` can be set to one value of the following list:

| New value | Platform    |
| :---      | :---        |
| `off`     | Do not use hardware acceleration |
| `ssse3`   | Choose given feature for x86, x86_64, WASM SIMD128 |
| `avx2`    | Choose given feature for x86, x86_64 |
| `avx512f` | Choose given feature for x86, x86_64 |
| `neon`    | Choose given feature for ARM, ARM64 |
| `auto`    | Choose the best available implementation automatically |
| `max`     | Choose maximal hardware acceleration, even if still experimental |

The result is a string naming the actually used implementation.

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
`mc_chacha20_hwaccel` can also be used as a URI parameter to select the CPU feature for accelerating the ChaCha20 algorithm.
