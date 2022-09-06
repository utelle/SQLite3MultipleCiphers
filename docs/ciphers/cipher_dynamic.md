---
layout: default
title: Dynamic cipher schemes
parent: Supported Ciphers
nav_order: 7
---
## <a name="legacy" /> Dynamic cipher schemes

Starting with **SQLite3 Multiple Ciphers** version _1.5.0_ it is supported to register cipher schemes dynamically using the C function [`sqlite3mc_register_cipher()`]({{ site.baseurl }}{% link docs/configuration/config_capi.md %}#cipher_register). This allows developers to bring their own implementations of cipher schemes in addition to or instead of the builtin cipher schemes. 

Function [`sqlite3mc_register_cipher()`]({{ site.baseurl }}{% link docs/configuration/config_capi.md %}#cipher_register) has 3 parameters:

  1. a pointer to a [cipher descriptor](#cipher_descriptor)
  2. a pointer to a list of [configuration parameters](#cipher_config_params)
  3. a flag whether the cipher scheme should be made the default cipher scheme

### <a name="cipher_descriptor" />Cipher descriptor

A _cipher descriptor_ specifies the name of the cipher scheme, and a number of API function pointers:

  0. Unique cipher name.

     The _first_ character must be _alphabetic_ = alpha, all other characters may be _alphanumeric_ or _underscore_. The name may consist of a maximum of 63 characters.

  1. Function pointer for function `AllocateCipher`.

     This function allocates a cipher specific memory structure holding all internal information required for the cipher scheme.

  2. Function pointer for function `FreeCipher`.

     This function frees the memory structure of a cipher scheme.

  3. Function pointer for function `CloneCipher`.

     This function creates of clone of a given cipher scheme, typically used to derive the write cipher scheme from the write cipher scheme.

  4. Function pointer for function `GetLegacy`.

     This is a boolean function returning the legacy mode of a cipher scheme (see [legacy mode]({{ site.baseurl }}{% link docs/ciphers/cipher_legacy_mode.md %}) for further details).

  5. Function pointer for function `GetPageSize`

     This function returns the actual size of a database page in legacy mode. For non-legacy mode returning a value of `0` is sufficient, because the page size will be determined automatically.

  6. Function pointer for function `GetReserved`

     This function returns the number of reserved bytes per database page. The reserved bytes are used to store a HMAC (or other data) used by the cipher scheme to verify database page consistency.

  7. Function pointer for function `GetSalt`

     This function returns an array of bytes used as the salt of the cipher scheme.

  8. Function pointer for function `GenerateKey`

     This function is used to derive an encryption key from the given user passphrase.

  9. Function pointer for function `EncryptPage`

     This function is used to encrypt a single database page.

  10. Function pointer for function `DecryptPage`

      This function is used to decrypt a single database page.

Below the type declarations of the API functions and the _CipherDescriptor_ structure are listed in C syntax:

```c
typedef void* (*AllocateCipher_t)(sqlite3* db);
typedef void  (*FreeCipher_t)(void* cipher);
typedef void  (*CloneCipher_t)(void* cipherTo, void* cipherFrom);
typedef int   (*GetLegacy_t)(void* cipher);
typedef int   (*GetPageSize_t)(void* cipher);
typedef int   (*GetReserved_t)(void* cipher);
typedef unsigned char* (*GetSalt_t)(void* cipher);
typedef void  (*GenerateKey_t)(void* cipher, BtShared* pBt, char* userPassword, int passwordLength, int rekey, unsigned char* cipherSalt);
typedef int   (*EncryptPage_t)(void* cipher, int page, unsigned char* data, int len, int reserved);
typedef int   (*DecryptPage_t)(void* cipher, int page, unsigned char* data, int len, int reserved, int hmacCheck);

typedef struct _CipherDescriptor
{
  char* m_name;
  AllocateCipher_t m_allocateCipher;
  FreeCipher_t     m_freeCipher;
  CloneCipher_t    m_cloneCipher;
  GetLegacy_t      m_getLegacy;
  GetPageSize_t    m_getPageSize;
  GetReserved_t    m_getReserved;
  GetSalt_t        m_getSalt;
  GenerateKey_t    m_generateKey;
  EncryptPage_t    m_encryptPage;
  DecryptPage_t    m_decryptPage;
} CipherDescriptor;
```

Please consult the code of the builtin cipher schemes for implementation details.

### <a name="cipher_config_params" />Cipher configuration parameters

A cipher scheme can be configured via named parameters. For this purpose a list of supported parameters needs to be specified. Each parameter entry specifies the name of the parameter, the current value, the default value, and the minimum and maximum value. Currently only integer parameters are supported. Additionally, a paramater value range should be completely within the range of positive integers (including `0`).

The structure of a parameter specification consists of the following components:

1. Name of parameter. The _first_ character must be _alphabetic_ = alpha, all other characters may be _alphanumeric_ or _underscore_. The name may consist of a maximum of 63 characters.
2. Current/transient parameter value
3. Default parameter value
4. Minimum valid parameter value
5. Maximum valid parameter value

Below the _CipherParams_ structure is listed in C syntax:

```c
typedef struct _CipherParams
{
  char* m_name;
  int   m_value;
  int   m_default;
  int   m_minValue;
  int   m_maxValue;
} CipherParams;
```

The list of parameter specifications must be completed with a sentinel entry, where the parameter name is given as an empty string (`""`).
