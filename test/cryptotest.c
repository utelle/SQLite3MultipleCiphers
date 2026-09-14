/*
** Tests for the cryptographic primitives: checks AES-CBC (NIST SP 800-38A),
** ChaCha20 and Poly1305 (RFC 8439) for all implementations available on the
** target, compares the implementations on pseudo-random input, and checks
** the Poly1305 tag comparison.
*/

#include "sqlite3mc.c"
#include <stdio.h>

/* Builds in which the ChaCha20 and Poly1305 implementations can be selected */
#if defined(SQLITE3MC_CHACHA20_HWACCL_OFF)
#define HAVE_SELECTABLE_IMPLEMENTATIONS 1
#endif

#define MAX_MESSAGE_LENGTH 8192
#define ARRAY_COUNT(array) ((int) (sizeof(array) / sizeof((array)[0])))

typedef struct
{
  const char* name;
  const char* key;
  const char* iv;
  const char* plaintext;
  const char* ciphertext;
} TestAesVector;

typedef struct
{
  const char* name;
  const char* key;
  const char* nonce;
  uint32_t counter;
  const char* plaintext;
  const char* ciphertext;
} TestChaCha20Vector;

typedef struct
{
  const char* name;
  const char* key;
  const char* message;
  const char* tag;
} TestPoly1305Vector;

/* NIST SP 800-38A, F.2.1 (CBC-AES128) and F.2.5 (CBC-AES256) */
static const TestAesVector aesCbcVectors[] =
{
  {
    "SP 800-38A F.2.1",
    "2b7e151628aed2a6abf7158809cf4f3c",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
  },
  {
    "SP 800-38A F.2.5",
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"
  },
};

/* RFC 8439, A.2 */
static const TestChaCha20Vector chacha20Vectors[] =
{
  {
    "RFC 8439 A.2 #1",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000",
    0,
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000",
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
  },
  {
    "RFC 8439 A.2 #2",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "000000000000000000000002",
    1,
    "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
    "6465642062792074686520436f6e7472696275746f7220666f72207075626c69"
    "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
    "20496e7465726e65742d4472616674206f722052464320616e6420616e792073"
    "746174656d656e74206d6164652077697468696e2074686520636f6e74657874"
    "206f6620616e204945544620616374697669747920697320636f6e7369646572"
    "656420616e20224945544620436f6e747269627574696f6e222e205375636820"
    "73746174656d656e747320696e636c756465206f72616c2073746174656d656e"
    "747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
    "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361"
    "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c"
    "207768696368206172652061646472657373656420746f",
    "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec"
    "2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d"
    "4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950"
    "42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a"
    "d00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d"
    "c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b"
    "0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c"
    "cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b"
    "c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f"
    "5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6"
    "98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab"
    "7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221"
  },
  {
    "RFC 8439 A.2 #3",
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
    "000000000000000000000002",
    42,
    "2754776173206272696c6c69672c20616e642074686520736c6974687920746f"
    "7665730a446964206779726520616e642067696d626c6520696e207468652077"
    "6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
    "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
    "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf"
    "166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb"
    "f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
    "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"
  },
};

/* RFC 8439, A.3 */
static const TestPoly1305Vector poly1305Vectors[] =
{
  {
    "RFC 8439 A.3 #1",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000"
  },
  {
    "RFC 8439 A.3 #2",
    "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
    "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
    "6465642062792074686520436f6e7472696275746f7220666f72207075626c69"
    "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
    "20496e7465726e65742d4472616674206f722052464320616e6420616e792073"
    "746174656d656e74206d6164652077697468696e2074686520636f6e74657874"
    "206f6620616e204945544620616374697669747920697320636f6e7369646572"
    "656420616e20224945544620436f6e747269627574696f6e222e205375636820"
    "73746174656d656e747320696e636c756465206f72616c2073746174656d656e"
    "747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
    "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361"
    "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c"
    "207768696368206172652061646472657373656420746f",
    "36e5f6b5c5e06070f0efca96227a863e"
  },
  {
    "RFC 8439 A.3 #3",
    "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
    "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
    "6465642062792074686520436f6e7472696275746f7220666f72207075626c69"
    "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
    "20496e7465726e65742d4472616674206f722052464320616e6420616e792073"
    "746174656d656e74206d6164652077697468696e2074686520636f6e74657874"
    "206f6620616e204945544620616374697669747920697320636f6e7369646572"
    "656420616e20224945544620436f6e747269627574696f6e222e205375636820"
    "73746174656d656e747320696e636c756465206f72616c2073746174656d656e"
    "747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
    "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361"
    "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c"
    "207768696368206172652061646472657373656420746f",
    "f3477e7cd95417af89a6b8794c310cf0"
  },
  {
    "RFC 8439 A.3 #4",
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
    "2754776173206272696c6c69672c20616e642074686520736c6974687920746f"
    "7665730a446964206779726520616e642067696d626c6520696e207468652077"
    "6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
    "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
    "4541669a7eaaee61e708dc7cbcc5eb62"
  },
  {
    "RFC 8439 A.3 #5",
    "0200000000000000000000000000000000000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
    "03000000000000000000000000000000"
  },
  {
    "RFC 8439 A.3 #6",
    "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
    "02000000000000000000000000000000",
    "03000000000000000000000000000000"
  },
  {
    "RFC 8439 A.3 #7",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff"
    "11000000000000000000000000000000",
    "05000000000000000000000000000000"
  },
  {
    "RFC 8439 A.3 #8",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe"
    "01010101010101010101010101010101",
    "00000000000000000000000000000000"
  },
  {
    "RFC 8439 A.3 #9",
    "0200000000000000000000000000000000000000000000000000000000000000",
    "fdffffffffffffffffffffffffffffff",
    "faffffffffffffffffffffffffffffff"
  },
  {
    "RFC 8439 A.3 #10",
    "0100000000000000040000000000000000000000000000000000000000000000",
    "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
    "0000000000000000000000000000000001000000000000000000000000000000",
    "14000000000000005500000000000000"
  },
  {
    "RFC 8439 A.3 #11",
    "0100000000000000040000000000000000000000000000000000000000000000",
    "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
    "00000000000000000000000000000000",
    "13000000000000000000000000000000"
  },
};

static int totalChecks = 0;
static int failedChecks = 0;
static int printedMismatches = 0;

static unsigned char testKey[32];
static unsigned char testNonce[12];
static unsigned char inputBuffer[MAX_MESSAGE_LENGTH];
static unsigned char expectedBuffer[MAX_MESSAGE_LENGTH];
static unsigned char outputBuffer[MAX_MESSAGE_LENGTH];

/* Converts a hex string to bytes and returns the number of bytes */
static size_t hexToBytes(const char* hex, unsigned char* bytes)
{
  size_t count = 0;
  unsigned int value;
  while (hex[0] && hex[1] && sscanf(hex, "%2x", &value) == 1)
  {
    bytes[count++] = (unsigned char) value;
    hex += 2;
  }
  return count;
}

/* Pseudo-random bytes (xorshift64); the fixed seed makes failures reproducible */
static uint64_t randomState = 0x243F6A8885A308D3ull;

static void pseudoRandomBytes(unsigned char* bytes, size_t count)
{
  while (count-- > 0)
  {
    randomState ^= randomState << 13;
    randomState ^= randomState >> 7;
    randomState ^= randomState << 17;
    *bytes++ = (unsigned char) (randomState >> 24);
  }
}

/* Message lengths for the comparisons: all short lengths and the block sizes of the SIMD implementations */
static int messageLengths(size_t* lengths)
{
  static const size_t blockBoundaries[] = { 191, 192, 193, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
                                            2047, 2048, 2049, 4095, 4096, 4097, 8000 };
  int count = 0;
  int i;
  for (i = 0; i <= 130; i++) lengths[count++] = i;
  for (i = 131; i < 1100; i += 37) lengths[count++] = i;
  for (i = 0; i < ARRAY_COUNT(blockBoundaries); i++) lengths[count++] = blockBoundaries[i];
  return count;
}

/* Returns 1 if the check failed; the first 20 failures are printed */
static int checkResult(int passed, const char* implementation, const char* description)
{
  if (!passed && printedMismatches++ < 20)
  {
    printf("  mismatch: %s, %s\n", implementation, description);
  }
  return !passed;
}

static void reportResult(const char* algorithm, const char* implementation, int failures, int checks)
{
  totalChecks += checks;
  failedChecks += failures;
  printf("%-12s %-18s %s (%d check%s)\n", algorithm, implementation, failures ? "FAILED" : "ok",
         checks, (checks == 1) ? "" : "s");
}

/* Returns 1 if the processor has all of the given features */
static int cpuSupports(unsigned int features)
{
#ifdef HAVE_SELECTABLE_IMPLEMENTATIONS
  return (sqlite3mcCpuFeatures() & features) == features;
#else
  return features == 0;
#endif
}

/*
** AES-CBC: the software implementation (with the CBC chaining done here), the
** Rijndael CBC functions used by the cipher schemes, and the hardware
** implementation
*/

static Rijndael rijndaelContext;

static void testAesCbc(void)
{
  int softwareFailures = 0;
  int rijndaelFailures = 0;
  int hardwareFailures = 0;
  int hardwareTested = 0;
  int i;

  for (i = 0; i < ARRAY_COUNT(aesCbcVectors); i++)
  {
    const TestAesVector* vector = &aesCbcVectors[i];
    unsigned char key[32], iv[16], plaintext[64], ciphertext[64], result[64];
    unsigned char previousBlock[16], block[16];
    int keyLength = (int) hexToBytes(vector->key, key);
    int keyLengthCode = (keyLength == 16) ? RIJNDAEL_Direction_KeyLength_Key16Bytes
                                          : RIJNDAEL_Direction_KeyLength_Key32Bytes;
    size_t length, offset, j;
    hexToBytes(vector->iv, iv);
    length = hexToBytes(vector->plaintext, plaintext);
    hexToBytes(vector->ciphertext, ciphertext);

    /* Software implementation */
    RijndaelCreate(&rijndaelContext);
    RijndaelInit(&rijndaelContext, RIJNDAEL_Direction_Mode_ECB, RIJNDAEL_Direction_Encrypt, key, keyLengthCode, iv);
    memcpy(previousBlock, iv, 16);
    for (offset = 0; offset < length; offset += 16)
    {
      for (j = 0; j < 16; j++) block[j] = plaintext[offset + j] ^ previousBlock[j];
      RijndaelEncrypt(&rijndaelContext, block, result + offset);
      memcpy(previousBlock, result + offset, 16);
    }
    softwareFailures += checkResult(memcmp(result, ciphertext, length) == 0, "software", vector->name);
    RijndaelInit(&rijndaelContext, RIJNDAEL_Direction_Mode_ECB, RIJNDAEL_Direction_Decrypt, key, keyLengthCode, iv);
    memcpy(previousBlock, iv, 16);
    for (offset = 0; offset < length; offset += 16)
    {
      RijndaelDecrypt(&rijndaelContext, ciphertext + offset, block);
      for (j = 0; j < 16; j++) result[offset + j] = block[j] ^ previousBlock[j];
      memcpy(previousBlock, ciphertext + offset, 16);
    }
    softwareFailures += checkResult(memcmp(result, plaintext, length) == 0, "software", vector->name);

    /* Rijndael CBC functions (they use the hardware implementation, if available) */
    RijndaelInit(&rijndaelContext, RIJNDAEL_Direction_Mode_CBC, RIJNDAEL_Direction_Encrypt, key, keyLengthCode, iv);
    RijndaelBlockEncrypt(&rijndaelContext, plaintext, (int) length * 8, result);
    rijndaelFailures += checkResult(memcmp(result, ciphertext, length) == 0, "Rijndael CBC", vector->name);
    RijndaelInit(&rijndaelContext, RIJNDAEL_Direction_Mode_CBC, RIJNDAEL_Direction_Decrypt, key, keyLengthCode, iv);
    RijndaelBlockDecrypt(&rijndaelContext, ciphertext, (int) length * 8, result);
    rijndaelFailures += checkResult(memcmp(result, plaintext, length) == 0, "Rijndael CBC", vector->name);

#if defined(HAS_AES_HARDWARE) && HAS_AES_HARDWARE != AES_HARDWARE_NONE
    /* Hardware implementation */
    if (aesHardwareAvailable())
    {
      unsigned char encryptionKeys[15 * 16], decryptionKeys[15 * 16];
      int rounds = (keyLength == 16) ? 10 : 14;
      aesGenKeyEncrypt(key, keyLength * 8, encryptionKeys);
      aesGenKeyDecrypt(key, keyLength * 8, decryptionKeys);
      memcpy(previousBlock, iv, 16);
      aesEncryptCBC(plaintext, result, previousBlock, length, encryptionKeys, rounds);
      hardwareFailures += checkResult(memcmp(result, ciphertext, length) == 0, "hardware", vector->name);
      memcpy(previousBlock, iv, 16);
      aesDecryptCBC(ciphertext, result, previousBlock, length, decryptionKeys, rounds);
      hardwareFailures += checkResult(memcmp(result, plaintext, length) == 0, "hardware", vector->name);
      hardwareTested = 1;
    }
#endif
  }
  reportResult("AES-CBC", "software", softwareFailures, 2 * ARRAY_COUNT(aesCbcVectors));
  reportResult("AES-CBC", "Rijndael CBC", rijndaelFailures, 2 * ARRAY_COUNT(aesCbcVectors));
  if (hardwareTested)
  {
    reportResult("AES-CBC", "hardware", hardwareFailures, 2 * ARRAY_COUNT(aesCbcVectors));
  }
}

/*
** ChaCha20 and Poly1305: every implementation has to reproduce the RFC 8439
** test vectors and give the same result as the first implementation in its
** list (the reference) for pseudo-random input.
*/

typedef void (*ChaCha20Function)(unsigned char* output, const unsigned char* input, size_t length,
                                 const unsigned char* key, const unsigned char* nonce, uint32_t counter);

typedef struct
{
  const char* name;
  ChaCha20Function function;
  unsigned int requiredCpuFeatures;
} ChaCha20Implementation;

typedef void (*Poly1305Function)(const uint8_t* message, size_t length, const uint8_t key[32], uint8_t tag[16]);

typedef struct
{
  const char* name;
  Poly1305Function function;
  unsigned int requiredCpuFeatures;
} Poly1305Implementation;

/* Default implementation, as used by the cipher scheme */
static void chacha20Default(unsigned char* output, const unsigned char* input, size_t length,
                            const unsigned char* key, const unsigned char* nonce, uint32_t counter)
{
  memcpy(output, input, length);
  chacha20_xor(output, length, key, nonce, counter);
}

#ifdef HAVE_SELECTABLE_IMPLEMENTATIONS

static void chacha20Sqleet(unsigned char* output, const unsigned char* input, size_t length,
                           const unsigned char* key, const unsigned char* nonce, uint32_t counter)
{
  memcpy(output, input, length);
  sqleet_chacha20_xor(output, length, key, nonce, counter);
}

/* Defines a function that calls the given libsodium ChaCha20 implementation */
#define LIBSODIUM_CHACHA20(functionName, implementation) \
static void functionName(unsigned char* output, const unsigned char* input, size_t length, \
                         const unsigned char* key, const unsigned char* nonce, uint32_t counter) \
{ \
  (implementation).stream_ietf_ext_xor_ic(output, input, length, nonce, counter, key); \
}

LIBSODIUM_CHACHA20(chacha20LibsodiumRef, crypto_stream_chacha20_ref_implementation)
#if defined(SQLITE3MC_TARGET_X86)
LIBSODIUM_CHACHA20(chacha20LibsodiumSsse3, crypto_stream_chacha20_dolbeau_ssse3_implementation)
LIBSODIUM_CHACHA20(chacha20LibsodiumAvx2, crypto_stream_chacha20_dolbeau_avx2_implementation)
LIBSODIUM_CHACHA20(chacha20LibsodiumAvx512, crypto_stream_chacha20_dolbeau_avx512_implementation)
#endif
#if defined(SQLITE3MC_TARGET_ARM64) && defined(__ARM_NEON)
LIBSODIUM_CHACHA20(chacha20LibsodiumNeon, crypto_stream_chacha20_dolbeau_neon_implementation)
#endif

#endif /* HAVE_SELECTABLE_IMPLEMENTATIONS */

static const ChaCha20Implementation chacha20List[] =
{
#ifdef HAVE_SELECTABLE_IMPLEMENTATIONS
  { "sqleet",           chacha20Sqleet,          0 },
  { "libsodium ref",    chacha20LibsodiumRef,    0 },
#if defined(SQLITE3MC_TARGET_X86)
  { "libsodium ssse3",  chacha20LibsodiumSsse3,  SQLITE3MC_CPU_SSSE3 },
  { "libsodium avx2",   chacha20LibsodiumAvx2,   SQLITE3MC_CPU_AVX2 },
  { "libsodium avx512", chacha20LibsodiumAvx512, SQLITE3MC_CPU_AVX512F },
#endif
#if defined(SQLITE3MC_TARGET_ARM64) && defined(__ARM_NEON)
  { "libsodium neon",   chacha20LibsodiumNeon,   SQLITE3MC_CPU_NEON },
#endif
#endif
  { "chacha20_xor",     chacha20Default,         0 }
};

static const Poly1305Implementation poly1305List[] =
{
#ifdef HAVE_SELECTABLE_IMPLEMENTATIONS
  { "sqleet",   sqleet_poly1305, 0 },
  { "donna",    donna_poly1305,  0 },
#if defined(SQLITE3MC_TARGET_X86)
  { "sse2",     sse2_poly1305,   SQLITE3MC_CPU_SSE2 },
#endif
#endif
  { "poly1305", poly1305,        0 }
};

static void testChaCha20(void)
{
  static const uint32_t counters[] = { 0, 1, 0x12345, 0xfffff000u };
  const ChaCha20Implementation* reference = &chacha20List[0];
  int failures[ARRAY_COUNT(chacha20List)] = { 0 };
  int checks[ARRAY_COUNT(chacha20List)] = { 0 };
  size_t lengths[256];
  int lengthCount = messageLengths(lengths);
  char description[80];
  int i, j, c;

  /* Test vectors */
  for (i = 0; i < ARRAY_COUNT(chacha20Vectors); i++)
  {
    const TestChaCha20Vector* vector = &chacha20Vectors[i];
    size_t length = hexToBytes(vector->plaintext, inputBuffer);
    hexToBytes(vector->key, testKey);
    hexToBytes(vector->nonce, testNonce);
    hexToBytes(vector->ciphertext, expectedBuffer);
    for (j = 0; j < ARRAY_COUNT(chacha20List); j++)
    {
      if (!cpuSupports(chacha20List[j].requiredCpuFeatures)) continue;
      memset(outputBuffer, 0, length);
      chacha20List[j].function(outputBuffer, inputBuffer, length, testKey, testNonce, vector->counter);
      failures[j] += checkResult(memcmp(outputBuffer, expectedBuffer, length) == 0, chacha20List[j].name, vector->name);
      checks[j]++;
    }
  }

  /* Comparison with the reference implementation */
  for (i = 0; i < lengthCount; i++)
  {
    for (c = 0; c < ARRAY_COUNT(counters); c++)
    {
      size_t length = lengths[i];
      pseudoRandomBytes(testKey, sizeof(testKey));
      pseudoRandomBytes(testNonce, sizeof(testNonce));
      pseudoRandomBytes(inputBuffer, length);
      reference->function(expectedBuffer, inputBuffer, length, testKey, testNonce, counters[c]);
      snprintf(description, sizeof(description), "random input, length %d, counter %u",
               (int) length, (unsigned int) counters[c]);
      for (j = 1; j < ARRAY_COUNT(chacha20List); j++)
      {
        if (!cpuSupports(chacha20List[j].requiredCpuFeatures)) continue;
        memset(outputBuffer, 0, length);
        chacha20List[j].function(outputBuffer, inputBuffer, length, testKey, testNonce, counters[c]);
        failures[j] += checkResult(memcmp(outputBuffer, expectedBuffer, length) == 0, chacha20List[j].name, description);
        checks[j]++;
      }
    }
  }

  for (j = 0; j < ARRAY_COUNT(chacha20List); j++)
  {
    if (cpuSupports(chacha20List[j].requiredCpuFeatures))
    {
      reportResult("ChaCha20", chacha20List[j].name, failures[j], checks[j]);
    }
  }
}

static void testPoly1305(void)
{
  const Poly1305Implementation* reference = &poly1305List[0];
  int failures[ARRAY_COUNT(poly1305List)] = { 0 };
  int checks[ARRAY_COUNT(poly1305List)] = { 0 };
  unsigned char tag[16], expectedTag[16];
  size_t lengths[256];
  int lengthCount = messageLengths(lengths);
  char description[80];
  int i, j, variant;

  /* Test vectors */
  for (i = 0; i < ARRAY_COUNT(poly1305Vectors); i++)
  {
    const TestPoly1305Vector* vector = &poly1305Vectors[i];
    size_t length = hexToBytes(vector->message, inputBuffer);
    hexToBytes(vector->key, testKey);
    hexToBytes(vector->tag, expectedTag);
    for (j = 0; j < ARRAY_COUNT(poly1305List); j++)
    {
      if (!cpuSupports(poly1305List[j].requiredCpuFeatures)) continue;
      memset(tag, 0, sizeof(tag));
      poly1305List[j].function(inputBuffer, length, testKey, tag);
      failures[j] += checkResult(memcmp(tag, expectedTag, 16) == 0, poly1305List[j].name, vector->name);
      checks[j]++;
    }
  }

  /* Comparison with the reference implementation */
  for (i = 0; i < lengthCount; i++)
  {
    for (variant = 0; variant < 4; variant++)
    {
      size_t length = lengths[i];
      pseudoRandomBytes(testKey, sizeof(testKey));
      pseudoRandomBytes(inputBuffer, length);
      if (variant == 2) memset(inputBuffer, 0xff, length);  /* message with all bits set */
      if (variant == 3) memset(testKey + 16, 0xff, 16);     /* s close to 2^128: carry in the final addition */
      reference->function(inputBuffer, length, testKey, expectedTag);
      snprintf(description, sizeof(description), "random input, length %d, variant %d", (int) length, variant);
      for (j = 1; j < ARRAY_COUNT(poly1305List); j++)
      {
        if (!cpuSupports(poly1305List[j].requiredCpuFeatures)) continue;
        memset(tag, 0, sizeof(tag));
        poly1305List[j].function(inputBuffer, length, testKey, tag);
        failures[j] += checkResult(memcmp(tag, expectedTag, 16) == 0, poly1305List[j].name, description);
        checks[j]++;
      }
    }
  }

  for (j = 0; j < ARRAY_COUNT(poly1305List); j++)
  {
    if (cpuSupports(poly1305List[j].requiredCpuFeatures))
    {
      reportResult("Poly1305", poly1305List[j].name, failures[j], checks[j]);
    }
  }
}

#ifdef HAVE_SELECTABLE_IMPLEMENTATIONS

/*
** Poly1305 tag comparison: the functions return 0 for equal tags. They are
** checked with equal tags and with tags that differ in one bit; every bit
** position is covered.
*/

typedef int (*TagCompareFunction)(const uint8_t tag1[16], const uint8_t tag2[16]);

typedef struct
{
  const char* name;
  TagCompareFunction function;
  unsigned int requiredCpuFeatures;
} TagCompareImplementation;

static const TagCompareImplementation tagCompareList[] =
{
  { "scalar",          poly1305_tagcmp_scalar,    0 },
#if defined(SQLITE3MC_TARGET_X86)
  { "sse2",            poly1305_tagcmp_sse2,      SQLITE3MC_CPU_SSE2 },
  { "sse41",           poly1305_tagcmp_sse41,     SQLITE3MC_CPU_SSE41 },
#elif defined(SQLITE3MC_TARGET_ARM64) && defined(__ARM_NEON)
  { "neon",            poly1305_tagcmp_neon,      SQLITE3MC_CPU_NEON },
#elif defined(SQLITE3MC_TARGET_WASM) && defined(__wasm_simd128__)
  { "wasm simd",       poly1305_tagcmp_wasm_simd, 0 },
#endif
  { "poly1305_tagcmp", poly1305_tagcmp,           0 }
};

static void testTagCompare(void)
{
  int failures[ARRAY_COUNT(tagCompareList)] = { 0 };
  int checks[ARRAY_COUNT(tagCompareList)] = { 0 };
  unsigned char tag1[16], tag2[16];
  char description[80];
  int pair, j;

  for (pair = 0; pair < 1024; pair++)
  {
    int different = pair & 1;
    int bitPosition = (pair / 2) % 128;
    pseudoRandomBytes(tag1, 16);
    memcpy(tag2, tag1, 16);
    if (different)
    {
      tag2[bitPosition / 8] ^= (unsigned char) (1u << (bitPosition % 8));
    }
    snprintf(description, sizeof(description), "%s tags, pair %d", different ? "different" : "equal", pair);
    for (j = 0; j < ARRAY_COUNT(tagCompareList); j++)
    {
      if (!cpuSupports(tagCompareList[j].requiredCpuFeatures)) continue;
      failures[j] += checkResult((tagCompareList[j].function(tag1, tag2) != 0) == different,
                                 tagCompareList[j].name, description);
      checks[j]++;
    }
  }

  for (j = 0; j < ARRAY_COUNT(tagCompareList); j++)
  {
    if (cpuSupports(tagCompareList[j].requiredCpuFeatures))
    {
      reportResult("Tag compare", tagCompareList[j].name, failures[j], checks[j]);
    }
  }
}

#endif /* HAVE_SELECTABLE_IMPLEMENTATIONS */

int main(void)
{
  printf("%s, SQLite %s\n", sqlite3mc_version(), sqlite3_libversion());
  testAesCbc();
  testChaCha20();
  testPoly1305();
#ifdef HAVE_SELECTABLE_IMPLEMENTATIONS
  testTagCompare();
#endif
  printf("%d checks, %d failed\n", totalChecks, failedChecks);
  return (failedChecks == 0) ? 0 : 1;
}
