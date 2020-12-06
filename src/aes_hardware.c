/*
** Name:        aes_hardware.c
** Purpose:     AES algorithms based on AES NI
** Author:      Ulrich Telle
** Created:     2020-12-01
** Copyright:   (c) 2020 Ulrich Telle
** License:     MIT
*/

/*
** Check whether the platform offers hardware support for AES
*/

#if defined(__clang__)
#if __has_attribute(target) && __has_include(<wmmintrin.h>) && (defined(__x86_64__) || defined(__i386))
#define HAS_AES_HARDWARE 1
#endif
#elif defined(__GNUC__)
#if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)) && (defined(__x86_64__) || defined(__i386))
#define HAS_AES_HARDWARE 1
#endif
#elif defined (_MSC_VER)
#if (defined(_M_X64) || defined(_M_IX86)) && _MSC_FULL_VER >= 150030729
#define HAS_AES_HARDWARE 1
#endif
#else
#define HAS_AES_HARDWARE 0
#endif

#if HAS_AES_HARDWARE

/*
** Define function for detecting hardware AES support at runtime
*/

#if defined(__clang__) || defined(__GNUC__)
/* Compiler CLang or GCC */

#include <cpuid.h>

static int
aesHardwareCheck()
{
  unsigned int cpuInfo[4];
  __cpuid(1, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
  /* Check AES and SSE4.1 */
  return (cpuInfo[2] & (1 << 25)) != 0 && (cpuInfo[2] & (1 << 19)) != 0;
}

#else /* !(defined(__clang__) || defined(__GNUC__)) */
/* Compiler Visual C++ */

#include <intrin.h>

static int
aesHardwareCheck()
{
  unsigned int CPUInfo[4];
  __cpuid(CPUInfo, 1);
  return (CPUInfo[2] & (1 << 25)) != 0 && (CPUInfo[2] & (1 << 19)) != 0; /* Check AES and SSE4.1 */
}

#endif /* defined(__clang__) || defined(__GNUC__) */

#else /* !HAS_AES_HARDWARE */
/* No AES hardware support */

static int
aesHardwareCheck()
{
  return 0;
}

#endif /* HAS_AES_HARDWARE */

/*
** The top-level selection function, caching the results of
** aes_hw_available() so it only has to run once.
*/
static int aesHardwareAvailable()
{
  static int initialized = 0;
  static int hw_available;
  if (!initialized)
  {
    hw_available = aesHardwareCheck();
    initialized = 1;
  }
  return hw_available;
}

#if HAS_AES_HARDWARE

#include <wmmintrin.h>

static __m128i
aesKey128Assist(__m128i temp1, __m128i temp2)
{
  __m128i temp3;
  temp2 = _mm_shuffle_epi32(temp2, 0xff);
  temp3 = _mm_slli_si128(temp1, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp1 = _mm_xor_si128(temp1, temp2);
  return temp1;
}

static void
aesKey128Expansion(const unsigned char* userkey, __m128i* expandedKey)
{
  __m128i temp1, temp2;
  __m128i* keySchedule = expandedKey;
  temp1 = _mm_loadu_si128((__m128i*) userkey);
  keySchedule[0] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[1] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[2] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[3] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[4] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[5] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[6] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[7] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[8] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[9] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
  temp1 = aesKey128Assist(temp1, temp2);
  keySchedule[10] = temp1;
}

/*
** Key size 192
*/

static void
aesKey192Assist(__m128i* temp1, __m128i* temp2, __m128i* temp3)
{
  __m128i temp4;
  *temp2 = _mm_shuffle_epi32(*temp2, 0x55);
  temp4 = _mm_slli_si128(*temp1, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  *temp1 = _mm_xor_si128(*temp1, *temp2);
  *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
  temp4 = _mm_slli_si128(*temp3, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  *temp3 = _mm_xor_si128(*temp3, *temp2);
}

static void
aesKey192Expansion(const unsigned char* userkey, __m128i* expandedKey)
{
  __m128i temp1, temp2, temp3;
  __m128i* keySchedule = expandedKey;
  temp1 = _mm_loadu_si128((__m128i*) userkey);
  temp3 = _mm_loadu_si128((__m128i*) (userkey + 16));
  keySchedule[0] = temp1;
  keySchedule[1] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x1);
  aesKey192Assist(&temp1, &temp2, &temp3);
  keySchedule[1] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(keySchedule[1]), _mm_castsi128_pd(temp1), 0));
  keySchedule[2] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
  aesKey192Assist(&temp1, &temp2, &temp3);
  keySchedule[3] = temp1;
  keySchedule[4] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
  aesKey192Assist(&temp1, &temp2, &temp3);
  keySchedule[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(keySchedule[4]), _mm_castsi128_pd(temp1), 0));
  keySchedule[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
  aesKey192Assist(&temp1, &temp2, &temp3);
  keySchedule[6] = temp1;
  keySchedule[7] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
  aesKey192Assist(&temp1, &temp2, &temp3);
  keySchedule[7] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(keySchedule[7]), _mm_castsi128_pd(temp1), 0));
  keySchedule[8] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
  aesKey192Assist(&temp1, &temp2, &temp3);
  keySchedule[9] = temp1;
  keySchedule[10] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
  aesKey192Assist(&temp1, &temp2, &temp3);
  keySchedule[10] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(keySchedule[10]), _mm_castsi128_pd(temp1), 0));
  keySchedule[11] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 1));
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
  aesKey192Assist(&temp1, &temp2, &temp3);
  keySchedule[12] = temp1;
}

/*
** Key size 256
*/

static void
aesKey256Assist1(__m128i* temp1, __m128i* temp2)
{
  __m128i temp4;
  *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
  temp4 = _mm_slli_si128(*temp1, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  *temp1 = _mm_xor_si128(*temp1, *temp2);
}

static void
aesKey256Assist2(__m128i* temp1, __m128i* temp3)
{
  __m128i temp2, temp4;
  temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
  temp2 = _mm_shuffle_epi32(temp4, 0xaa);
  temp4 = _mm_slli_si128(*temp3, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  *temp3 = _mm_xor_si128(*temp3, temp2);
}

static void
aesKey256Expansion(const unsigned char* userkey, __m128i* expandedKey)
{
  __m128i temp1, temp2, temp3;
  __m128i* keySchedule = expandedKey;
  temp1 = _mm_loadu_si128((__m128i*) userkey);
  temp3 = _mm_loadu_si128((__m128i*) (userkey + 16));
  keySchedule[0] = temp1;
  keySchedule[1] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
  aesKey256Assist1(&temp1, &temp2);
  keySchedule[2] = temp1;
  aesKey256Assist2(&temp1, &temp3);
  keySchedule[3] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
  aesKey256Assist1(&temp1, &temp2);
  keySchedule[4] = temp1;
  aesKey256Assist2(&temp1, &temp3);
  keySchedule[5] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
  aesKey256Assist1(&temp1, &temp2);
  keySchedule[6] = temp1;
  aesKey256Assist2(&temp1, &temp3);
  keySchedule[7] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
  aesKey256Assist1(&temp1, &temp2);
  keySchedule[8] = temp1;
  aesKey256Assist2(&temp1, &temp3);
  keySchedule[9] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
  aesKey256Assist1(&temp1, &temp2);
  keySchedule[10] = temp1;
  aesKey256Assist2(&temp1, &temp3);
  keySchedule[11] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
  aesKey256Assist1(&temp1, &temp2);
  keySchedule[12] = temp1;
  aesKey256Assist2(&temp1, &temp3);
  keySchedule[13] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
  aesKey256Assist1(&temp1, &temp2);
  keySchedule[14] = temp1;
}

/*
** Set up expanded key
*/

static int
aesGenKeyEncryptInternal(const unsigned char* userKey, const int bits, __m128i* keyData)
{
  int rc = 0;
  int numberOfRounds = 0;

  if (bits == 128)
  {
    numberOfRounds = 10;
    aesKey128Expansion(userKey, keyData);
  }
  else if (bits == 192)
  {
    numberOfRounds = 12;
    aesKey192Expansion(userKey, keyData);
  }
  else if (bits == 256)
  {
    numberOfRounds = 14;
    aesKey256Expansion(userKey, keyData);
  }
  else
  {
    rc = -2;
  }
  return rc;
}

static int
aesGenKeyEncrypt(const unsigned char* userKey, const int bits, unsigned char* keyData)
{
  int numberOfRounds = (bits == 128) ? 10 : (bits == 192) ? 12 : (bits == 256) ? 14 : 0;
  int rc = (!userKey || !keyData) ? -1 : (numberOfRounds > 0) ? 0 : -2;
  
  if (rc == 0)
  {
    __m128i tempKey[_MAX_ROUNDS + 1];
    rc = aesGenKeyEncryptInternal(userKey, bits, tempKey);
    if (rc == 0)
    {
      int j;
      for (j = 0; j <= numberOfRounds; ++j)
      {
        _mm_storeu_si128(&((__m128i*) keyData)[j], tempKey[j]);
      }
    }
  }
  return rc;
}

static int
aesGenKeyDecrypt(const unsigned char* userKey, const int bits, unsigned char* keyData)
{
  int numberOfRounds = (bits == 128) ? 10 : (bits == 192) ? 12 : (bits == 256) ? 14 : 0;
  int rc = (!userKey || !keyData) ? -1 : (numberOfRounds > 0) ? 0 : -2;

  if (rc == 0)
  {
    __m128i tempKeySchedule[_MAX_ROUNDS + 1];
    __m128i keySchedule[_MAX_ROUNDS + 1];
    rc = aesGenKeyEncryptInternal(userKey, bits, tempKeySchedule);
    if (rc == 0)
    {
      int j;
      keySchedule[0] = tempKeySchedule[0];
      for (j = 1; j < numberOfRounds; ++j)
      {
        keySchedule[j] = _mm_aesimc_si128(tempKeySchedule[j]);
      }
      keySchedule[numberOfRounds] = tempKeySchedule[numberOfRounds];

      for (j = 0; j <= numberOfRounds; ++j)
      {
        _mm_storeu_si128(&((__m128i*) keyData)[j], keySchedule[j]);
      }
    }
  }
  return rc;
}

/*
** AES CBC CTS Encryption
*/

static void
aesEncryptCBC(const unsigned char* in,
              unsigned char* out,
              unsigned char ivec[16],
              unsigned long length,
              const unsigned char* keyData,
              int numberOfRounds)
{
  __m128i key[_MAX_ROUNDS + 1];
  __m128i feedback;
  __m128i data;
  unsigned long i;
  int j;
  unsigned long numBlocks = length / 16;
  unsigned long lenFrag = (length % 16);

  /* Load key data into properly aligned local storage */
  for (j = 0; j <= numberOfRounds; ++j)
  {
    key[j] = _mm_loadu_si128(&((__m128i*) keyData)[j]);
  }

  /* Encrypt all complete blocks */
  feedback = _mm_loadu_si128((__m128i*) ivec);
  for (i = 0; i < numBlocks; ++i)
  {
    data = _mm_loadu_si128(&((__m128i*) in)[i]);
    feedback = _mm_xor_si128(data, feedback);

    feedback = _mm_xor_si128(feedback, key[0]);
    for (j = 1; j < numberOfRounds; j++)
    {
      feedback = _mm_aesenc_si128(feedback, key[j]);
    }
    feedback = _mm_aesenclast_si128(feedback, key[j]);
    _mm_storeu_si128(&((__m128i*) out)[i], feedback);
  }

  /* Use Cipher Text Stealing (CTS) for incomplete last block */
  if (lenFrag > 0)
  {
    UINT8 lastblock[16];
    UINT8 partialblock[16];
    /* Adjust the second last plain block. */
    memcpy(lastblock, &out[16*(numBlocks-1)], lenFrag);
    /* Encrypt the last plain block. */
    memset(partialblock, 0, 16);
    memcpy(partialblock, &in[16*numBlocks], lenFrag);

    data = _mm_loadu_si128(&((__m128i*) partialblock)[0]);
    feedback = _mm_xor_si128(data, feedback);

    feedback = _mm_xor_si128(feedback, key[0]);
    for (j = 1; j < numberOfRounds; j++)
    {
      feedback = _mm_aesenc_si128(feedback, key[j]);
    }
    feedback = _mm_aesenclast_si128(feedback, key[j]);
    _mm_storeu_si128(&((__m128i*) out)[numBlocks-1], feedback);

    memcpy(&out[16*numBlocks], lastblock, lenFrag);
  }
}

/*
** AES CBC CTS decryption
*/
static void
aesDecryptCBC(const unsigned char* in,
              unsigned char* out,
              unsigned char ivec[16],
              unsigned long length,
              const char* keyData,
              int numberOfRounds)
{
  __m128i key[_MAX_ROUNDS + 1];
  __m128i data;
  __m128i feedback;
  __m128i last_in;
  unsigned long i;
  int j;
  unsigned long numBlocks = length / 16;
  unsigned long lenFrag = (length % 16);

  /* Load key data into properly aligned local storage */
  for (j = 0; j <= numberOfRounds; ++j)
  {
    key[j] = _mm_loadu_si128(&((__m128i*) keyData)[j]);
  }

  /* Use Cipher Text Stealing (CTS) for incomplete last block */
  if (lenFrag > 0)
  {
    UINT8 lastblock[16];
    UINT8 partialblock[16];
    int offset;
    --numBlocks;
    offset = numBlocks * 16;
 
    /* Decrypt the last plain block. */
    last_in = _mm_loadu_si128(&((__m128i*) in)[numBlocks]);
    data = _mm_xor_si128(last_in, key[numberOfRounds - 0]);
    for (j = 1; j < numberOfRounds; j++)
    {
      data = _mm_aesdec_si128(data, key[numberOfRounds - j]);
    }
    data = _mm_aesdeclast_si128(data, key[numberOfRounds - j]);
    _mm_storeu_si128(&((__m128i*) partialblock)[0], data);

    memcpy(partialblock, &in[16 * numBlocks + 16], lenFrag);
    last_in = _mm_loadu_si128(&((__m128i*) partialblock)[0]);

    data = _mm_xor_si128(data, last_in);
    _mm_storeu_si128(&((__m128i*) lastblock)[0], data);

    /* Decrypt the second last block. */
    data = _mm_xor_si128(last_in, key[numberOfRounds - 0]);
    for (j = 1; j < numberOfRounds; j++)
    {
      data = _mm_aesdec_si128(data, key[numberOfRounds - j]);
    }
    data = _mm_aesdeclast_si128(data, key[numberOfRounds - j]);

    if (numBlocks > 0)
    {
      feedback = _mm_loadu_si128(&((__m128i*) in)[numBlocks - 1]);
    }
    else
    {
      feedback = _mm_loadu_si128((__m128i*) ivec);
    }
    data = _mm_xor_si128(data, feedback);
    _mm_storeu_si128(&((__m128i*) out)[numBlocks], data);

    memcpy(out + offset + 16, lastblock, lenFrag);
  }

  /* Encrypt all complete blocks */
  feedback = _mm_loadu_si128((__m128i*) ivec);
  for (i = 0; i < numBlocks; i++)
  {
    last_in =_mm_loadu_si128(&((__m128i*) in)[i]);
    data = _mm_xor_si128(last_in, key[numberOfRounds - 0]);
    for (j = 1; j < numberOfRounds; j++)
    {
      data = _mm_aesdec_si128(data, key[numberOfRounds - j]);
    }
    data = _mm_aesdeclast_si128(data, key[numberOfRounds - j]);
    data = _mm_xor_si128(data, feedback);
    _mm_storeu_si128(&((__m128i*) out)[i], data);
    feedback = last_in;
  }
}

#else

static void
aesEncryptCBC(const unsigned char* in,
              unsigned char* out,
              unsigned char ivec[16],
              unsigned long length,
              const unsigned char* keyData,
              int numberOfRounds)
{
  memcpy(out, in, length);
}

static void
aesDecryptCBC(const unsigned char* in,
              unsigned char* out,
              unsigned char ivec[16],
              unsigned long length,
              const char* keyData,
              int numberOfRounds)
{
  memcpy(out, in, length);
}

#endif
