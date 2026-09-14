/*
** This file contains the implementation for
**   - retrieving entropy
**   - random number generation
**
** The code was separated from the ChaCha20-Poly1305 implementation.
*/

#include "mystdint.h"
#include <string.h>

/*
 * Platform-specific entropy functions for seeding RNG
 */
#if defined(__wasm__) || defined(__wasi__)

#if defined(__EMSCRIPTEN__)
#include <emscripten.h>

 /* Calls the Web Crypto API directly instead of relying on an opaque
  * getentropy() shim whose actual backing implementation cannot be
  * verified from the C side. crypto.getRandomValues() is capped at
  * 65536 bytes per call, so large requests are chunked; not relevant
  * for this generator's actual usage (32/12/24-byte reads), but kept
  * for correctness if entropy() is ever called with a larger buffer. */
EM_JS(int, wasm_crypto_getrandom, (uint8_t* buf, size_t n),
{
  if (typeof crypto === 'undefined' || !crypto.getRandomValues)
    return -1;
  try
  {
    var view = new Uint8Array(HEAPU8.buffer, buf, n);
    var chunk = 65536;
    for (var i = 0; i < n; i += chunk)
    {
      crypto.getRandomValues(view.subarray(i, Math.min(i + chunk, n)));
    }
    return 0;
  }
  catch (e)
  {
    return -1;
  }
});

static size_t entropy(void* buf, size_t n)
{
  size_t i;
  if (wasm_crypto_getrandom((uint8_t*)buf, n) != 0)
    return 0;
  /* Defense in depth: reject an all-zero result. */
  for (i = 0; i < n; i++)
  {
    if (((uint8_t*)buf)[i] != 0)
      return n;
  }
  return (n == 0) ? n : 0;
}

#elif defined(__wasi__)
#include <wasi/api.h>

static size_t entropy(void* buf, size_t n)
{
  size_t i;
  if (__wasi_random_get((uint8_t*)buf, n) != __WASI_ERRNO_SUCCESS)
    return 0;
  for (i = 0; i < n; i++)
  {
    if (((uint8_t*)buf)[i] != 0)
      return n;
  }
  return (n == 0) ? n : 0;
}
#else
extern int getentropy(void* buf, size_t n);

static size_t entropy(void* buf, size_t n)
{
  size_t i;
  if (getentropy(buf, n) != 0)
    return 0;
  for (i = 0; i < n; i++)
  {
    if (((uint8_t*)buf)[i] != 0)
      return n;
  }
  return (n == 0) ? n : 0;
}
#endif

#elif defined(_WIN32) || defined(__CYGWIN__)

#if SQLITE3MC_USE_RAND_S

/* Force header stdlib.h to define rand_s() */
#if !defined(_CRT_RAND_S)
#define _CRT_RAND_S
#endif
#include <stdlib.h>

/*
  Provide declaration of rand_s() for MinGW-32 (not 64).
  MinGW-32 didn't declare it prior to version 5.3.0.
*/
#if defined(__MINGW32__) && defined(__MINGW32_VERSION) && __MINGW32_VERSION < 5003000L && !defined(__MINGW64_VERSION_MAJOR)
__declspec(dllimport) int rand_s(unsigned int *);
#endif

static size_t entropy(void* buf, size_t n)
{
  size_t totalBytes = 0;
  while (totalBytes < n)
  {
    unsigned int random32 = 0;
    size_t j = 0;

    if (rand_s(&random32))
    {
      /* rand_s failed */
      return 0;
    }

    for (; (j < sizeof(random32)) && (totalBytes < n); j++, totalBytes++)
    {
      const uint8_t random8 = (uint8_t)(random32 >> (j * 8));
      ((uint8_t*) buf)[totalBytes] = random8;
    }
  }
  return n;
}

#else

#include <windows.h>
#define RtlGenRandom SystemFunction036
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#pragma comment(lib, "advapi32.lib")
static size_t entropy(void* buf, size_t n)
{
  return RtlGenRandom(buf, (ULONG) n) ? n : 0;
}

#endif

#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__) || defined(__QNX__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef __linux__
#include <poll.h>
#include <sys/ioctl.h>
/* musl does not have <linux/random.h> so let's define RNDGETENTCNT here */
#ifndef RNDGETENTCNT
#define RNDGETENTCNT _IOR('R', 0x00, int)
#endif

/* Waits until the kernel's random pool is initialized, as libsodium does */
static int wait_for_random_pool(void)
{
  struct pollfd pfd;
  int fd, ret;

  do
  {
    fd = open("/dev/random", O_RDONLY, 0);
  }
  while (fd == -1 && errno == EINTR);
  if (fd == -1)
    return 0;  /* no /dev/random: don't block, like libsodium */

  /* /dev/random becomes readable once the pool is initialized */
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  do
  {
    ret = poll(&pfd, 1, -1);
  }
  while (ret == -1 && (errno == EINTR || errno == EAGAIN));
  close(fd);
  return (ret == 1) ? 0 : -1;
}
#endif

/* Returns 1 if all n bytes are zero */
static int is_all_zero(const void* buf, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++)
  {
    if (((const uint8_t*) buf)[i] != 0)
      return 0;
  }
  return 1;
}

/* Returns the number of urandom bytes read (either 0 or n) */
static size_t read_urandom(void* buf, size_t n)
{
  size_t i;
  ssize_t ret;
  int fd, count;
  struct stat st;
  int errnold = errno;

#ifdef __linux__
  /* Unlike getrandom(), /dev/urandom does not wait for the pool */
  if (wait_for_random_pool() != 0)
    goto fail;
#endif

  do
  {
    fd = open("/dev/urandom", O_RDONLY, 0);
  }
  while (fd == -1 && errno == EINTR);
  if (fd == -1)
    goto fail;
  fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

  /* Check the sanity of the device node */
  if (fstat(fd, &st) == -1 || !S_ISCHR(st.st_mode)
                         #ifdef __linux__
                           || ioctl(fd, RNDGETENTCNT, &count) == -1
                         #endif
     )
  {
    close(fd);
    goto fail;
  }

  /* Read bytes */
  for (i = 0; i < n; i += ret)
  {
    while ((ret = read(fd, (char *)buf + i, n - i)) == -1)
    {
      if (errno != EAGAIN && errno != EINTR)
      {
        close(fd);
        goto fail;
      }
    }
  }
  close(fd);

  /* Verify that the random device returned non-zero data */
  if (!is_all_zero(buf, n))
  {
    errno = errnold;
    return n;
  }

  /* Tiny n may unintentionally fall through! */
fail:
  fprintf(stderr, "bad /dev/urandom RNG\n");
  abort(); /* PANIC! */
  return 0;
}

#if defined(__APPLE__)
  #if defined(__clang__) || defined(__GNUC__)
    #if __has_include(<CommonCrypto/CommonRandom.h>)
      #include <CommonCrypto/CommonRandom.h>
      #define HAVE_COMMONCRYPTO_COMMONRANDOM_H 1
    #endif
  #endif
#endif

#if defined(__linux__) && defined(SYS_getrandom)
/* Returns the number of getrandom() bytes read (either 0 or n) */
static size_t read_getrandom(void* buf, size_t n)
{
  size_t i = 0;
  int errnold = errno;
  while (i < n)
  {
    long ret = syscall(SYS_getrandom, (char*) buf + i, n - i, 0);
    if (ret > 0)
      i += (size_t) ret;  /* short read: continue */
    else if (ret != -1 || errno != EINTR)
      break;              /* interrupted: retry; any other error: give up */
  }
  errno = errnold;
  return (i == n) ? n : 0;
}
#endif

static size_t entropy(void* buf, size_t n)
{
#if defined(__APPLE__) && defined(HAVE_COMMONCRYPTO_COMMONRANDOM_H)
  if (CCRandomGenerateBytes(buf, n) == kCCSuccess && !is_all_zero(buf, n))
    return n;
#elif defined(__linux__) && defined(SYS_getrandom)
  if (read_getrandom(buf, n) == n && !is_all_zero(buf, n))
    return n;
#endif
  return read_urandom(buf, n);
}

#else
# error "Secure pseudorandom number generator not implemented for this OS"
#endif

/*
 * ChaCha20 random number generator with fast key erasure: each refill
 * replaces the key with the first 32 bytes of new keystream.
 */
#define CHACHA20_RNG_RESEED_INTERVAL 16384 /* refills (3.5 MiB of output) */

SQLITE_PRIVATE
void chacha20_rng(void* out, size_t n)
{
  static uint8_t key[32], nonce[12], buffer[256] = { 0 };
  static uint32_t counter = 0;
  static size_t available = 0;
#if !defined(_WIN32) && !defined(__wasm__)
  static pid_t pid = 0;
  pid_t currentPid = getpid();
#endif
#if SQLITE_THREADSAFE
  sqlite3_mutex* mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_PRNG);
  sqlite3_mutex_enter(mutex);
#endif
#if !defined(_WIN32) && !defined(__wasm__)
  /*
   * Detect fork(): if the current process id differs from the pid
   * recorded on the previous call, we are running in a freshly forked
   * child that inherited the parent's generator state via copy-on-write
   * memory -- the same key, nonce, counter, and any not-yet-consumed
   * buffered keystream bytes. If left as-is, both parent and child would
   * emit the identical keystream for every buffered/future byte until
   * the next natural reseed, which is a nonce-reuse condition and
   * breaks the security guarantees this generator is relied on for
   * (e.g. per-page nonces). Forcing counter = 0 triggers a reseed from
   * a fresh entropy() call on the next iteration, and clearing
   * available discards any keystream bytes already buffered from the
   * parent's state so they cannot be replayed in both processes.
   * Not applicable on Windows, which has no fork() in the POSIX sense.
   */
  if (currentPid != pid)
  {
    /* Fork detected (or first call): force a reseed and discard any
     * buffered output that might otherwise be replayed in both
     * parent and child. */
    pid = currentPid;
    counter = 0;
    available = 0;
  }
#endif

  while (n > 0)
  {
    size_t m;
    if (available == 0)
    {
      if (counter == 0)
      {
        if (entropy(key, sizeof(key)) != sizeof(key))
          abort();
        if (entropy(nonce, sizeof(nonce)) != sizeof(nonce))
          abort();
      }
      memset(buffer, 0, sizeof(buffer));
      chacha20_xor(buffer, sizeof(buffer), key, nonce, 0);
      /* The first 32 bytes become the next key */
      memcpy(key, buffer, sizeof(key));
      memset(buffer, 0, sizeof(key));
      available = sizeof(buffer) - sizeof(key);
      counter = (counter + 1) % CHACHA20_RNG_RESEED_INTERVAL;
    }
    m = (available < n) ? available : n;
    memcpy(out, buffer + (sizeof(buffer) - available), m);
    /* Wipe handed-out bytes */
    memset(buffer + (sizeof(buffer) - available), 0, m);
    out = (uint8_t*)out + m;
    available -= m;
    n -= m;
  }

#if SQLITE_THREADSAFE
  sqlite3_mutex_leave(mutex);
#endif
}
