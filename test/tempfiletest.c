/*
** Test for the encryption of temporary files: an anonymous temporary file is
** opened through the SQLite3 Multiple Ciphers VFS and gets random writes,
** appends, reads and truncates, which are compared with a plain in-memory
** model of the file.
**
** A second VFS below checks every write that reaches the disk, independently
** of the read path: the blocks carry their counter value in front of them,
** every byte must be the model's plaintext XOR the keystream of that counter,
** a counter value must never be smaller than one used before, and no keystream
** byte may be used twice, not even after a failed write.
**
** Usage: tempfiletest [operations] [seed] [chunk] [faults] [db[N]] [anon]
**
**   chunk   ask for SQLITE_FCNTL_CHUNK_SIZE first; the file then keeps blocks
**           behind its end, which must still read as zeros
**   faults  let disk writes fail after a random part and disk reads fail; a
**           wrong value without an error is a failure
**   db[N]   open the file as a temporary database whose first write is a page
**           of N bytes (default 1024), so blocks are that size
**   anon    open the file as a main journal without a name: every file opened
**           without a name is encrypted, whatever its type
**
** In a build without the encryption of temporary files, only the model is
** checked.
*/

#include "sqlite3mc.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE_SIZE (3 * 1024 * 1024)
#define MAX_BLOCKS (MAX_FILE_SIZE / 512 + 1)
#define MAX_BLOCK_SIZE 16384     /* largest block size the checks are sized for */
#define MAX_DISK_WRITES 256      /* one write covers at most 64 KiB, that is 128 blocks of 512 bytes */

/*
** The model: what the file should contain
*/
static unsigned char model[MAX_FILE_SIZE];      /* expected content */
static unsigned char undefined[MAX_FILE_SIZE];  /* bytes of a failed write, any value is allowed */
static unsigned char writeBuf[200000];
static unsigned char readBuf[200000];
static sqlite3_int64 modelSize;
static unsigned long long rngState;
static int chunkFile;                           /* the file was given a chunk size */
static int blockSize = MC_TEMP_BLOCK;           /* block size of the file under test */
static sqlite3_file* file;                      /* the temporary file under test */
static int encrypted;                           /* the build encrypts temporary files */
static long nWrite, nRead, nTrunc, nShort, nWriteErrors, nReadErrors;

/*
** Without encryption the size of a one byte file is reported as 0 (SQLite
** ticket #3260), and with a chunk size a truncate rounds the size up
*/
static int sizeIsPlausible(sqlite3_int64 fsz)
{
  if (chunkFile) return fsz >= modelSize && fsz <= (modelSize + 65535) / 65536 * 65536;
  return fsz == modelSize || (modelSize == 1 && fsz == 0);
}

static unsigned long long rnd(void)
{
  rngState ^= rngState << 13; rngState ^= rngState >> 7; rngState ^= rngState << 17;
  return rngState;
}

/* Mostly small lengths and offsets near block boundaries, sometimes large ones */
static int randLen(void)
{
  switch (rnd() % 6)
  {
    case 0: return 1 + (int) (rnd() % 8);
    case 1: return 4;
    case 2: return 4096;
    case 3: return 1 + (int) (rnd() % 5000);
    case 4: return 4096 * (1 + (int) (rnd() % 4)) + (int) (rnd() % 3) - 1;
    default: return 1 + (int) (rnd() % 65536);  /* SQLite writes at most 64 KiB at once; the unix VFS rejects 128 KiB and more */
  }
}
static sqlite3_int64 randOffset(void)
{
  sqlite3_int64 base = (sqlite3_int64) (rnd() % 600) * 4096, off;
  switch (rnd() % 6)
  {
    case 0: off = base; break;
    case 1: off = base + (sqlite3_int64) (rnd() % 64); break;
    case 2: { sqlite3_int64 back = base - 1 - (sqlite3_int64) (rnd() % 64); off = back > 0 ? back : 0; } break;
    case 3: off = modelSize; break;                                  /* append */
    case 4: off = modelSize + (sqlite3_int64) (rnd() % 100); break;  /* append after a gap */
    default: off = (sqlite3_int64) (rnd() % (MAX_FILE_SIZE - 200000)); break;
  }
  return off < MAX_FILE_SIZE ? off : MAX_FILE_SIZE - 1;
}

/*
** The VFS below the one under test: it records the writes of one operation on
** their way to the disk, and injects errors
*/
static sqlite3_vfs* realVfs;
static sqlite3_vfs spyVfs;
static struct
{
  sqlite3_int64 off;                                 /* where it went */
  int n;                                             /* how many bytes */
  int failed;                                        /* the write was made to fail */
  unsigned char data[MC_TEMP_HEADER + MAX_BLOCK_SIZE];
} diskWrite[MAX_DISK_WRITES];
static int nDiskWrite;            /* recorded writes of the current operation */
static int diskWriteOverflow;     /* more writes than the record can hold */
static int faultMode;             /* inject errors */
static int faultInjected;         /* an error was injected during the current operation */
static long nFaultWrites, nFaultReads;

/*
** What the checks remember about the file
*/
static sqlite3_uint64 lastCounter[MAX_BLOCKS];   /* counter value each block was written with */
static sqlite3_uint64 maxCounter;                /* largest counter value seen so far */
static unsigned char keystreamUsed[MAX_BLOCKS][MAX_BLOCK_SIZE / 8];
static unsigned char blockFailed[MAX_BLOCKS];    /* a write failed here, so reads and writes may report an error */
static sqlite3_int64 firstStaleBlock = MAX_BLOCKS;
                                  /* from here on, cleaning up behind the end of the file may have failed */
static long nWritesChecked, nAppendWrites;

typedef struct SpyFile { sqlite3_file base; sqlite3_file* real; } SpyFile;
#define REAL(f) (((SpyFile*) (f))->real)
static int spyClose(sqlite3_file* f) { return REAL(f)->pMethods ? REAL(f)->pMethods->xClose(REAL(f)) : SQLITE_OK; }
static int spyRead(sqlite3_file* f, void* b, int n, sqlite3_int64 o)
{
  if (faultMode && rnd() % 80 == 0) { nFaultReads++; faultInjected = 1; return SQLITE_IOERR_READ; }
  return REAL(f)->pMethods->xRead(REAL(f), b, n, o);
}
static int spyWrite(sqlite3_file* f, const void* b, int n, sqlite3_int64 o)
{
  int failed = faultMode && rnd() % 40 == 0;
  if (nDiskWrite < MAX_DISK_WRITES && n <= MC_TEMP_HEADER + MAX_BLOCK_SIZE) { diskWrite[nDiskWrite].off = o; diskWrite[nDiskWrite].n = n; diskWrite[nDiskWrite].failed = failed; memcpy(diskWrite[nDiskWrite].data, b, n); nDiskWrite++; }
  else diskWriteOverflow = 1;
  if (failed)
  {
    int k = (int) (rnd() % (unsigned) n);  /* bytes that reach the disk before the error */
    if (k > 0) REAL(f)->pMethods->xWrite(REAL(f), b, k, o);
    nFaultWrites++;
    faultInjected = 1;
    return SQLITE_FULL;
  }
  return REAL(f)->pMethods->xWrite(REAL(f), b, n, o);
}
static int spyTruncate(sqlite3_file* f, sqlite3_int64 s) { return REAL(f)->pMethods->xTruncate(REAL(f), s); }
static int spySync(sqlite3_file* f, int fl) { return REAL(f)->pMethods->xSync(REAL(f), fl); }
static int spyFileSize(sqlite3_file* f, sqlite3_int64* s) { return REAL(f)->pMethods->xFileSize(REAL(f), s); }
static int spyLock(sqlite3_file* f, int l) { return REAL(f)->pMethods->xLock(REAL(f), l); }
static int spyUnlock(sqlite3_file* f, int l) { return REAL(f)->pMethods->xUnlock(REAL(f), l); }
static int spyCheckReserved(sqlite3_file* f, int* r) { return REAL(f)->pMethods->xCheckReservedLock(REAL(f), r); }
static int spyFileControl(sqlite3_file* f, int op, void* a) { return REAL(f)->pMethods->xFileControl(REAL(f), op, a); }
static int spySectorSize(sqlite3_file* f) { return REAL(f)->pMethods->xSectorSize(REAL(f)); }
static int spyDevChar(sqlite3_file* f) { return REAL(f)->pMethods->xDeviceCharacteristics(REAL(f)); }
static const sqlite3_io_methods spyIo = {
  1, spyClose, spyRead, spyWrite, spyTruncate, spySync, spyFileSize, spyLock, spyUnlock,
  spyCheckReserved, spyFileControl, spySectorSize, spyDevChar
};
static int spyOpen(sqlite3_vfs* v, sqlite3_filename name, sqlite3_file* f, int flags, int* outFlags)
{
  SpyFile* p = (SpyFile*) f;
  int rc;
  (void) v;
  p->real = (sqlite3_file*) &p[1];
  rc = realVfs->xOpen(realVfs, name, p->real, flags, outFlags);
  p->base.pMethods = (rc == SQLITE_OK && p->real->pMethods) ? &spyIo : NULL;
  return rc;
}
static int spyDelete(sqlite3_vfs* v, const char* n, int s) { (void) v; return realVfs->xDelete(realVfs, n, s); }
static int spyAccess(sqlite3_vfs* v, const char* n, int fl, int* r) { (void) v; return realVfs->xAccess(realVfs, n, fl, r); }
static int spyFullPath(sqlite3_vfs* v, const char* n, int nOut, char* out) { (void) v; return realVfs->xFullPathname(realVfs, n, nOut, out); }
static int spyRandomness(sqlite3_vfs* v, int n, char* out) { (void) v; return realVfs->xRandomness(realVfs, n, out); }
static int spySleep(sqlite3_vfs* v, int us) { (void) v; return realVfs->xSleep(realVfs, us); }
static int spyCurrentTime(sqlite3_vfs* v, double* t) { (void) v; return realVfs->xCurrentTime(realVfs, t); }
static int spyLastError(sqlite3_vfs* v, int n, char* e) { (void) v; return realVfs->xGetLastError(realVfs, n, e); }

static void installSpy(void)
{
  realVfs = sqlite3_vfs_find(NULL);
  memset(&spyVfs, 0, sizeof(spyVfs));
  spyVfs.iVersion = 1; spyVfs.szOsFile = (int) sizeof(SpyFile) + realVfs->szOsFile; spyVfs.mxPathname = realVfs->mxPathname;
  spyVfs.zName = "spy"; spyVfs.xOpen = spyOpen; spyVfs.xDelete = spyDelete; spyVfs.xAccess = spyAccess;
  spyVfs.xFullPathname = spyFullPath; spyVfs.xRandomness = spyRandomness; spyVfs.xSleep = spySleep;
  spyVfs.xCurrentTime = spyCurrentTime; spyVfs.xGetLastError = spyLastError;
  sqlite3_vfs_register(&spyVfs, 0);
  sqlite3mc_vfs_create("spy", 1);
}

/*
** Check the recorded disk writes of one xWrite (the model is already updated):
** counter values never go backwards, keystream never reused, also by failed
** writes; successful writes carry the encrypted plaintext
*/
static int checkDiskWrites(long op)
{
  mcTempCipher* pTemp = ((sqlite3mc_file*) file)->tempCipher;
  int slotSize = MC_TEMP_HEADER + blockSize;
  int i, k;
  if (!encrypted) { nDiskWrite = 0; return 0; }
  if (diskWriteOverflow) { printf("  op %ld: more disk writes than the test records\n", op); return 1; }
  for (i = 0; i < nDiskWrite; i++)
  {
    sqlite3_int64 iBlock = diskWrite[i].off / slotSize;
    int rel = (int) (diskWrite[i].off % slotSize);  /* position inside the block on disk */
    int iOff, n;
    const unsigned char* payload;
    sqlite3_uint64 counter;
    unsigned char ks[MAX_BLOCK_SIZE], nonce[12];

    if (iBlock >= MAX_BLOCKS) { printf("  op %ld: write beyond the model\n", op); return 1; }
    if (rel == 0)
    {
      /* A block written from its start carries the counter value in front */
      if (diskWrite[i].n < MC_TEMP_HEADER) { printf("  op %ld: write shorter than the counter\n", op); return 1; }
      counter = 0;
      for (k = 0; k < 8; k++) counter |= ((sqlite3_uint64) diskWrite[i].data[k]) << (8 * k);
      payload = diskWrite[i].data + MC_TEMP_HEADER;
      iOff = 0;
      n = diskWrite[i].n - MC_TEMP_HEADER;
    }
    else if (rel >= MC_TEMP_HEADER)
    {
      /* An append continues the block that is already on disk */
      counter = lastCounter[iBlock];
      payload = diskWrite[i].data;
      iOff = rel - MC_TEMP_HEADER;
      n = diskWrite[i].n;
      if (counter == 0) { printf("  op %ld: append to block %lld without a counter on disk\n", op, (long long) iBlock); return 1; }
      nAppendWrites++;
    }
    else { printf("  op %ld: write starts inside the counter\n", op); return 1; }

    if (iOff + n > blockSize) { printf("  op %ld: write crosses a block boundary\n", op); return 1; }
    if (counter == 0 && rel == 0 && diskWrite[i].n == MC_TEMP_HEADER)
    {
      /* A truncate clears the counter value of a block behind the new end */
      lastCounter[iBlock] = 0;
      memset(keystreamUsed[iBlock], 0, sizeof(keystreamUsed[iBlock]));
      continue;
    }
    if (counter == 0) { printf("  op %ld: counter value 0 written\n", op); return 1; }
    if (counter != lastCounter[iBlock])
    {
      if (counter <= maxCounter)
      {
        printf("  op %ld: counter value %llu for block %lld was used before\n", op, (unsigned long long) counter, (long long) iBlock);
        return 1;
      }
      maxCounter = counter;
      lastCounter[iBlock] = counter;
      memset(keystreamUsed[iBlock], 0, sizeof(keystreamUsed[iBlock]));
    }
    for (k = iOff; k < iOff + n; k++)
    {
      if (keystreamUsed[iBlock][k >> 3] & (1 << (k & 7)))
      {
        printf("  op %ld: keystream reused, block %lld counter %llu byte %d\n", op, (long long) iBlock, (unsigned long long) counter, k);
        return 1;
      }
      keystreamUsed[iBlock][k >> 3] |= (unsigned char) (1 << (k & 7));
    }
    if (diskWrite[i].failed) continue;
    memset(nonce, 0, sizeof(nonce));
    for (k = 0; k < 8; k++) nonce[k] = (unsigned char) (counter >> (8 * k));
    memset(ks, 0, sizeof(ks));
    chacha20_xor(ks, sizeof(ks), pTemp->key, nonce, 0);
    for (k = iOff; k < iOff + n; k++)
    {
      sqlite3_int64 pos = iBlock * blockSize + k;
      unsigned char plain = (pos < modelSize) ? model[pos] : 0;
      if (pos < MAX_FILE_SIZE && undefined[pos]) continue;
      if (payload[k - iOff] != (unsigned char) (plain ^ ks[k]))
      {
        printf("  op %ld: byte %lld on disk is not the encrypted plaintext\n", op, (long long) pos);
        return 1;
      }
    }
    nWritesChecked++;
  }
  return 0;
}

/* Does [off, off + n) touch a block that had a failed write? A write behind
** the end of the file also fills up the last block, so that one counts too. */
static int mayReportError(sqlite3_int64 off, int n)
{
  sqlite3_int64 b;
  if (!encrypted) return 0;
  for (b = off / blockSize; b <= (off + n - 1) / blockSize && b < MAX_BLOCKS; b++)
    if (blockFailed[b]) return 1;
  if (off > modelSize && modelSize > 0 && blockFailed[(modelSize - 1) / blockSize]) return 1;
  if ((off + n - 1) / blockSize >= firstStaleBlock) return 1;
  return 0;
}

/*
** One random write, possibly behind the end of the file or across a gap
*/
static int doWrite(long op)
{
  sqlite3_int64 off = randOffset(), fsz = -1, b;
  int n = randLen(), k, rc, failures = 0;
  if (off + n > MAX_FILE_SIZE) n = (int) (MAX_FILE_SIZE - off);
  for (k = 0; k < n; k++) writeBuf[k] = (unsigned char) rnd();
  nDiskWrite = 0; diskWriteOverflow = 0;
  rc = file->pMethods->xWrite(file, writeBuf, n, off);

  if (rc != SQLITE_OK && faultMode && (faultInjected || (rc == SQLITE_IOERR_WRITE && mayReportError(off, n))))
  {
    /* The range of a failed write is undefined, and the bytes between the old
    ** and the new end of the file read as zeros */
    file->pMethods->xFileSize(file, &fsz);
    if (fsz > modelSize) { memset(model + modelSize, 0, (size_t) (fsz - modelSize)); memset(undefined + modelSize, 0, (size_t) (fsz - modelSize)); }
    if (off > modelSize) { memset(model + modelSize, 0, (size_t) (off - modelSize)); memset(undefined + modelSize, 0, (size_t) (off - modelSize)); }
    memcpy(model + off, writeBuf, n);
    memset(undefined + off, 1, n);
    if (fsz > modelSize) modelSize = fsz;
    for (b = off / blockSize; b <= (off + n - 1) / blockSize; b++) blockFailed[b] = 1;
    if (off > modelSize && modelSize > 0) blockFailed[(modelSize - 1) / blockSize] = 1;  /* filling up the last block may have failed */
    if (fsz / blockSize < firstStaleBlock) firstStaleBlock = fsz / blockSize;            /* cleaning up behind the end may have failed */
    nWriteErrors++;
    return checkDiskWrites(op);
  }
  if (rc != SQLITE_OK)
  {
    int lastErrno = 0;
    file->pMethods->xFileControl(file, SQLITE_FCNTL_LAST_ERRNO, &lastErrno);
    printf("  write failed at op %ld: rc %d, errno %d, offset %lld, length %d, file size %lld\n",
           op, rc, lastErrno, (long long) off, n, (long long) modelSize);
    return 1;
  }

  if (off > modelSize) { memset(model + modelSize, 0, (size_t) (off - modelSize)); memset(undefined + modelSize, 0, (size_t) (off - modelSize)); }
  memcpy(model + off, writeBuf, n);
  memset(undefined + off, 0, n);
  if (off + n > modelSize) modelSize = off + n;
  for (b = (off + blockSize - 1) / blockSize; (b + 1) * blockSize <= off + n; b++) blockFailed[b] = 0;  /* written completely, readable again */

  file->pMethods->xFileSize(file, &fsz);
  if (!sizeIsPlausible(fsz))
  {
    printf("  op %ld: size %lld after write at %lld length %d, expected %lld\n",
           op, (long long) fsz, (long long) off, n, (long long) modelSize);
    failures++;
  }
  nWrite++;
  return failures + checkDiskWrites(op);
}

/*
** One random read, possibly behind the end of the file
*/
static int doRead(long op)
{
  sqlite3_int64 off = randOffset();
  int n = randLen(), k, rc, expectShort;
  if (off + n > MAX_FILE_SIZE) n = (int) (MAX_FILE_SIZE - off);
  memset(readBuf, 0xAA, n);
  rc = file->pMethods->xRead(file, readBuf, n, off);

  if (rc == SQLITE_IOERR_READ && faultMode &&
      (faultInjected || mayReportError(off, n) ||
       (encrypted && ((sqlite3mc_file*) file)->tempCipher->allBroken)))
  {
    nReadErrors++;
    return 0;
  }
  expectShort = off + n > modelSize;
  if ((expectShort && rc != SQLITE_IOERR_SHORT_READ && !(chunkFile && rc == SQLITE_OK)) || (!expectShort && rc != SQLITE_OK))
  {
    printf("  read rc %d at op %ld (off %lld, n %d, size %lld)\n", rc, op, (long long) off, n, (long long) modelSize);
    return 1;
  }
  for (k = 0; k < n; k++)
  {
    unsigned char want = (off + k < modelSize) ? model[off + k] : 0;
    if (off + k < MAX_FILE_SIZE && off + k < modelSize && undefined[off + k]) continue;
    if (readBuf[k] != want)
    {
      printf("  WRONG DATA WITHOUT ERROR at op %ld: offset %lld (read off %lld n %d, size %lld)\n",
             op, (long long) (off + k), (long long) off, n, (long long) modelSize);
      return 1;
    }
  }
  nRead++;
  if (expectShort) nShort++;
  return 0;
}

/*
** One truncate; SQLite only ever shortens a temporary file
*/
static int doTruncate(long op)
{
  sqlite3_int64 size = modelSize > 0 ? (sqlite3_int64) (rnd() % (modelSize + 1)) : 0, fsz = -1, b;
  int rc, failures = 0;
  nDiskWrite = 0; diskWriteOverflow = 0;
  rc = file->pMethods->xTruncate(file, size);
  if (rc != SQLITE_OK) { printf("  truncate failed at op %ld: %d\n", op, rc); return 1; }
  modelSize = size;
  memset(undefined + size, 0, (size_t) (MAX_FILE_SIZE - size));
  if (faultMode && size / blockSize < firstStaleBlock) firstStaleBlock = size / blockSize;  /* the cleanup behind the new end can fail too */
  for (b = (size + blockSize - 1) / blockSize; b < MAX_BLOCKS; b++) blockFailed[b] = 0;

  file->pMethods->xFileSize(file, &fsz);
  if (!sizeIsPlausible(fsz)) { printf("  size %lld after truncate, expected %lld\n", (long long) fsz, (long long) modelSize); failures++; }
  nTrunc++;
  return failures + checkDiskWrites(op);
}

int main(int argc, char** argv)
{
  long ops = argc > 1 ? atol(argv[1]) : 100000, i;
  sqlite3_vfs* vfs;
  int outFlags, rc, failures = 0;
  int pageSize = 0, fileType = SQLITE_OPEN_TEMP_JOURNAL;
  rngState = argc > 2 ? strtoull(argv[2], NULL, 10) : 0x9E3779B97F4A7C15ULL;

  sqlite3_initialize();
  installSpy();
  vfs = sqlite3_vfs_find(NULL);
  file = (sqlite3_file*) sqlite3_malloc(vfs->szOsFile);
  memset(file, 0, vfs->szOsFile);
  for (i = 3; i < argc; i++)
  {
    if (strncmp(argv[i], "db", 2) == 0) { pageSize = atoi(argv[i] + 2); if (pageSize == 0) pageSize = 1024; fileType = SQLITE_OPEN_TEMP_DB; }
    if (strcmp(argv[i], "anon") == 0) fileType = SQLITE_OPEN_MAIN_JOURNAL;
  }
  printf("  file opened without a name as %s\n", fileType == SQLITE_OPEN_TEMP_DB ? "temp db" :
         fileType == SQLITE_OPEN_MAIN_JOURNAL ? "main journal" : "temp journal");
  rc = vfs->xOpen(vfs, NULL, file, fileType | SQLITE_OPEN_READWRITE |
                  SQLITE_OPEN_CREATE | SQLITE_OPEN_EXCLUSIVE | SQLITE_OPEN_DELETEONCLOSE, &outFlags);
  if (rc != SQLITE_OK) { printf("open failed: %d\n", rc); return 1; }
  for (i = 3; i < argc; i++)
  {
    if (strcmp(argv[i], "chunk") == 0)
    {
      int chunkSize = 65536;
      file->pMethods->xFileControl(file, SQLITE_FCNTL_CHUNK_SIZE, &chunkSize);
      chunkFile = 1;
      printf("  SQLITE_FCNTL_CHUNK_SIZE 65536 requested\n");
    }
  }
  if (pageSize)
  {
    /* The first write of a database is a whole page */
    int k;
    for (k = 0; k < pageSize; k++) model[k] = writeBuf[k] = (unsigned char) rnd();
    rc = file->pMethods->xWrite(file, writeBuf, pageSize, 0);
    if (rc != SQLITE_OK) { printf("first page write failed: %d\n", rc); return 1; }
    modelSize = pageSize;
  }
  encrypted = ((sqlite3mc_file*) file)->tempCipher != NULL;
  printf("  VFS %s, %s encryption of the temporary file\n", vfs->zName, encrypted ? "with" : "without");
  if (encrypted)
  {
    blockSize = ((sqlite3mc_file*) file)->tempCipher->blockSize;
    printf("  block size %d\n", blockSize);
    if (pageSize) { nDiskWrite = 0; failures += checkDiskWrites(-1); }
  }
  for (i = 3; i < argc; i++)
  {
    if (strcmp(argv[i], "faults") == 0)
    {
      faultMode = 1;
      printf("  injecting disk write and read faults\n");
    }
  }

  for (i = 0; i < ops && failures < 5; i++)
  {
    int op = (int) (rnd() % 10);
    faultInjected = 0;
    if (op < 5) failures += doWrite(i);
    else if (op < 9) failures += doRead(i);
    else failures += doTruncate(i);
  }
  file->pMethods->xClose(file);
  sqlite3_free(file);
  printf("  %ld operations: %ld writes, %ld reads (%ld beyond the end), %ld truncates\n", i, nWrite, nRead, nShort, nTrunc);
  if (faultMode)
    printf("  faults: %ld disk writes and %ld disk reads failed; %ld writes and %ld reads reported an error\n",
           nFaultWrites, nFaultReads, nWriteErrors, nReadErrors);
  printf("  %ld disk writes checked against ChaCha20 and for keystream reuse, %ld of them appends with the same counter value\n",
         nWritesChecked, nAppendWrites);
  printf(failures ? "FAILED: %d failure(s)\n" : "OK: %d failure(s)\n", failures);
  return failures != 0;
}
