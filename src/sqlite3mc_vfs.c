/*
** Name:        sqlite3mc_vfs.c
** Purpose:     Implementation of SQLite VFS for Multiple Ciphers
** Author:      Ulrich Telle
** Created:     2020-02-28
** Copyright:   (c) 2020-2023 Ulrich Telle
** License:     MIT
*/

#include "sqlite3mc_vfs.h"
#include "sqlite3.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "mystdint.h"

/*
** Type definitions
*/

typedef struct sqlite3mc_file sqlite3mc_file;
typedef struct sqlite3mc_vfs sqlite3mc_vfs;
typedef struct mcTempCipher mcTempCipher;

/*
** SQLite3 Multiple Ciphers file structure
*/

struct sqlite3mc_file
{
  sqlite3_file base;           /* sqlite3_file I/O methods */
  sqlite3_file* pFile;         /* Real underlying OS file */
  sqlite3mc_vfs* pVfsMC;       /* Pointer to the sqlite3mc_vfs object */
  const char* zFileName;       /* File name */
  int openFlags;               /* Open flags */
  sqlite3mc_file* pMainNext;   /* Next main db file */
  sqlite3mc_file* pMainDb;     /* Main database to which this one is attached */
  Codec* codec;                /* Codec if encrypted */
  int pageNo;                  /* Page number (in case of journal files) */
  mcTempCipher* tempCipher;    /* Cipher of a temporary file opened without a name */
};

/*
** SQLite3 Multiple Ciphers VFS structure
*/

struct sqlite3mc_vfs
{
  sqlite3_vfs base;      /* Multiple Ciphers VFS shim methods */
  sqlite3_mutex* mutex;  /* Mutex to protect pMain */
  sqlite3mc_file* pMain; /* List of main database files */
};

#define REALVFS(p) ((sqlite3_vfs*)(((sqlite3mc_vfs*)(p))->base.pAppData))
#define REALFILE(p) (((sqlite3mc_file*)(p))->pFile)

/*
** Prototypes for VFS methods
*/

static int mcVfsOpen(sqlite3_vfs* pVfs, const char* zName, sqlite3_file* pFile, int flags, int* pOutFlags);
static int mcVfsDelete(sqlite3_vfs* pVfs, const char* zName, int syncDir);
static int mcVfsAccess(sqlite3_vfs* pVfs, const char* zName, int flags, int* pResOut);
static int mcVfsFullPathname(sqlite3_vfs* pVfs, const char* zName, int nOut, char* zOut);
static void* mcVfsDlOpen(sqlite3_vfs* pVfs, const char* zFilename);
static void mcVfsDlError(sqlite3_vfs* pVfs, int nByte, char* zErrMsg);
static void (*mcVfsDlSym(sqlite3_vfs* pVfs, void* p, const char* zSymbol))(void);
static void mcVfsDlClose(sqlite3_vfs* pVfs, void* p);
static int mcVfsRandomness(sqlite3_vfs* pVfs, int nByte, char* zOut);
static int mcVfsSleep(sqlite3_vfs* pVfs, int microseconds);
static int mcVfsCurrentTime(sqlite3_vfs* pVfs, double* pOut);
static int mcVfsGetLastError(sqlite3_vfs* pVfs, int nErr, char* zOut);
static int mcVfsCurrentTimeInt64(sqlite3_vfs* pVfs, sqlite3_int64* pOut);
static int mcVfsSetSystemCall(sqlite3_vfs* pVfs, const char* zName, sqlite3_syscall_ptr pNewFunc);
static sqlite3_syscall_ptr mcVfsGetSystemCall(sqlite3_vfs* pVfs, const char* zName);
static const char* mcVfsNextSystemCall(sqlite3_vfs* pVfs, const char* zName);

/*
** Prototypes for IO methods
*/

static int mcIoClose(sqlite3_file* pFile);
static int mcIoRead(sqlite3_file* pFile, void*, int iAmt, sqlite3_int64 iOfst);
static int mcIoWrite(sqlite3_file* pFile,const void*,int iAmt, sqlite3_int64 iOfst);
static int mcIoTruncate(sqlite3_file* pFile, sqlite3_int64 size);
static int mcIoSync(sqlite3_file* pFile, int flags);
static int mcIoFileSize(sqlite3_file* pFile, sqlite3_int64* pSize);
static int mcIoLock(sqlite3_file* pFile, int lock);
static int mcIoUnlock(sqlite3_file* pFile, int lock);
static int mcIoCheckReservedLock(sqlite3_file* pFile, int *pResOut);
static int mcIoFileControl(sqlite3_file* pFile, int op, void *pArg);
static int mcIoSectorSize(sqlite3_file* pFile);
static int mcIoDeviceCharacteristics(sqlite3_file* pFile);
static int mcIoShmMap(sqlite3_file* pFile, int iPg, int pgsz, int map, void volatile** p);
static int mcIoShmLock(sqlite3_file* pFile, int offset, int n, int flags);
static void mcIoShmBarrier(sqlite3_file* pFile);
static int mcIoShmUnmap(sqlite3_file* pFile, int deleteFlag);
static int mcIoFetch(sqlite3_file* pFile, sqlite3_int64 iOfst, int iAmt, void** pp);
static int mcIoUnfetch(sqlite3_file* pFile, sqlite3_int64 iOfst, void* p);

/*
** Encryption of temporary files
**
** SQLite opens temporary files without a name: temporary and transient
** databases, temporary journals, sorter files and statement journals. Such a
** file is private and deleted on close (see xOpen in sqlite3.h), and it can'pTemp
** be linked to the codec of a database. Therefore every file opened without a
** name is encrypted with its own random key, which exists only in memory and
** is wiped when the file is closed.
**
** A file is encrypted in blocks with ChaCha20. The nonce of a block consists
** of its block number and a generation number, which is kept in memory and
** increases whenever the block is re-encrypted. A write that appends to the
** encrypted part of a block continues its keystream, every other write
** re-encrypts the block with the next generation. A keystream is therefore
** never used twice.
**
** The encryption protects the confidentiality of temporary files, not their
** integrity.
*/
#ifndef SQLITE3MC_ENCRYPT_TEMP_FILES
#define SQLITE3MC_ENCRYPT_TEMP_FILES 1
#endif

#define MC_TEMP_BLOCK 4096
#define MC_TEMP_BROKEN 0xffffffffu  /* Sentinel for mcTempBlock.used */
#define MC_TEMP_MAX_GENERATION 0xffffffffu

typedef struct mcTempBlock
{
  uint32_t generation;  /* Part of the nonce, incremented on re-encryption; never reset */
  uint32_t valid;       /* Bytes from the block start encrypted with generation; the rest reads as zeros */
  uint32_t used;        /* Bytes from the block start whose keystream for generation was used,
                        ** or MC_TEMP_BROKEN if a failed rewrite left the valid part unreadable */
} mcTempBlock;

struct mcTempCipher
{
  uint8_t key[32];                /* Random key */
  int blockSize;                  /* MC_TEMP_BLOCK, or the page size of a database with smaller pages */
  mcTempBlock* blocks;            /* State per block */
  sqlite3_int64 nBlocks;          /* Number of entries in blocks */
  uint8_t blockBuffer[MC_TEMP_BLOCK];
                        /* Work buffer for one block, holds only ciphertext between calls;
                        ** SQLite uses a file from one thread at a time */
};

/*
** Create the cipher of a temporary file with a fresh random key
*/
static mcTempCipher* mcTempCreate(void)
{
  mcTempCipher* pTemp = (mcTempCipher*) sqlite3_malloc(sizeof(mcTempCipher));
  if (pTemp != NULL)
  {
    memset(pTemp, 0, sizeof(mcTempCipher));
    pTemp->blockSize = MC_TEMP_BLOCK;
    chacha20_rng(pTemp->key, sizeof(pTemp->key));
  }
  return pTemp;
}

/*
** Wipe and release the cipher of a temporary file
*/
static void mcTempFree(mcTempCipher* pTemp)
{
  if (pTemp != NULL)
  {
    sqlite3_free(pTemp->blocks);
    sqlite3mcSecureZeroMemory(pTemp, sizeof(mcTempCipher));
    sqlite3_free(pTemp);
  }
}

/*
** XOR the keystream of a block and generation into data, which starts at
** byte iOff of the block
*/
static void mcTempXorKeystream(mcTempCipher* pTemp, sqlite3_int64 iBlock, uint32_t generation,
                               uint8_t* data, int iOff, int n)
{
  uint8_t nonce[12];
  uint32_t counter = (uint32_t) (iOff / 64);
  int skip = iOff % 64;
  int i;
  for (i = 0; i < 4; i++) nonce[i] = (uint8_t) (generation >> (8 * i));
  for (i = 0; i < 8; i++) nonce[4 + i] = (uint8_t) (((sqlite3_uint64) iBlock) >> (8 * i));
  if (skip > 0)
  {
    uint8_t ks[64];
    int m = (n < 64 - skip) ? n : 64 - skip;
    memset(ks, 0, sizeof(ks));
    chacha20_xor(ks, sizeof(ks), pTemp->key, nonce, counter++);
    for (i = 0; i < m; i++) data[i] ^= ks[skip + i];
    sqlite3mcSecureZeroMemory(ks, sizeof(ks));
    data += m;
    n -= m;
  }
  if (n > 0)
  {
    chacha20_xor(data, (size_t) n, pTemp->key, nonce, counter);
  }
}

/*
** Read from a temporary file and decrypt the encrypted part of every block
** the request covers; the rest is returned as zeros
*/
static int mcTempRead(sqlite3mc_file* mcFile, void* buffer, int count, sqlite3_int64 offset)
{
  mcTempCipher* pTemp = mcFile->tempCipher;
  sqlite3_int64 pos, end = offset + count;
  int rc;
  assert(offset >= 0 && count >= 0);
  rc = REALFILE(mcFile)->pMethods->xRead(REALFILE(mcFile), buffer, count, offset);
  if (rc != SQLITE_OK && rc != SQLITE_IOERR_SHORT_READ) return rc;
  for (pos = offset; pos < end; )
  {
    sqlite3_int64 iBlock = pos / pTemp->blockSize;
    int iOff = (int) (pos % pTemp->blockSize);
    int n = (pTemp->blockSize - iOff < end - pos) ? pTemp->blockSize - iOff : (int) (end - pos);
    int nDecrypt = 0;
    uint8_t* data = (uint8_t*) buffer + (pos - offset);
    if (iBlock < pTemp->nBlocks && iOff < (int) pTemp->blocks[iBlock].valid)
    {
      mcTempBlock* pBlock = &pTemp->blocks[iBlock];
      if (pBlock->used == MC_TEMP_BROKEN) return SQLITE_IOERR_READ;
      nDecrypt = (iOff + n < (int) pBlock->valid) ? n : (int) pBlock->valid - iOff;
      mcTempXorKeystream(pTemp, iBlock, pBlock->generation, data, iOff, nDecrypt);
    }
    /* Bytes beyond the valid part read as zeros, whatever is on disk */
    if (nDecrypt < n) memset(data + nDecrypt, 0, n - nDecrypt);
    pos += n;
  }
  return rc;
}

/*
** Encrypt and write to a temporary file, block by block
*/
static int mcTempWrite(sqlite3mc_file* mcFile, const void* buffer, int count, sqlite3_int64 offset)
{
  mcTempCipher* pTemp = mcFile->tempCipher;
  sqlite3_file* pReal = REALFILE(mcFile);
  sqlite3_int64 pos, end = offset + count;
  int rc;
  assert(offset >= 0 && count >= 0);
  if (pTemp->nBlocks == 0 && (mcFile->openFlags & (SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TRANSIENT_DB)) &&
      count >= 512 && count < MC_TEMP_BLOCK && (count & (count - 1)) == 0 && offset % count == 0)
  {
    /* A database with small pages uses its page size as block size, so that
    ** writing a page never rewrites another; the first write tells the size */
    pTemp->blockSize = count;
  }
  for (pos = offset; pos < end; )
  {
    sqlite3_int64 iBlock = pos / pTemp->blockSize;
    int iOff = (int) (pos % pTemp->blockSize);
    int n = (pTemp->blockSize - iOff < end - pos) ? pTemp->blockSize - iOff : (int) (end - pos);
    int iStart;  /* First byte of the block to encrypt and write */
    int nKeep;   /* Bytes from the block start whose content is kept */
    mcTempBlock* pBlock;

    if (iBlock >= pTemp->nBlocks)
    {
      sqlite3_int64 nAlloc = (iBlock + 1) * 2;
      mcTempBlock* pNew = (mcTempBlock*) sqlite3_realloc64(pTemp->blocks, nAlloc * sizeof(mcTempBlock));
      if (pNew == NULL) return SQLITE_NOMEM;
      memset(pNew + pTemp->nBlocks, 0, (size_t) (nAlloc - pTemp->nBlocks) * sizeof(mcTempBlock));
      pTemp->blocks = pNew;
      pTemp->nBlocks = nAlloc;
    }
    pBlock = &pTemp->blocks[iBlock];

    if (iOff >= (int) pBlock->valid && pBlock->valid == pBlock->used)
    {
      /* Append: the keystream after the valid part is still unused */
      iStart = nKeep = (int) pBlock->valid;
    }
    else
    {
      /* Re-encrypt the block from its start with the next generation */
      if (pBlock->generation == MC_TEMP_MAX_GENERATION) return SQLITE_IOERR_WRITE;
      iStart = nKeep = 0;
      if (pBlock->valid > 0 && (iOff > 0 || iOff + n < (int) pBlock->valid))
      {
        if (pBlock->used == MC_TEMP_BROKEN) return SQLITE_IOERR_WRITE;
        nKeep = (int) pBlock->valid;
        rc = pReal->pMethods->xRead(pReal, pTemp->blockBuffer, nKeep, iBlock * pTemp->blockSize);
        if (rc != SQLITE_OK) return (rc == SQLITE_IOERR_SHORT_READ) ? SQLITE_IOERR_READ : rc;
        mcTempXorKeystream(pTemp, iBlock, pBlock->generation, pTemp->blockBuffer, 0, nKeep);
      }
      pBlock->generation++;
    }
    /* A gap before the new data reads as zeros */
    if (nKeep < iOff) memset(pTemp->blockBuffer + nKeep, 0, iOff - nKeep);
    memcpy(pTemp->blockBuffer + iOff, (const uint8_t*) buffer + (pos - offset), n);
    pBlock->valid = pBlock->used = (uint32_t) ((iOff + n > nKeep) ? iOff + n : nKeep);

    mcTempXorKeystream(pTemp, iBlock, pBlock->generation, pTemp->blockBuffer + iStart, iStart, (int) pBlock->valid - iStart);
    rc = pReal->pMethods->xWrite(pReal, pTemp->blockBuffer + iStart, (int) pBlock->valid - iStart, iBlock * pTemp->blockSize + iStart);
    if (rc != SQLITE_OK)
    {
      /* The new bytes read as zeros; if kept bytes were rewritten, reading
      ** the block fails until it is written completely */
      if (iStart < nKeep) pBlock->used = MC_TEMP_BROKEN;
      else pBlock->valid = (uint32_t) iStart;
      return rc;
    }
    pos += n;
  }
  return SQLITE_OK;
}

/*
** Truncate a temporary file and forget the bytes beyond the new size
*/
static int mcTempTruncate(sqlite3mc_file* mcFile, sqlite3_int64 size)
{
  mcTempCipher* pTemp = mcFile->tempCipher;
  int rc = REALFILE(mcFile)->pMethods->xTruncate(REALFILE(mcFile), size);
  if (rc == SQLITE_OK)
  {
    /* Shorten the valid parts; generation and used are kept, so no keystream is reused */
    sqlite3_int64 i;
    for (i = size / pTemp->blockSize; i < pTemp->nBlocks; i++)
    {
      sqlite3_int64 limit = size - i * pTemp->blockSize;
      if (limit < 0) limit = 0;
      if ((sqlite3_int64) pTemp->blocks[i].valid > limit) pTemp->blocks[i].valid = (uint32_t) limit;
    }
  }
  return rc;
}

#define SQLITE3MC_VFS_NAME ("multipleciphers")

#define SQLITE3MC_FCNTL_PVFS 0x3f98c078

/*
** Header sizes of WAL journal files
*/
static const int walFrameHeaderSize = 24;
static const int walFileHeaderSize = 32;

/*
** Global I/O method structure of SQLite3 Multiple Ciphers VFS
*/

#define IOMETHODS_VERSION_MIN 1
#define IOMETHODS_VERSION_MAX 3

static sqlite3_io_methods mcIoMethodsGlobal1 =
{
  1,                          /* iVersion */
  mcIoClose,                  /* xClose */
  mcIoRead,                   /* xRead */
  mcIoWrite,                  /* xWrite */
  mcIoTruncate,               /* xTruncate */
  mcIoSync,                   /* xSync */
  mcIoFileSize,               /* xFileSize */
  mcIoLock,                   /* xLock */
  mcIoUnlock,                 /* xUnlock */
  mcIoCheckReservedLock,      /* xCheckReservedLock */
  mcIoFileControl,            /* xFileControl */
  mcIoSectorSize,             /* xSectorSize */
  mcIoDeviceCharacteristics,  /* xDeviceCharacteristics */
  0,                          /* xShmMap */
  0,                          /* xShmLock */
  0,                          /* xShmBarrier */
  0,                          /* xShmUnmap */
  0,                          /* xFetch */
  0,                          /* xUnfetch */
};

static sqlite3_io_methods mcIoMethodsGlobal2 =
{
  2,                          /* iVersion */
  mcIoClose,                  /* xClose */
  mcIoRead,                   /* xRead */
  mcIoWrite,                  /* xWrite */
  mcIoTruncate,               /* xTruncate */
  mcIoSync,                   /* xSync */
  mcIoFileSize,               /* xFileSize */
  mcIoLock,                   /* xLock */
  mcIoUnlock,                 /* xUnlock */
  mcIoCheckReservedLock,      /* xCheckReservedLock */
  mcIoFileControl,            /* xFileControl */
  mcIoSectorSize,             /* xSectorSize */
  mcIoDeviceCharacteristics,  /* xDeviceCharacteristics */
  mcIoShmMap,                 /* xShmMap */
  mcIoShmLock,                /* xShmLock */
  mcIoShmBarrier,             /* xShmBarrier */
  mcIoShmUnmap,               /* xShmUnmap */
  0,                          /* xFetch */
  0,                          /* xUnfetch */
};

static sqlite3_io_methods mcIoMethodsGlobal3 =
{
  3,                          /* iVersion */
  mcIoClose,                  /* xClose */
  mcIoRead,                   /* xRead */
  mcIoWrite,                  /* xWrite */
  mcIoTruncate,               /* xTruncate */
  mcIoSync,                   /* xSync */
  mcIoFileSize,               /* xFileSize */
  mcIoLock,                   /* xLock */
  mcIoUnlock,                 /* xUnlock */
  mcIoCheckReservedLock,      /* xCheckReservedLock */
  mcIoFileControl,            /* xFileControl */
  mcIoSectorSize,             /* xSectorSize */
  mcIoDeviceCharacteristics,  /* xDeviceCharacteristics */
  mcIoShmMap,                 /* xShmMap */
  mcIoShmLock,                /* xShmLock */
  mcIoShmBarrier,             /* xShmBarrier */
  mcIoShmUnmap,               /* xShmUnmap */
  mcIoFetch,                  /* xFetch */
  mcIoUnfetch,                /* xUnfetch */
};

static sqlite3_io_methods* mcIoMethodsGlobal[] =
  { 0, &mcIoMethodsGlobal1 , &mcIoMethodsGlobal2 , &mcIoMethodsGlobal3 };

/*
** Internal functions
*/

/*
** Add an item to the list of main database files, if it is not already present.
*/
static void mcMainListAdd(sqlite3mc_file* pFile)
{
  assert( (pFile->openFlags & SQLITE_OPEN_MAIN_DB) );
  sqlite3_mutex_enter(pFile->pVfsMC->mutex);
  pFile->pMainNext = pFile->pVfsMC->pMain;
  pFile->pVfsMC->pMain = pFile;
  sqlite3_mutex_leave(pFile->pVfsMC->mutex);
}

/*
** Remove an item from the list of main database files.
*/
static void mcMainListRemove(sqlite3mc_file* pFile)
{
  sqlite3mc_file** pMainPrev;
  sqlite3_mutex_enter(pFile->pVfsMC->mutex);
  for (pMainPrev = &pFile->pVfsMC->pMain; *pMainPrev && *pMainPrev != pFile; pMainPrev = &((*pMainPrev)->pMainNext)){}
  if (*pMainPrev) *pMainPrev = pFile->pMainNext;
  pFile->pMainNext = 0;
  sqlite3_mutex_leave(pFile->pVfsMC->mutex);
}

/*
** Given that zFileName points to a buffer containing a database file name passed to
** either the xOpen() or xAccess() VFS method, search the list of main database files
** for a file handle opened by the same database connection on the corresponding
** database file.
*/
static sqlite3mc_file* mcFindDbMainFileName(sqlite3mc_vfs* mcVfs, const char* zFileName)
{
  sqlite3mc_file* pDb;
  sqlite3_mutex_enter(mcVfs->mutex);
  for (pDb = mcVfs->pMain; pDb && pDb->zFileName != zFileName; pDb = pDb->pMainNext){}
  sqlite3_mutex_leave(mcVfs->mutex);
  return pDb;
}

/*
** Find a pointer to the Multiple Ciphers VFS in use for a database connection.
*/
static sqlite3mc_vfs* mcFindVfs(sqlite3* db, const char* zDbName)
{
  sqlite3mc_vfs* pVfsMC = NULL;
  if (db->pVfs && db->pVfs->xOpen == mcVfsOpen)
  {
    /* The top level VFS is a Multiple Ciphers VFS */
    pVfsMC = (sqlite3mc_vfs*)(db->pVfs);
  }
  else
  {
    /*
    ** The top level VFS is not a Multiple Ciphers VFS.
    ** Retrieve the Multiple Ciphers VFS via file control function,
    ** if it is included in the VFS stack.
    */
    sqlite3mc_vfs* pVfs = NULL;
    if ((sqlite3_file_control(db, zDbName, SQLITE3MC_FCNTL_PVFS, &pVfs) == SQLITE_OK) &&
        (pVfs && pVfs->base.xOpen == mcVfsOpen))
    {
      pVfsMC = pVfs;
    }
  }
  return pVfsMC;
}

/*
** Check whether the VFS of the database file corresponding
** to the database schema name supports encryption.
*/
SQLITE_PRIVATE int sqlite3mcIsEncryptionSupported(sqlite3* db, const char* zDbName)
{
  sqlite3mc_vfs* pVfsMC = mcFindVfs(db, zDbName);
  return (pVfsMC != NULL);
}

/*
** Find the codec of the database file
** corresponding to the database schema name.
*/
SQLITE_PRIVATE Codec* sqlite3mcGetCodec(sqlite3* db, const char* zDbName)
{
  Codec* codec = NULL;
  sqlite3mc_vfs* pVfsMC = mcFindVfs(db, zDbName);

  if (pVfsMC)
  {
    const char* dbFileName = sqlite3_db_filename(db, zDbName);
    sqlite3mc_file* pDbMain = mcFindDbMainFileName(pVfsMC, dbFileName);
    if (pDbMain)
    {
      codec = pDbMain->codec;
    }
  }
  return codec;
}

/*
** Find the codec of the main database file.
*/
SQLITE_PRIVATE Codec* sqlite3mcGetMainCodec(sqlite3* db)
{
  return sqlite3mcGetCodec(db, "main");
}

SQLITE_PRIVATE int sqlite3mcIsBackupSupported(sqlite3* pSrc, const char* zSrc, sqlite3* pDest, const char* zDest)
{
  int ok = 1;
  if (pSrc != pDest)
  {
    Codec* codecSrc = sqlite3mcGetCodec(pSrc, zSrc);
    Codec* codecDest = sqlite3mcGetCodec(pDest, zDest);
    if (codecSrc && codecDest)
    {
      /* Both databases have a codec, are encrypted, and have the same page size */
      ok = sqlite3mcIsEncrypted(codecSrc) && sqlite3mcIsEncrypted(codecDest) &&
           (sqlite3mcGetPageSizeReadCipher(codecSrc) == sqlite3mcGetPageSizeWriteCipher(codecDest)) &&
           (sqlite3mcGetReadReserved(codecSrc) == sqlite3mcGetWriteReserved(codecDest));
    }
    else
    {
      /* At least one database has no codec */
      /* Backup supported if both databases are plain databases */
      ok = !codecSrc && !codecDest;
    }
  }
  return ok;
}

/*
** Set the codec of the database file with the given database file name.
**
** The parameter db, the handle of the database connection, is currently
** not used to determine the database file handle, for which the codec
** should be set. The reason is that for shared cache mode the database
** connection handle is not unique, and it is not even clear which
** connection handle is actually valid, because the association between
** connection handles and database file handles is not maintained properly.
*/
SQLITE_PRIVATE void sqlite3mcSetCodec(sqlite3* db, const char* zDbName, const char* zFileName, Codec* codec)
{
  sqlite3mc_file* pDbMain = NULL;
  sqlite3mc_vfs* pVfsMC = mcFindVfs(db, zDbName);
  if (pVfsMC)
  {
    pDbMain = mcFindDbMainFileName(pVfsMC, zFileName);
  }
  if (pDbMain)
  {
    Codec* prevCodec = pDbMain->codec;
    Codec* msgCodec = (codec) ? codec : prevCodec;
    pDbMain->codec = codec;
    if (msgCodec)
    {
      /* Reset error state of pager */
      mcReportCodecError(sqlite3mcGetBtShared(msgCodec), SQLITE_OK);
    }
    if (prevCodec)
    {
      /*
      ** Free a codec that was already associated with this main database file handle
      */
      sqlite3mcCodecFree(prevCodec);
    }
  }
  else
  {
    /*
    ** No main database file handle found, free codec
    */
    sqlite3mcCodecFree(codec);
  }
}

/*
** This function is called by the wal module when writing page content
** into the log file.
**
** This function returns a pointer to a buffer containing the encrypted
** page content. If a malloc fails, this function may return NULL.
*/
SQLITE_PRIVATE void* sqlite3mcPagerCodec(PgHdrMC* pPg)
{
  sqlite3_file* pFile = sqlite3PagerFile(pPg->pPager);
  void* aData = 0;
  if (pFile->pMethods == &mcIoMethodsGlobal1 ||
      pFile->pMethods == &mcIoMethodsGlobal2 ||
      pFile->pMethods == &mcIoMethodsGlobal3)
  {
    sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
    Codec* codec = mcFile->codec;
    if (codec != 0 && codec->m_walLegacy == 0 && sqlite3mcIsEncrypted(codec))
    {
      aData = sqlite3mcCodec(codec, pPg->pData, pPg->pgno, 6);
    }
    else
    {
      aData = (char*) pPg->pData;
    }
  }
  else
  {
    aData = (char*) pPg->pData;
  }
  return aData;
}

/*
** Implementation of VFS methods
*/

static int mcVfsOpen(sqlite3_vfs* pVfs, const char* zName, sqlite3_file* pFile, int flags, int* pOutFlags)
{
  int rc;
  sqlite3mc_vfs* mcVfs = (sqlite3mc_vfs*) pVfs;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
  mcFile->pFile = (sqlite3_file*) &mcFile[1];
  mcFile->pVfsMC = mcVfs;
  mcFile->openFlags = flags;
  mcFile->zFileName = zName;
  mcFile->codec = 0;
  mcFile->pMainDb = 0;
  mcFile->pMainNext = 0;
  mcFile->pageNo = 0;
  mcFile->tempCipher = 0;

  if (SQLITE3MC_ENCRYPT_TEMP_FILES && zName == NULL)
  {
    mcFile->tempCipher = mcTempCreate();
    if (mcFile->tempCipher == NULL) return SQLITE_NOMEM;
  }

  if (zName)
  {
    if (flags & SQLITE_OPEN_MAIN_DB)
    {
      mcFile->zFileName = zName;
      SQLITE3MC_DEBUG_LOG("mcVfsOpen MAIN: mcFile=%p fileName=%s\n", mcFile, mcFile->zFileName);
    }
    else if (flags & SQLITE_OPEN_TEMP_DB)
    {
      mcFile->zFileName = zName;
      SQLITE3MC_DEBUG_LOG("mcVfsOpen TEMP: mcFile=%p fileName=%s\n", mcFile, mcFile->zFileName);
    }
#if 0
    else if (flags & SQLITE_OPEN_TRANSIENT_DB)
    {
      /*
      ** TODO: When does SQLite open a transient DB? Could/Should it be encrypted?
      */
    }
#endif
    else if (flags & SQLITE_OPEN_MAIN_JOURNAL)
    {
      const char* dbFileName = sqlite3_filename_database(zName);
      mcFile->pMainDb = mcFindDbMainFileName(mcFile->pVfsMC, dbFileName);
      mcFile->zFileName = zName;
      SQLITE3MC_DEBUG_LOG("mcVfsOpen MAIN Journal: mcFile=%p fileName=%s dbFileName=%s\n", mcFile, mcFile->zFileName, dbFileName);
    }
#if 0
    else if (flags & SQLITE_OPEN_TEMP_JOURNAL)
    {
      /*
      ** TODO: When does SQLite open a temporary journal? Could/Should it be encrypted?
      */
    }
#endif
    else if (flags & SQLITE_OPEN_SUBJOURNAL)
    {
      const char* dbFileName = sqlite3_filename_database(zName);
      mcFile->pMainDb = mcFindDbMainFileName(mcFile->pVfsMC, dbFileName);
      mcFile->zFileName = zName;
      SQLITE3MC_DEBUG_LOG("mcVfsOpen SUB Journal: mcFile=%p fileName=%s dbFileName=%s\n", mcFile, mcFile->zFileName, dbFileName);
    }
#if 0
    else if (flags & SQLITE_OPEN_MASTER_JOURNAL)
    {
      /*
      ** Master journal contains only administrative information
      ** No encryption necessary
      */
    }
#endif
    else if (flags & SQLITE_OPEN_WAL)
    {
      const char* dbFileName = sqlite3_filename_database(zName);
      mcFile->pMainDb = mcFindDbMainFileName(mcFile->pVfsMC, dbFileName);
      mcFile->zFileName = zName;
      SQLITE3MC_DEBUG_LOG("mcVfsOpen WAL Journal: mcFile=%p fileName=%s dbFileName=%s\n", mcFile, mcFile->zFileName, dbFileName);
    }
  }

  rc = REALVFS(pVfs)->xOpen(REALVFS(pVfs), zName, mcFile->pFile, flags, pOutFlags);
  if (rc == SQLITE_OK)
  {
    /*
    ** Real open succeeded
    ** Initialize methods (use same version number as underlying implementation
    ** Register main database files
    */
    int ioMethodsVersion = mcFile->pFile->pMethods->iVersion;
    if (ioMethodsVersion < IOMETHODS_VERSION_MIN ||
        ioMethodsVersion > IOMETHODS_VERSION_MAX)
    {
      /* If version out of range, use highest known version */
      ioMethodsVersion = IOMETHODS_VERSION_MAX;
    }
    pFile->pMethods = mcIoMethodsGlobal[ioMethodsVersion];
    if (flags & SQLITE_OPEN_MAIN_DB)
    {
      mcMainListAdd(mcFile);
    }
  }
  else
  {
    mcTempFree(mcFile->tempCipher);
    mcFile->tempCipher = 0;
  }
  return rc;
}

static int mcVfsDelete(sqlite3_vfs* pVfs, const char* zName, int syncDir)
{
  return REALVFS(pVfs)->xDelete(REALVFS(pVfs), zName, syncDir);
}

static int mcVfsAccess(sqlite3_vfs* pVfs, const char* zName, int flags, int* pResOut)
{
  return REALVFS(pVfs)->xAccess(REALVFS(pVfs), zName, flags, pResOut);
}

static int mcVfsFullPathname(sqlite3_vfs* pVfs, const char* zName, int nOut, char* zOut)
{
  return REALVFS(pVfs)->xFullPathname(REALVFS(pVfs), zName, nOut, zOut);
}

static void* mcVfsDlOpen(sqlite3_vfs* pVfs, const char* zFilename)
{
  return REALVFS(pVfs)->xDlOpen(REALVFS(pVfs), zFilename);
}

static void mcVfsDlError(sqlite3_vfs* pVfs, int nByte, char* zErrMsg)
{
  REALVFS(pVfs)->xDlError(REALVFS(pVfs), nByte, zErrMsg);
}

static void (*mcVfsDlSym(sqlite3_vfs* pVfs, void* p, const char* zSymbol))(void)
{
  return REALVFS(pVfs)->xDlSym(REALVFS(pVfs), p, zSymbol);
}

static void mcVfsDlClose(sqlite3_vfs* pVfs, void* p)
{
  REALVFS(pVfs)->xDlClose(REALVFS(pVfs), p);
}

static int mcVfsRandomness(sqlite3_vfs* pVfs, int nByte, char* zOut)
{
  return REALVFS(pVfs)->xRandomness(REALVFS(pVfs), nByte, zOut);
}

static int mcVfsSleep(sqlite3_vfs* pVfs, int microseconds)
{
  return REALVFS(pVfs)->xSleep(REALVFS(pVfs), microseconds);
}

static int mcVfsCurrentTime(sqlite3_vfs* pVfs, double* pOut)
{
  return REALVFS(pVfs)->xCurrentTime(REALVFS(pVfs), pOut);
}

static int mcVfsGetLastError(sqlite3_vfs* pVfs, int code, char* pOut)
{
  return REALVFS(pVfs)->xGetLastError(REALVFS(pVfs), code, pOut);
}

static int mcVfsCurrentTimeInt64(sqlite3_vfs* pVfs, sqlite3_int64* pOut)
{
  return REALVFS(pVfs)->xCurrentTimeInt64(REALVFS(pVfs), pOut);
}

static int mcVfsSetSystemCall(sqlite3_vfs* pVfs, const char* zName, sqlite3_syscall_ptr pNewFunc)
{
  return REALVFS(pVfs)->xSetSystemCall(REALVFS(pVfs), zName, pNewFunc);
}

static sqlite3_syscall_ptr mcVfsGetSystemCall(sqlite3_vfs* pVfs, const char* zName)
{
  return REALVFS(pVfs)->xGetSystemCall(REALVFS(pVfs), zName);
}

static const char* mcVfsNextSystemCall(sqlite3_vfs* pVfs, const char* zName)
{
  return REALVFS(pVfs)->xNextSystemCall(REALVFS(pVfs), zName);
}

/*
** IO methods
*/

static int mcIoClose(sqlite3_file* pFile)
{
  int rc;
  sqlite3mc_file* p = (sqlite3mc_file*) pFile;

  /*
  ** Unregister main database files
  */
  if (p->openFlags & SQLITE_OPEN_MAIN_DB)
  {
    mcMainListRemove(p);
  }

  /*
  ** Release codec memory
  */
  if (p->codec)
  {
    sqlite3mcCodecFree(p->codec);
    p->codec = 0;
  }
  mcTempFree(p->tempCipher);
  p->tempCipher = 0;

  assert(p->pMainNext == 0 && p->pVfsMC->pMain != p);
  rc = REALFILE(pFile)->pMethods->xClose(REALFILE(pFile));
  return rc;
}

/*
** Read operation on main database file
*/
static int mcReadMainDb(sqlite3_file* pFile, void* buffer, int count, sqlite3_int64 offset)
{
  int rc = SQLITE_OK;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;

  /*
  ** Special case: read 16 bytes salt from beginning of database file without decrypting
  */
  if (offset == 0 && count == 16)
  {
    return rc;
  }

  if (mcFile->codec != 0 && sqlite3mcIsEncrypted(mcFile->codec))
  {
    const int pageSize = sqlite3mcGetPageSize(mcFile->codec);
    const int deltaOffset = offset % pageSize;
    const int deltaCount = count % pageSize;
    if (deltaOffset || deltaCount)
    {
      /*
      ** Read partial page
      */
      int pageNo = 0;
      void* bufferDecrypted = 0;
      const sqlite3_int64 prevOffset = offset - deltaOffset;
      unsigned char* pageBuffer = sqlite3mcGetPageBuffer(mcFile->codec);

      /*
      ** Read complete page from file
      */
      rc = REALFILE(pFile)->pMethods->xRead(REALFILE(pFile), pageBuffer, pageSize, prevOffset);
      if (rc == SQLITE_IOERR_SHORT_READ)
      {
        return rc;
      }

      /*
      ** Determine page number and decrypt page buffer
      */
      pageNo = prevOffset / pageSize + 1;
      bufferDecrypted = sqlite3mcCodec(mcFile->codec, pageBuffer, pageNo, 3);
      rc = sqlite3mcGetCodecLastError(mcFile->codec);

      /*
      ** Return the requested content
      */
      if (deltaOffset)
      {
        memcpy(buffer, pageBuffer + deltaOffset, count);
      }
      else
      {
        memcpy(buffer, pageBuffer, count);
      }
    }
    else
    {
      /*
      ** Read full page(s)
      **
      ** In fact, SQLite reads only one database page at a time.
      ** This would allow to remove the page loop below.
      */
      unsigned char* data = (unsigned char*) buffer;
      int pageNo = offset / pageSize + 1;
      int nPages = count / pageSize;
      int iPage;
      for (iPage = 0; iPage < nPages; ++iPage)
      {
        void* bufferDecrypted = sqlite3mcCodec(mcFile->codec, data, pageNo, 3);
        rc = sqlite3mcGetCodecLastError(mcFile->codec);
        data += pageSize;
        offset += pageSize;
        ++pageNo;
      }
    }
  }
  return rc;
}

/*
** Read operation on main journal file
*/
static int mcReadMainJournal(sqlite3_file* pFile, const void* buffer, int count, sqlite3_int64 offset)
{
  int rc = SQLITE_OK;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
  Codec* codec = (mcFile->pMainDb) ? mcFile->pMainDb->codec : 0;

  if (codec != 0 && sqlite3mcIsEncrypted(codec))
  {
    const int pageSize = sqlite3mcGetPageSize(codec);

    if (count == pageSize && mcFile->pageNo != 0)
    {
      /*
      ** Decrypt the page buffer, but only if the page number is valid
      */
      void* bufferDecrypted = sqlite3mcCodec(codec, (char*) buffer, mcFile->pageNo, 3);
      rc = sqlite3mcGetCodecLastError(codec);
      mcFile->pageNo = 0;
    }
    else if (count == 4)
    {
      /*
      ** SQLite always reads the page number from the journal file
      ** immediately before the corresponding page content is read.
      */
      mcFile->pageNo = sqlite3Get4byte(buffer);
    }
  }
  return rc;
}

/*
** Read operation on subjournal file
*/
static int mcReadSubJournal(sqlite3_file* pFile, const void* buffer, int count, sqlite3_int64 offset)
{
  int rc = SQLITE_OK;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
  Codec* codec = (mcFile->pMainDb) ? mcFile->pMainDb->codec : 0;

  if (codec != 0 && sqlite3mcIsEncrypted(codec))
  {
    const int pageSize = sqlite3mcGetPageSize(codec);

    if (count == pageSize && mcFile->pageNo != 0)
    {
      /*
      ** Decrypt the page buffer, but only if the page number is valid
      */
      void* bufferDecrypted = sqlite3mcCodec(codec, (char*) buffer, mcFile->pageNo, 3);
      rc = sqlite3mcGetCodecLastError(codec);
    }
    else if (count == 4)
    {
      /*
      ** SQLite always reads the page number from the journal file
      ** immediately before the corresponding page content is read.
      */
      mcFile->pageNo = sqlite3Get4byte(buffer);
    }
  }
  return rc;
}

/*
** Read operation on WAL journal file
*/
static int mcReadWal(sqlite3_file* pFile, const void* buffer, int count, sqlite3_int64 offset)
{
  int rc = SQLITE_OK;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
  Codec* codec = (mcFile->pMainDb) ? mcFile->pMainDb->codec : 0;

  if (codec != 0 && sqlite3mcIsEncrypted(codec))
  {
    const int pageSize = sqlite3mcGetPageSize(codec);

    if (count == pageSize)
    {
      int pageNo = 0;
      unsigned char ac[4];

      /*
      ** Determine page number
      **
      ** It is necessary to explicitly read the page number from the frame header.
      */
      rc = REALFILE(pFile)->pMethods->xRead(REALFILE(pFile), ac, 4, offset - walFrameHeaderSize);
      if (rc == SQLITE_OK)
      {
        pageNo = sqlite3Get4byte(ac);
      }

      /*
      ** Decrypt page content if page number is valid
      */
      if (pageNo != 0)
      {
        void* bufferDecrypted = sqlite3mcCodec(codec, (char*)buffer, pageNo, 3);
        rc = sqlite3mcGetCodecLastError(codec);
      }
    }
    else if (codec->m_walLegacy != 0 && count == pageSize + walFrameHeaderSize)
    {
      int pageNo = sqlite3Get4byte(buffer);

      /*
      ** Decrypt page content if page number is valid
      */
      if (pageNo != 0)
      {
        void* bufferDecrypted = sqlite3mcCodec(codec, (char*)buffer+walFrameHeaderSize, pageNo, 3);
        rc = sqlite3mcGetCodecLastError(codec);
      }
    }
  }
  return rc;
}

static int mcIoRead(sqlite3_file* pFile, void* buffer, int count, sqlite3_int64 offset)
{
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
  int rc;
  if (mcFile->tempCipher)
  {
    return mcTempRead(mcFile, buffer, count, offset);
  }
  rc = REALFILE(pFile)->pMethods->xRead(REALFILE(pFile), buffer, count, offset);
  if (rc != SQLITE_OK)
  {
    return rc;
  }

  if (mcFile->openFlags & SQLITE_OPEN_MAIN_DB)
  {
    rc = mcReadMainDb(pFile, buffer, count, offset);
  }
#if 0
  else if (mcFile->openFlags & SQLITE_OPEN_TEMP_DB)
  {
    /*
    ** TODO: Could/Should a temporary database file be encrypted?
    */
  }
#endif
#if 0
  else if (mcFile->openFlags & SQLITE_OPEN_TRANSIENT_DB)
  {
    /*
    ** TODO: Could/Should a transient database file be encrypted?
    */
  }
#endif
  else if (mcFile->openFlags & SQLITE_OPEN_MAIN_JOURNAL)
  {
    rc = mcReadMainJournal(pFile, buffer, count, offset);
  }
#if 0
  else if (mcFile->openFlags & SQLITE_OPEN_TEMP_JOURNAL)
  {
    /*
    ** TODO: Could/Should a temporary journal file be encrypted?
    */
  }
#endif
  else if (mcFile->openFlags & SQLITE_OPEN_SUBJOURNAL)
  {
    rc = mcReadSubJournal(pFile, buffer, count, offset);
  }
#if 0
  else if (mcFile->openFlags & SQLITE_OPEN_MASTER_JOURNAL)
  {
    /*
    ** Master journal contains only administrative information
    ** No encryption necessary
    */
  }
#endif
  else if (mcFile->openFlags & SQLITE_OPEN_WAL)
  {
    rc = mcReadWal(pFile, buffer, count, offset);
  }
  return rc;
}

/*
** Write operation on main database file
*/
static int mcWriteMainDb(sqlite3_file* pFile, const void* buffer, int count, sqlite3_int64 offset)
{
  int rc = SQLITE_OK;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;

  if (mcFile->codec != 0 && sqlite3mcIsEncrypted(mcFile->codec))
  {
    const int pageSize = sqlite3mcGetPageSize(mcFile->codec);
    const int deltaOffset = offset % pageSize;
    const int deltaCount = count % pageSize;

    if (deltaOffset || deltaCount)
    {
      /*
      ** Write partial page
      **
      ** SQLite does never write partial database pages.
      ** Therefore no encryption is required in this case.
      */
      rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
    }
    else
    {
      /*
      ** Write full page(s)
      **
      ** In fact, SQLite writes only one database page at a time.
      ** This would allow to remove the page loop below.
      */
      char* data = (char*) buffer;
      int pageNo = offset / pageSize + 1;
      int nPages = count / pageSize;
      int iPage;
      for (iPage = 0; iPage < nPages; ++iPage)
      {
        void* bufferEncrypted = sqlite3mcCodec(mcFile->codec, data, pageNo, 6);
        rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), bufferEncrypted, pageSize, offset);
        data += pageSize;
        offset += pageSize;
        ++pageNo;
      }
    }
  }
  else
  {
    /*
    ** Write buffer without encryption
    */
    rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
  }
  return rc;
}

/*
** Write operation on main journal file
*/
static int mcWriteMainJournal(sqlite3_file* pFile, const void* buffer, int count, sqlite3_int64 offset)
{
  int rc = SQLITE_OK;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
  Codec* codec = (mcFile->pMainDb) ? mcFile->pMainDb->codec : 0;

  if (codec != 0 && sqlite3mcIsEncrypted(codec))
  {
    const int pageSize = sqlite3mcGetPageSize(codec);
    const int frameSize = pageSize + 4 + 4;

    if (count == pageSize && mcFile->pageNo != 0)
    {
      /*
      ** Encrypt the page buffer, but only if the page number is valid
      */
      void* bufferEncrypted = sqlite3mcCodec(codec, (char*) buffer, mcFile->pageNo, 7);
      rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), bufferEncrypted, pageSize, offset);
    }
    else
    {
      /*
      ** Write buffer without encryption
      */
      rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
      if (count == 4)
      {
        /*
        ** SQLite always writes the page number to the journal file
        ** immediately before the corresponding page content is written.
        */
        mcFile->pageNo = (rc == SQLITE_OK) ? sqlite3Get4byte(buffer) : 0;
      }
    }
  }
  else
  {
    /*
    ** Write buffer without encryption
    */
    rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
  }
  return rc;
}

/*
** Write operation on subjournal file
*/
static int mcWriteSubJournal(sqlite3_file* pFile, const void* buffer, int count, sqlite3_int64 offset)
{
  int rc = SQLITE_OK;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
  Codec* codec = (mcFile->pMainDb) ? mcFile->pMainDb->codec : 0;

  if (codec != 0 && sqlite3mcIsEncrypted(codec))
  {
    const int pageSize = sqlite3mcGetPageSize(codec);
    const int frameSize = pageSize + 4;

    if (count == pageSize && mcFile->pageNo != 0)
    {
      /*
      ** Encrypt the page buffer, but only if the page number is valid
      */
      void* bufferEncrypted = sqlite3mcCodec(codec, (char*) buffer, mcFile->pageNo, 7);
      rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), bufferEncrypted, pageSize, offset);
    }
    else
    {
      /*
      ** Write buffer without encryption
      */
      rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
      if (count == 4)
      {
        /*
        ** SQLite always writes the page number to the journal file
        ** immediately before the corresponding page content is written.
        */
        mcFile->pageNo = (rc == SQLITE_OK) ? sqlite3Get4byte(buffer) : 0;
      }
    }
  }
  else
  {
    /*
    ** Write buffer without encryption
    */
    rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
  }
  return rc;
}

/*
** Write operation on WAL journal file
*/
static int mcWriteWal(sqlite3_file* pFile, const void* buffer, int count, sqlite3_int64 offset)
{
  int rc = SQLITE_OK;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
  Codec* codec = (mcFile->pMainDb) ? mcFile->pMainDb->codec : 0;

  if (codec != 0 && codec->m_walLegacy != 0 && sqlite3mcIsEncrypted(codec))
  {
    const int pageSize = sqlite3mcGetPageSize(codec);

    if (count == pageSize)
    {
      int pageNo = 0;
      unsigned char ac[4];

      /*
      ** Read the corresponding page number from the file
      **
      ** In WAL mode SQLite does not write the page number of a page to file
      ** immediately before writing the corresponding page content.
      ** Page numbers and checksums are written to file independently.
      ** Therefore it is necessary to explicitly read the page number
      ** on writing to file the content of a page.
      */
      rc = REALFILE(pFile)->pMethods->xRead(REALFILE(pFile), ac, 4, offset - walFrameHeaderSize);
      if (rc == SQLITE_OK)
      {
        pageNo = sqlite3Get4byte(ac);
      }

      if (pageNo != 0)
      {
        /*
        ** Encrypt the page buffer, but only if the page number is valid
        */
        void* bufferEncrypted = sqlite3mcCodec(codec, (char*) buffer, pageNo, 7);
        rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), bufferEncrypted, pageSize, offset);
      }
      else
      {
        /*
        ** Write buffer without encryption if the page number could not be determined
        */
        rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
      }
    }
    else if (count == pageSize + walFrameHeaderSize)
    {
      int pageNo = sqlite3Get4byte(buffer);
      if (pageNo != 0)
      {
        /*
        ** Encrypt the page buffer, but only if the page number is valid
        */
        void* bufferEncrypted = sqlite3mcCodec(codec, (char*)buffer+walFrameHeaderSize, pageNo, 7);
        rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, walFrameHeaderSize, offset);
        rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), bufferEncrypted, pageSize, offset+walFrameHeaderSize);
      }
      else
      {
        /*
        ** Write buffer without encryption if the page number could not be determined
        */
        rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
      }
    }
    else
    {
      /*
      ** Write buffer without encryption if it is not a database page
      */
      rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
    }
  }
  else
  {
    /*
    ** Write buffer without encryption
    */
    rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
  }
  return rc;
}

static int mcIoWrite(sqlite3_file* pFile, const void* buffer, int count, sqlite3_int64 offset)
{
  int rc = SQLITE_OK;
  int doDefault = 1;
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;

  if (mcFile->tempCipher)
  {
    rc = mcTempWrite(mcFile, buffer, count, offset);
  }
  else if (mcFile->openFlags & SQLITE_OPEN_MAIN_DB)
  {
    rc = mcWriteMainDb(pFile, buffer, count, offset);
  }
#if 0
  else if (mcFile->openFlags & SQLITE_OPEN_TEMP_DB)
  {
    /*
    ** TODO: Could/Should a temporary database file be encrypted?
    */
  }
#endif
#if 0
  else if (mcFile->openFlags & SQLITE_OPEN_TRANSIENT_DB)
  {
    /*
    ** TODO: Could/Should a transient database file be encrypted?
    */
  }
#endif
  else if (mcFile->openFlags & SQLITE_OPEN_MAIN_JOURNAL)
  {
    rc = mcWriteMainJournal(pFile, buffer, count, offset);
  }
#if 0
  else if (mcFile->openFlags & SQLITE_OPEN_TEMP_JOURNAL)
  {
    /*
    ** TODO: Could/Should a temporary journal file be encrypted?
    */
  }
#endif
  else if (mcFile->openFlags & SQLITE_OPEN_SUBJOURNAL)
  {
    rc = mcWriteSubJournal(pFile, buffer, count, offset);
}
#if 0
  else if (mcFile->openFlags & SQLITE_OPEN_MASTER_JOURNAL)
  {
    /*
    ** Master journal contains only administrative information
    ** No encryption necessary
    */
  }
#endif
  /*
  ** The page content is encrypted in memory in the WAL journal handler.
  ** This provides for compatibility with legacy applications using the
  ** previous SQLITE_HAS_CODEC encryption API.
  */
  else if (mcFile->openFlags & SQLITE_OPEN_WAL)
  {
    rc = mcWriteWal(pFile, buffer, count, offset);
  }
  else
  {
    rc = REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), buffer, count, offset);
  }
  return rc;
}

static int mcIoTruncate(sqlite3_file* pFile, sqlite3_int64 size)
{
  sqlite3mc_file* mcFile = (sqlite3mc_file*) pFile;
  if (mcFile->tempCipher)
  {
    return mcTempTruncate(mcFile, size);
  }
  return REALFILE(pFile)->pMethods->xTruncate(REALFILE(pFile), size);
}

static int mcIoSync(sqlite3_file* pFile, int flags)
{
  return REALFILE(pFile)->pMethods->xSync(REALFILE(pFile), flags);
}

static int mcIoFileSize(sqlite3_file* pFile, sqlite3_int64* pSize)
{
  return REALFILE(pFile)->pMethods->xFileSize(REALFILE(pFile), pSize);
}

static int mcIoLock(sqlite3_file* pFile, int lock)
{
  return REALFILE(pFile)->pMethods->xLock(REALFILE(pFile), lock);
}

static int mcIoUnlock(sqlite3_file* pFile, int lock)
{
  return REALFILE(pFile)->pMethods->xUnlock(REALFILE(pFile), lock);
}

static int mcIoCheckReservedLock(sqlite3_file* pFile, int* pResOut)
{
  return REALFILE(pFile)->pMethods->xCheckReservedLock(REALFILE(pFile), pResOut);
}

static int mcIoFileControl(sqlite3_file* pFile, int op, void* pArg)
{
  int rc = SQLITE_OK;
  int doReal = 1;
  sqlite3mc_file* p = (sqlite3mc_file*) pFile;

  switch (op)
  {
    case SQLITE3MC_FCNTL_PVFS:
      {
        *(sqlite3mc_vfs**) pArg = p->pVfsMC;
        doReal = 0;
      }
      break;
    case SQLITE_FCNTL_PDB:
      {
#if 0
        /*
        ** pArg points to the sqlite3* handle for which the database file was opened.
        ** In shared cache mode this function is invoked for every use of the database
        ** file in a connection. Unfortunately there is no notification, when a database
        ** file is no longer used by a connection (close in normal mode).
        **
        ** For now, the database handle will not be stored in the file object.
        ** In the future, this behaviour may be changed, especially, if shared cache mode
        ** is disabled. Shared cache mode is enabled for backward compatibility only, its
        ** use is not recommended. A future version of SQLite might disable it by default.
        */
        sqlite3* db = *((sqlite3**) pArg);
#endif
      }
      break;
    case SQLITE_FCNTL_PRAGMA:
      {
        /*
        ** Handle pragmas specific to this database file
        */
#if 0
        /*
        ** SQLite invokes this function for all pragmas, which are related to the schema
        ** associated with this database file. In case of an unknown pragma, this function
        ** should return SQLITE_NOTFOUND. However, since this VFS is just a shim, handling
        ** of the pragma is forwarded to the underlying real VFS in such a case.
        **
        ** For now, all pragmas are handled at the connection level.
        ** For this purpose the SQLite's pragma handling is intercepted.
        ** The latter requires a patch of SQLite's amalgamation code.
        ** Maybe a future version will be able to abandon the patch.
        */
        char* pragmaName = ((char**) pArg)[1];
        char* pragmaValue = ((char**) pArg)[2];
        if (sqlite3StrICmp(pragmaName, "...") == 0)
        {
          /* Action */
          /* ((char**) pArg)[0] = sqlite3_mprintf("error msg.");*/
          doReal = 0;
        }
#endif
      }
      break;
    default:
      break;
  }
  if (doReal)
  {
    rc = REALFILE(pFile)->pMethods->xFileControl(REALFILE(pFile), op, pArg);
    if (rc == SQLITE_OK && op == SQLITE_FCNTL_VFSNAME)
    {
      sqlite3mc_vfs* pVfsMC = p->pVfsMC;
      char* zIn = *(char**)pArg;
      char* zOut = sqlite3_mprintf("%s/%z", pVfsMC->base.zName, zIn);
      *(char**)pArg = zOut;
      if (zOut == 0) rc = SQLITE_NOMEM;
    }
  }
  return rc;
}

static int mcIoSectorSize(sqlite3_file* pFile)
{
  if (REALFILE(pFile)->pMethods->xSectorSize)
    return REALFILE(pFile)->pMethods->xSectorSize(REALFILE(pFile));
  else
    return SQLITE_DEFAULT_SECTOR_SIZE;
}

static int mcIoDeviceCharacteristics(sqlite3_file* pFile)
{
  return REALFILE(pFile)->pMethods->xDeviceCharacteristics(REALFILE(pFile));
}

static int mcIoShmMap(sqlite3_file* pFile, int iPg, int pgsz, int map, void volatile** p)
{
  return REALFILE(pFile)->pMethods->xShmMap(REALFILE(pFile), iPg, pgsz, map, p);
}

static int mcIoShmLock(sqlite3_file* pFile, int offset, int n, int flags)
{
  return REALFILE(pFile)->pMethods->xShmLock(REALFILE(pFile), offset, n, flags);
}

static void mcIoShmBarrier(sqlite3_file* pFile)
{
  REALFILE(pFile)->pMethods->xShmBarrier(REALFILE(pFile));
}

static int mcIoShmUnmap(sqlite3_file* pFile, int deleteFlag)
{
  return REALFILE(pFile)->pMethods->xShmUnmap(REALFILE(pFile), deleteFlag);
}

static int mcIoFetch(sqlite3_file* pFile, sqlite3_int64 iOfst, int iAmt, void** pp)
{
  if (((sqlite3mc_file*) pFile)->tempCipher)
  {
    /* No memory mapping for encrypted temporary files; SQLite falls back to xRead */
    *pp = 0;
    return SQLITE_OK;
  }
  return REALFILE(pFile)->pMethods->xFetch(REALFILE(pFile), iOfst, iAmt, pp);
}

static int mcIoUnfetch( sqlite3_file* pFile, sqlite3_int64 iOfst, void* p)
{
  return REALFILE(pFile)->pMethods->xUnfetch(REALFILE(pFile), iOfst, p);
}

/*
** SQLite3 Multiple Ciphers internal API functions
*/

/*
** Check the requested VFS
*/
SQLITE_PRIVATE int
sqlite3mcCheckVfs(const char* zVfs)
{
  int rc = SQLITE_OK;
  sqlite3_vfs* pVfs = sqlite3_vfs_find(zVfs);
  if (pVfs == NULL)
  {
    /* VFS not found */
    int prefixLen = (int) strlen(SQLITE3MC_VFS_NAME);
    if (strncmp(zVfs, SQLITE3MC_VFS_NAME, prefixLen) == 0)
    {
      /* VFS name starts with prefix. */
      const char* zVfsNameEnd = zVfs + strlen(SQLITE3MC_VFS_NAME);
      if (*zVfsNameEnd == '-')
      {
        /* Prefix separator found, determine the name of the real VFS. */
        const char* zVfsReal = zVfsNameEnd + 1;
        pVfs = sqlite3_vfs_find(zVfsReal);
        if (pVfs != NULL)
        {
          /* Real VFS exists */
          /* Create VFS with encryption support based on real VFS */
          rc = sqlite3mc_vfs_create(zVfsReal, 0);
        }
      }
    }
  }
  return rc;
}

SQLITE_PRIVATE int
sqlite3mcPagerHasCodec(PagerMC* pPager)
{
  int hasCodec = 0;
  sqlite3mc_vfs* pVfsMC = NULL;
  sqlite3_vfs* pVfs = pPager->pVfs;

  /* Check whether the VFS stack of the pager contains a Multiple Ciphers VFS */
  for (; pVfs; pVfs = pVfs->pNext)
  {
    if (pVfs && pVfs->xOpen == mcVfsOpen)
    {
      /* Multiple Ciphers VFS found */
      pVfsMC = (sqlite3mc_vfs*)(pVfs);
      break;
    }
  }

  /* Check whether codec is enabled for associated database file */
  if (pVfsMC)
  {
    sqlite3mc_file* mcFile = mcFindDbMainFileName(pVfsMC, pPager->zFilename);
    if (mcFile)
    {
      Codec* codec = mcFile->codec;
      hasCodec = (codec != 0 && sqlite3mcIsEncrypted(codec));
    }
  }
  return hasCodec;
}

/*
** SQLite3 Multiple Ciphers external API functions
*/

static void mcVfsDestroy(sqlite3_vfs* pVfs)
{
  if (pVfs && pVfs->xOpen == mcVfsOpen)
  {
    /* Destroy the VFS instance only if no file is referring to it any longer */
    if (((sqlite3mc_vfs*) pVfs)->pMain == 0)
    {
      sqlite3_mutex_free(((sqlite3mc_vfs*)pVfs)->mutex);
      sqlite3_vfs_unregister(pVfs);
      sqlite3_free(pVfs);
    }
  }
}

/*
** Unregister and destroy a Multiple Ciphers VFS
** created by an earlier call to sqlite3mc_vfs_create().
*/
SQLITE_API void sqlite3mc_vfs_destroy(const char* zName)
{
  mcVfsDestroy(sqlite3_vfs_find(zName));
}

/*
** Create a Multiple Ciphers VFS based on the underlying VFS with name given by zVfsReal.
** If makeDefault is true, the VFS is set as the default VFS.
*/
SQLITE_API int sqlite3mc_vfs_create(const char* zVfsReal, int makeDefault)
{
  static sqlite3_vfs mcVfsTemplate =
  {
    3,                      /* iVersion */
    0,                      /* szOsFile */
    1024,                   /* mxPathname */
    0,                      /* pNext */
    0,                      /* zName */
    0,                      /* pAppData */
    mcVfsOpen,              /* xOpen */
    mcVfsDelete,            /* xDelete */
    mcVfsAccess,            /* xAccess */
    mcVfsFullPathname,      /* xFullPathname */
#ifndef SQLITE_OMIT_LOAD_EXTENSION
    mcVfsDlOpen,            /* xDlOpen */
    mcVfsDlError,           /* xDlError */
    mcVfsDlSym,             /* xDlSym */
    mcVfsDlClose,           /* xDlClose */
#else
    0, 0, 0, 0,
#endif
    mcVfsRandomness,        /* xRandomness */
    mcVfsSleep,             /* xSleep */
    mcVfsCurrentTime,       /* xCurrentTime */
    mcVfsGetLastError,      /* xGetLastError */
    mcVfsCurrentTimeInt64,  /* xCurrentTimeInt64 */
    mcVfsSetSystemCall,     /* xSetSystemCall */
    mcVfsGetSystemCall,     /* xGetSystemCall */
    mcVfsNextSystemCall     /* xNextSystemCall */
  };
  sqlite3mc_vfs* pVfsNew = 0;  /* Newly allocated VFS */
  sqlite3_vfs* pVfsReal = sqlite3_vfs_find(zVfsReal); /* Real VFS */
  int rc;

  if (pVfsReal)
  {
    size_t nPrefix = strlen(SQLITE3MC_VFS_NAME);
    size_t nRealName = strlen(pVfsReal->zName);
    size_t nName =  nPrefix + nRealName + 1;
    size_t nByte = sizeof(sqlite3mc_vfs) + nName + 1;
    pVfsNew = (sqlite3mc_vfs*) sqlite3_malloc64(nByte);
    if (pVfsNew)
    {
      char* zSpace = (char*) &pVfsNew[1];
      memset(pVfsNew, 0, nByte);
      memcpy(&pVfsNew->base, &mcVfsTemplate, sizeof(sqlite3_vfs));
      pVfsNew->base.iVersion = pVfsReal->iVersion;
      pVfsNew->base.pAppData = pVfsReal;
      pVfsNew->base.mxPathname = pVfsReal->mxPathname;
      pVfsNew->base.szOsFile = sizeof(sqlite3mc_file) + pVfsReal->szOsFile;

      /* Set name of new VFS as combination of the multiple ciphers prefix and the name of the underlying VFS */
      pVfsNew->base.zName = (const char*) zSpace;
      memcpy(zSpace, SQLITE3MC_VFS_NAME, nPrefix);
      memcpy(zSpace + nPrefix, "-", 1);
      memcpy(zSpace + nPrefix + 1, pVfsReal->zName, nRealName);

      /* Allocate the mutex and register the new VFS */
      pVfsNew->mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_RECURSIVE);
      if (pVfsNew->mutex)
      {
        rc = sqlite3_vfs_register(&pVfsNew->base, makeDefault);
        if (rc != SQLITE_OK)
        {
          sqlite3_mutex_free(pVfsNew->mutex);
        }
      }
      else
      {
        /* Mutex could not be allocated */
        rc = SQLITE_NOMEM;
      }
      if (rc != SQLITE_OK)
      {
        /* Mutex could not be allocated or new VFS could not be registered */
        sqlite3_free(pVfsNew);
      }
    }
    else
    {
      /* New VFS could not be allocated */
      rc = SQLITE_NOMEM;
    }
  }
  else
  {
    /* Underlying VFS not found */
    rc = SQLITE_NOTFOUND;
  }
  return rc;
}

/*
** Shutdown all registered SQLite3 Multiple Ciphers VFSs
*/
SQLITE_API void sqlite3mc_vfs_shutdown()
{
  sqlite3_vfs* pVfs;
  sqlite3_vfs* pVfsNext;
  for (pVfs = sqlite3_vfs_find(0); pVfs; pVfs = pVfsNext)
  {
    pVfsNext = pVfs->pNext;
    mcVfsDestroy(pVfs);
  }
}
