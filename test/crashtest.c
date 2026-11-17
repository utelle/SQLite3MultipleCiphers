/*
** Crash and I/O error tests for encrypted databases.
**
** A VFS below the SQLite3 Multiple Ciphers VFS keeps all files in memory and
** counts every write, sync, truncate and delete of a named file. An operation
** (a transaction, a rekey, VACUUM, ...) is run again and again; in run k the
** k-th of these calls fails in one of four ways:
**
**   crash      the process stops: the call and everything after it is lost
**   torn       like crash, but the first half of the failing write arrives
**   powerloss  every file falls back to the content of its last sync
**   ioerr      the call returns an I/O error, the connection carries on
**
** Then a new connection opens the files and must find the database complete
** in the old or in the new state: it opens with the old or the new key,
** integrity_check is ok, the rows match one of the two states exactly, the
** state stays the same after closing and opening again, and no file contains
** the plaintext marker of the rows (unless the operation removes encryption).
** If the failing call was an I/O error and the operation reported success,
** the database must be in the new state.
**
** Usage: crashtest [full] [verbose] [filter]
**   default  a selection that runs in a few seconds
**   full     all ciphers, journal modes, page sizes and operations
**   verbose  report every failure, not only the first three per scenario
**   filter   only scenarios whose name contains this text
*/

#include "sqlite3mc.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MARKER "CRASHMARKER"
#define MAX_FILES 16
#define MAX_SHM 64

/*
** In-memory files
*/
typedef struct CtData CtData;
struct CtData
{
  char* zName;               /* NULL for anonymous temporary files */
  unsigned char* a;          /* current content */
  sqlite3_int64 n;
  unsigned char* aSynced;    /* content at the last sync */
  sqlite3_int64 nSynced;
  int nRef;
  void* apShm[MAX_SHM];      /* wal-index regions */
  int szShm;
};

typedef struct CtFile CtFile;
struct CtFile
{
  sqlite3_file base;
  CtData* pData;
  int isTemp;
};

static CtData* disk[MAX_FILES];

/* Failure injection */
enum { MODE_NONE, MODE_CRASH, MODE_TORN, MODE_POWERLOSS, MODE_IOERR };
static const char* modeNames[] = { "none", "crash", "torn", "powerloss", "ioerr" };
static int failMode;
static int failAt;        /* 0: never */
static int opCount;
static int crashed;
static int ioerrHit;

static sqlite3_vfs ctVfs;
static sqlite3_vfs* baseVfs;

static void ctDataFreeShm(CtData* d)
{
  int i;
  for (i = 0; i < MAX_SHM; i++)
  {
    sqlite3_free(d->apShm[i]);
    d->apShm[i] = NULL;
  }
}

static void ctDataFree(CtData* d)
{
  if (d == NULL) return;
  ctDataFreeShm(d);
  sqlite3_free(d->zName);
  sqlite3_free(d->a);
  sqlite3_free(d->aSynced);
  sqlite3_free(d);
}

static CtData* diskFind(const char* zName)
{
  int i;
  for (i = 0; i < MAX_FILES; i++)
  {
    if (disk[i] != NULL && strcmp(disk[i]->zName, zName) == 0) return disk[i];
  }
  return NULL;
}

static int diskAdd(CtData* d)
{
  int i;
  for (i = 0; i < MAX_FILES; i++)
  {
    if (disk[i] == NULL) { disk[i] = d; return SQLITE_OK; }
  }
  return SQLITE_FULL;
}

static void diskRemove(CtData* d)
{
  int i;
  for (i = 0; i < MAX_FILES; i++)
  {
    if (disk[i] == d) disk[i] = NULL;
  }
}

static int ctResize(CtData* d, sqlite3_int64 n)
{
  if (n > d->n)
  {
    unsigned char* a = sqlite3_realloc64(d->a, n);
    if (a == NULL) return SQLITE_NOMEM;
    memset(a + d->n, 0, (size_t) (n - d->n));
    d->a = a;
  }
  d->n = n;
  return SQLITE_OK;
}

/*
** Decide what happens to a modifying call of a named file.
** Returns 1 if the call is to be carried out, 0 if it has to fail.
*/
static int failNow(void)
{
  if (crashed) return 0;
  opCount++;
  if (failAt != 0 && opCount == failAt)
  {
    if (failMode == MODE_IOERR)
    {
      ioerrHit = 1;
      return 0;
    }
    crashed = 1;
    return 0;
  }
  return 1;
}

static int ctClose(sqlite3_file* f)
{
  CtFile* p = (CtFile*) f;
  CtData* d = p->pData;
  if (d != NULL && --d->nRef == 0 && p->isTemp) ctDataFree(d);
  p->pData = NULL;
  return SQLITE_OK;
}

static int ctRead(sqlite3_file* f, void* buf, int amt, sqlite3_int64 ofst)
{
  CtData* d = ((CtFile*) f)->pData;
  if (ofst >= d->n)
  {
    memset(buf, 0, amt);
    return SQLITE_IOERR_SHORT_READ;
  }
  if (ofst + amt > d->n)
  {
    int got = (int) (d->n - ofst);
    memcpy(buf, d->a + ofst, got);
    memset((char*) buf + got, 0, amt - got);
    return SQLITE_IOERR_SHORT_READ;
  }
  memcpy(buf, d->a + ofst, amt);
  return SQLITE_OK;
}

static int ctWrite(sqlite3_file* f, const void* buf, int amt, sqlite3_int64 ofst)
{
  CtFile* p = (CtFile*) f;
  CtData* d = p->pData;
  if (!p->isTemp && !failNow())
  {
    if (crashed && failMode == MODE_TORN && opCount == failAt)
    {
      /* The first half of the failing write reaches the disk */
      int half = amt / 2;
      if (ofst + half > d->n && ctResize(d, ofst + half) != SQLITE_OK) return SQLITE_NOMEM;
      memcpy(d->a + ofst, buf, half);
    }
    return SQLITE_IOERR_WRITE;
  }
  if (ofst + amt > d->n && ctResize(d, ofst + amt) != SQLITE_OK) return SQLITE_NOMEM;
  memcpy(d->a + ofst, buf, amt);
  return SQLITE_OK;
}

static int ctTruncate(sqlite3_file* f, sqlite3_int64 size)
{
  CtFile* p = (CtFile*) f;
  if (!p->isTemp && !failNow()) return SQLITE_IOERR_TRUNCATE;
  if (size < p->pData->n) p->pData->n = size;
  return SQLITE_OK;
}

static int ctSync(sqlite3_file* f, int flags)
{
  CtFile* p = (CtFile*) f;
  CtData* d = p->pData;
  (void) flags;
  if (p->isTemp) return SQLITE_OK;
  if (!failNow()) return SQLITE_IOERR_FSYNC;
  sqlite3_free(d->aSynced);
  d->aSynced = sqlite3_malloc64(d->n > 0 ? d->n : 1);
  if (d->aSynced == NULL) return SQLITE_NOMEM;
  memcpy(d->aSynced, d->a, (size_t) d->n);
  d->nSynced = d->n;
  return SQLITE_OK;
}

static int ctFileSize(sqlite3_file* f, sqlite3_int64* pSize)
{
  *pSize = ((CtFile*) f)->pData->n;
  return SQLITE_OK;
}

static int ctLock(sqlite3_file* f, int l) { (void) f; (void) l; return SQLITE_OK; }
static int ctCheckReserved(sqlite3_file* f, int* pRes) { (void) f; *pRes = 0; return SQLITE_OK; }
static int ctFileControl(sqlite3_file* f, int op, void* arg) { (void) f; (void) op; (void) arg; return SQLITE_NOTFOUND; }
static int ctSectorSize(sqlite3_file* f) { (void) f; return 512; }
static int ctDeviceChar(sqlite3_file* f) { (void) f; return 0; }

static int ctShmMap(sqlite3_file* f, int iRegion, int szRegion, int bExtend, void volatile** pp)
{
  CtData* d = ((CtFile*) f)->pData;
  if (iRegion >= MAX_SHM) return SQLITE_IOERR_SHMMAP;
  if (d->apShm[iRegion] == NULL)
  {
    if (!bExtend)
    {
      *pp = NULL;
      return SQLITE_OK;
    }
    d->apShm[iRegion] = sqlite3_malloc(szRegion);
    if (d->apShm[iRegion] == NULL) return SQLITE_NOMEM;
    memset(d->apShm[iRegion], 0, szRegion);
    d->szShm = szRegion;
  }
  *pp = d->apShm[iRegion];
  return SQLITE_OK;
}
static int ctShmLock(sqlite3_file* f, int o, int n, int fl) { (void) f; (void) o; (void) n; (void) fl; return SQLITE_OK; }
static void ctShmBarrier(sqlite3_file* f) { (void) f; }
static int ctShmUnmap(sqlite3_file* f, int deleteFlag)
{
  if (deleteFlag) ctDataFreeShm(((CtFile*) f)->pData);
  return SQLITE_OK;
}

static const sqlite3_io_methods ctMethods =
{
  2, ctClose, ctRead, ctWrite, ctTruncate, ctSync, ctFileSize,
  ctLock, ctLock, ctCheckReserved, ctFileControl, ctSectorSize, ctDeviceChar,
  ctShmMap, ctShmLock, ctShmBarrier, ctShmUnmap
};

static int ctOpen(sqlite3_vfs* vfs, const char* zName, sqlite3_file* f, int flags, int* pOutFlags)
{
  CtFile* p = (CtFile*) f;
  CtData* d = NULL;
  (void) vfs;
  memset(p, 0, sizeof(*p));
  if (zName != NULL)
  {
    d = diskFind(zName);
    if (d == NULL)
    {
      if ((flags & SQLITE_OPEN_CREATE) == 0) return SQLITE_CANTOPEN;
      d = sqlite3_malloc(sizeof(CtData));
      if (d == NULL) return SQLITE_NOMEM;
      memset(d, 0, sizeof(*d));
      d->zName = sqlite3_mprintf("%s", zName);
      if (d->zName == NULL || diskAdd(d) != SQLITE_OK) { ctDataFree(d); return SQLITE_CANTOPEN; }
    }
  }
  else
  {
    d = sqlite3_malloc(sizeof(CtData));
    if (d == NULL) return SQLITE_NOMEM;
    memset(d, 0, sizeof(*d));
    p->isTemp = 1;
  }
  d->nRef++;
  p->pData = d;
  p->base.pMethods = &ctMethods;
  if (pOutFlags) *pOutFlags = flags;
  return SQLITE_OK;
}

static int ctDelete(sqlite3_vfs* vfs, const char* zName, int syncDir)
{
  CtData* d = diskFind(zName);
  (void) vfs; (void) syncDir;
  if (!failNow()) return SQLITE_IOERR_DELETE;
  if (d != NULL)
  {
    diskRemove(d);
    if (d->nRef == 0) ctDataFree(d);
    else { d->n = 0; d->nSynced = 0; } /* still open: keeps an empty, unnamed file */
  }
  return SQLITE_OK;
}

static int ctAccess(sqlite3_vfs* vfs, const char* zName, int flags, int* pResOut)
{
  CtData* d = diskFind(zName);
  (void) vfs; (void) flags;
  *pResOut = (d != NULL);
  return SQLITE_OK;
}

static int ctFullPathname(sqlite3_vfs* vfs, const char* zName, int nOut, char* zOut)
{
  (void) vfs;
  sqlite3_snprintf(nOut, zOut, "%s", zName);
  return SQLITE_OK;
}

static int ctRandomness(sqlite3_vfs* v, int n, char* out) { (void) v; return baseVfs->xRandomness(baseVfs, n, out); }
static int ctSleep(sqlite3_vfs* v, int us) { (void) v; (void) us; return SQLITE_OK; }
static int ctCurrentTime(sqlite3_vfs* v, double* t) { (void) v; return baseVfs->xCurrentTime(baseVfs, t); }
static int ctLastError(sqlite3_vfs* v, int n, char* e) { (void) v; (void) n; (void) e; return 0; }

#define TEST_VFS "multipleciphers-memcrash"

static int installCrashVfs(void)
{
  baseVfs = sqlite3_vfs_find(NULL);
  memset(&ctVfs, 0, sizeof(ctVfs));
  ctVfs.iVersion = 1;
  ctVfs.szOsFile = (int) sizeof(CtFile);
  ctVfs.mxPathname = 512;
  ctVfs.zName = "memcrash";
  ctVfs.xOpen = ctOpen;
  ctVfs.xDelete = ctDelete;
  ctVfs.xAccess = ctAccess;
  ctVfs.xFullPathname = ctFullPathname;
  ctVfs.xRandomness = ctRandomness;
  ctVfs.xSleep = ctSleep;
  ctVfs.xCurrentTime = ctCurrentTime;
  ctVfs.xGetLastError = ctLastError;
  sqlite3_vfs_register(&ctVfs, 0);
  return sqlite3mc_vfs_create("memcrash", 0);
}

/*
** Disk images
*/
typedef struct Image Image;
struct Image
{
  int nFile;
  char* zName[MAX_FILES];
  unsigned char* a[MAX_FILES];
  sqlite3_int64 n[MAX_FILES];
};

static void imageFree(Image* img)
{
  int i;
  for (i = 0; i < img->nFile; i++)
  {
    sqlite3_free(img->zName[i]);
    sqlite3_free(img->a[i]);
  }
  memset(img, 0, sizeof(*img));
}

/* Take the files as they are now (useSynced: as of their last sync) */
static void imageTake(Image* img, int useSynced)
{
  int i;
  memset(img, 0, sizeof(*img));
  for (i = 0; i < MAX_FILES; i++)
  {
    CtData* d = disk[i];
    if (d == NULL) continue;
    const unsigned char* src = useSynced ? d->aSynced : d->a;
    sqlite3_int64 n = useSynced ? d->nSynced : d->n;
    img->zName[img->nFile] = sqlite3_mprintf("%s", d->zName);
    img->a[img->nFile] = sqlite3_malloc64(n > 0 ? n : 1);
    if (n > 0) memcpy(img->a[img->nFile], src, (size_t) n);
    img->n[img->nFile] = n;
    img->nFile++;
  }
}

/* Replace the disk with an image; no connection may be open */
static void imageRestore(const Image* img)
{
  int i;
  for (i = 0; i < MAX_FILES; i++)
  {
    ctDataFree(disk[i]);
    disk[i] = NULL;
  }
  for (i = 0; i < img->nFile; i++)
  {
    CtData* d = sqlite3_malloc(sizeof(CtData));
    memset(d, 0, sizeof(*d));
    d->zName = sqlite3_mprintf("%s", img->zName[i]);
    d->n = d->nSynced = img->n[i];
    d->a = sqlite3_malloc64(d->n > 0 ? d->n : 1);
    d->aSynced = sqlite3_malloc64(d->n > 0 ? d->n : 1);
    if (d->n > 0)
    {
      memcpy(d->a, img->a[i], (size_t) d->n);
      memcpy(d->aSynced, img->a[i], (size_t) d->n);
    }
    disk[i] = d;
  }
}

static int imageContains(const Image* img, const char* marker)
{
  int i;
  size_t m = strlen(marker);
  for (i = 0; i < img->nFile; i++)
  {
    sqlite3_int64 j;
    for (j = 0; j + (sqlite3_int64) m <= img->n[i]; j++)
    {
      if (memcmp(img->a[i] + j, marker, m) == 0) return 1;
    }
  }
  return 0;
}

/*
** Scenarios
*/
typedef struct Cipher Cipher;
struct Cipher
{
  const char* name;
  const char* keyOld;   /* SQL that selects the cipher and sets the old key */
  const char* keyNew;   /* SQL for the new key, same cipher */
  const char* other;    /* SQL for another cipher with the new key */
  const char* wrong;    /* SQL for the same cipher with a wrong key */
};

static const Cipher ciphers[] =
{
  { "chacha20",
    "PRAGMA cipher='chacha20'; PRAGMA key='raw:hex:0101010101010101010101010101010101010101010101010101010101010101';",
    "PRAGMA cipher='chacha20'; PRAGMA key='raw:hex:0202020202020202020202020202020202020202020202020202020202020202';",
    "PRAGMA cipher='aes256cbc'; PRAGMA kdf_iter=1; PRAGMA key='new key';",
    "PRAGMA cipher='chacha20'; PRAGMA key='raw:hex:0303030303030303030303030303030303030303030303030303030303030303';" },
  { "aes128cbc",
    "PRAGMA cipher='aes128cbc'; PRAGMA key='old key';",
    "PRAGMA cipher='aes128cbc'; PRAGMA key='new key';",
    "PRAGMA cipher='chacha20'; PRAGMA key='raw:hex:0202020202020202020202020202020202020202020202020202020202020202';",
    "PRAGMA cipher='aes128cbc'; PRAGMA key='wrong key';" },
  { "aes256cbc",
    "PRAGMA cipher='aes256cbc'; PRAGMA kdf_iter=1; PRAGMA key='old key';",
    "PRAGMA cipher='aes256cbc'; PRAGMA kdf_iter=1; PRAGMA key='new key';",
    "PRAGMA cipher='chacha20'; PRAGMA key='raw:hex:0202020202020202020202020202020202020202020202020202020202020202';",
    "PRAGMA cipher='aes256cbc'; PRAGMA kdf_iter=1; PRAGMA key='wrong key';" },
  { "sqlcipher",
    "PRAGMA cipher='sqlcipher'; PRAGMA key='raw:hex:0101010101010101010101010101010101010101010101010101010101010101';",
    "PRAGMA cipher='sqlcipher'; PRAGMA key='raw:hex:0202020202020202020202020202020202020202020202020202020202020202';",
    "PRAGMA cipher='chacha20'; PRAGMA key='raw:hex:0202020202020202020202020202020202020202020202020202020202020202';",
    "PRAGMA cipher='sqlcipher'; PRAGMA key='raw:hex:0303030303030303030303030303030303030303030303030303030303030303';" },
  { "aegis",
    "PRAGMA cipher='aegis'; PRAGMA key='raw:hex:0101010101010101010101010101010101010101010101010101010101010101';",
    "PRAGMA cipher='aegis'; PRAGMA key='raw:hex:0202020202020202020202020202020202020202020202020202020202020202';",
    "PRAGMA cipher='chacha20'; PRAGMA key='raw:hex:0202020202020202020202020202020202020202020202020202020202020202';",
    "PRAGMA cipher='aegis'; PRAGMA key='raw:hex:0303030303030303030303030303030303030303030303030303030303030303';" },
  { "ascon128",
    "PRAGMA cipher='ascon128'; PRAGMA key='raw:hex:0101010101010101010101010101010101010101010101010101010101010101';",
    "PRAGMA cipher='ascon128'; PRAGMA key='raw:hex:0202020202020202020202020202020202020202020202020202020202020202';",
    "PRAGMA cipher='chacha20'; PRAGMA key='raw:hex:0202020202020202020202020202020202020202020202020202020202020202';",
    "PRAGMA cipher='ascon128'; PRAGMA key='raw:hex:0303030303030303030303030303030303030303030303030303030303030303';" },
};

enum { OP_UPDATE, OP_REKEY, OP_REKEY_CIPHER, OP_DECRYPT, OP_VACUUM };
static const char* opNames[] = { "update", "rekey", "rekey-cipher", "decrypt", "vacuum" };

static const char* journalModes[] = { "delete", "truncate", "persist", "wal" };

#define DBNAME "crash.db"

static const char* fillSql =
  "CREATE TABLE t(i INTEGER PRIMARY KEY, x TEXT, y BLOB);"
  "CREATE INDEX tx ON t(x);"
  "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 150)"
  " INSERT INTO t SELECT n, printf('" MARKER "-%d-%.*c', n, n % 50, 'x'), zeroblob(n % 200) FROM c;";

static const char* updateSql =
  "BEGIN;"
  "UPDATE t SET x = x || '-changed', y = zeroblob(length(y) + 10) WHERE i % 3 = 0;"
  "INSERT INTO t(x, y) SELECT printf('" MARKER "-new-%d', i), zeroblob(i % 400) FROM t WHERE i <= 60;"
  "DELETE FROM t WHERE i % 7 = 0;"
  "COMMIT;";

static const char* stateSql =
  "SELECT count(*) || ':' || ifnull(sum(length(x)), 0) || ':' || ifnull(sum(length(y)), 0) || ':' ||"
  " ifnull(sum(i * unicode(substr(x, 1 + i % 13, 1))), 0) FROM t;";

static int failures;
static int scenarioFailures;
static int verbose;
static char saltSql[400];  /* old key with the old salt (decryption only) */
static int saltRuns;
static int runs;

#define FAIL(...) do { \
  failures++; scenarioFailures++; \
  if (scenarioFailures <= 3 || verbose) { printf("    [FAIL] "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

/* Open the database with the given key SQL; returns the state text (sqlite3_malloc'ed) or NULL */
static char* readState(const char* keySql, int* pIntegrityOk)
{
  sqlite3* db = NULL;
  sqlite3_stmt* st = NULL;
  char* state = NULL;
  *pIntegrityOk = 0;
  if (sqlite3_open_v2(DBNAME, &db, SQLITE_OPEN_READWRITE, TEST_VFS) == SQLITE_OK &&
      (keySql == NULL || sqlite3_exec(db, keySql, NULL, NULL, NULL) == SQLITE_OK))
  {
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check;", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
    {
      *pIntegrityOk = (strcmp((const char*) sqlite3_column_text(st, 0), "ok") == 0);
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(db, stateSql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
    {
      state = sqlite3_mprintf("%s", sqlite3_column_text(st, 0));
    }
    sqlite3_finalize(st);
  }
  sqlite3_close(db);
  return state;
}

/* Run the operation on the database; returns the result code of the operation */
static int runOperation(const Cipher* c, const char* journal, int op)
{
  sqlite3* db = NULL;
  int rc;
  char setup[200];
  rc = sqlite3_open_v2(DBNAME, &db, SQLITE_OPEN_READWRITE, TEST_VFS);
  if (rc == SQLITE_OK) rc = sqlite3_exec(db, c->keyOld, NULL, NULL, NULL);
  sqlite3_snprintf(sizeof(setup), setup, "PRAGMA journal_mode=%s; PRAGMA synchronous=FULL; PRAGMA cache_size=20;", journal);
  if (rc == SQLITE_OK) rc = sqlite3_exec(db, setup, NULL, NULL, NULL);
  if (rc == SQLITE_OK)
  {
    /* Count and fail only during the operation */
    opCount = 0;
    crashed = 0;
    ioerrHit = 0;
    if (op == OP_UPDATE) rc = sqlite3_exec(db, updateSql, NULL, NULL, NULL);
    if (op == OP_REKEY || op == OP_REKEY_CIPHER || op == OP_DECRYPT)
    {
      /* PRAGMA rekey with the new key: built from the key SQL of the scenario */
      const char* sql = (op == OP_REKEY) ? c->keyNew : (op == OP_REKEY_CIPHER) ? c->other : NULL;
      char rekeySql[300];
      if (sql == NULL)
      {
        sqlite3_snprintf(sizeof(rekeySql), rekeySql, "PRAGMA rekey='';");
      }
      else
      {
        /* "PRAGMA cipher=...; [PRAGMA kdf_iter=1;] PRAGMA key='...';" -> same with rekey */
        const char* k = strstr(sql, "PRAGMA key=");
        sqlite3_snprintf(sizeof(rekeySql), rekeySql, "%.*sPRAGMA rekey=%s", (int) (k - sql), sql, k + 11);
      }
      rc = sqlite3_exec(db, rekeySql, NULL, NULL, NULL);
    }
    if (op == OP_VACUUM) rc = sqlite3_exec(db, "VACUUM;", NULL, NULL, NULL);
  }
  failAt = 0;        /* closing must not count */
  {
    int wasCrashed = crashed;
    sqlite3_close(db);
    crashed = wasCrashed;
  }
  return rc;
}

static void runScenario(const Cipher* c, const char* journal, int pageSize, int op, const char* filter)
{
  char name[120];
  Image start, image;
  char *stateOld, *stateNew;
  int total, k, mode, ok;
  sqlite3* db = NULL;
  char setup[200];
  const char* keyAfter;

  sqlite3_snprintf(sizeof(name), name, "%s/%s/%d/%s", c->name, journal, pageSize, opNames[op]);
  if (filter != NULL && strstr(name, filter) == NULL) return;
  scenarioFailures = 0;

  /* Initial state */
  memset(&image, 0, sizeof(image));
  imageRestore(&image);
  failAt = 0; crashed = 0;
  sqlite3_open_v2(DBNAME, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, TEST_VFS);
  sqlite3_snprintf(sizeof(setup), setup, "PRAGMA page_size=%d;", pageSize);
  sqlite3_exec(db, c->keyOld, NULL, NULL, NULL);
  sqlite3_exec(db, setup, NULL, NULL, NULL);
  sqlite3_snprintf(sizeof(setup), setup, "PRAGMA journal_mode=%s;", journal);
  sqlite3_exec(db, setup, NULL, NULL, NULL);
  if (sqlite3_exec(db, fillSql, NULL, NULL, NULL) != SQLITE_OK)
  {
    FAIL("%s: setup failed: %s", name, sqlite3_errmsg(db));
    sqlite3_close(db);
    return;
  }
  sqlite3_close(db);
  imageTake(&start, 0);
  stateOld = readState(c->keyOld, &ok);
  imageRestore(&start);
  saltSql[0] = 0;
  if (op == OP_DECRYPT)
  {
    /* Old key plus old salt: the documented way to roll back an interrupted decryption */
    sqlite3_stmt* st = NULL;
    sqlite3_open_v2(DBNAME, &db, SQLITE_OPEN_READWRITE, TEST_VFS);
    sqlite3_exec(db, c->keyOld, NULL, NULL, NULL);
    if (sqlite3_prepare_v2(db, "PRAGMA cipher_salt;", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
    {
      const char* k = strstr(c->keyOld, "PRAGMA key=");
      sqlite3_snprintf(sizeof(saltSql), saltSql, "%.*sPRAGMA cipher_salt='%s'; %s",
                       (int) (k - c->keyOld), c->keyOld, sqlite3_column_text(st, 0), k);
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    imageRestore(&start);
  }

  /* Complete run: number of calls and the new state */
  keyAfter = (op == OP_REKEY) ? c->keyNew : (op == OP_REKEY_CIPHER) ? c->other : (op == OP_DECRYPT) ? NULL : c->keyOld;
  failAt = 0;
  if (runOperation(c, journal, op) != SQLITE_OK)
  {
    FAIL("%s: operation failed without injected error", name);
  }
  total = opCount;
  stateNew = readState(keyAfter, &ok);
  if (stateNew == NULL || !ok) FAIL("%s: new state not readable", name);
  if (op == OP_REKEY || op == OP_REKEY_CIPHER || op == OP_DECRYPT)
  {
    /* The operation must have changed the key: the old key no longer opens the database */
    char* s = readState(c->keyOld, &ok);
    if (s != NULL && ok) FAIL("%s: old key still opens the database after the operation", name);
    sqlite3_free(s);
    if (op == OP_REKEY_CIPHER)
    {
      s = readState(c->keyNew, &ok);
      if (s != NULL && ok) FAIL("%s: cipher was not changed", name);
      sqlite3_free(s);
    }
  }
  if (op == OP_UPDATE && stateNew != NULL && stateOld != NULL && strcmp(stateNew, stateOld) == 0)
    FAIL("%s: update did not change the rows", name);

  for (mode = MODE_CRASH; mode <= MODE_IOERR; mode++)
  {
    for (k = 1; k <= total; k++)
    {
      int rcOp, okOld = 0, okNew = 0, plainExpected;
      char *sOld, *sNew, *s2;
      const char* found = NULL;
      runs++;
      imageRestore(&start);
      failMode = mode;
      failAt = k;
      rcOp = runOperation(c, journal, op);

      /* The disk after the failure */
      imageTake(&image, mode == MODE_POWERLOSS);
      crashed = 0; failMode = MODE_NONE;

      /* Which key opens it? Each attempt on a fresh copy of the disk. */
      imageRestore(&image);
      sNew = readState(keyAfter, &okNew);
      imageRestore(&image);
      sOld = readState(c->keyOld, &okOld);
      if (sNew != NULL && okNew && strcmp(sNew, stateNew) == 0) found = "new";
      else if (sOld != NULL && okOld && strcmp(sOld, stateOld) == 0) found = "old";

      if (found == NULL && saltSql[0] != 0)
      {
        int okS = 0;
        char* sS;
        imageRestore(&image);
        sS = readState(saltSql, &okS);
        if (sS != NULL && okS && strcmp(sS, stateOld) == 0)
        {
          found = "old with salt";
          saltRuns++;
        }
        sqlite3_free(sS);
      }
      if (found == NULL)
      {
        FAIL("%s %s at call %d of %d: neither old nor new state (rc=%d; new key: %s%s, old key: %s%s)",
             name, modeNames[mode], k, total, rcOp,
             sNew ? sNew : "no db", (sNew && !okNew) ? " integrity!" : "",
             sOld ? sOld : "no db", (sOld && !okOld) ? " integrity!" : "");
      }
      else
      {
        /* Recovery must stick: open again with the same key after the first recovery */
        const char* keySql = (strcmp(found, "new") == 0) ? keyAfter : (strcmp(found, "old") == 0) ? c->keyOld : saltSql;
        const char* expect = (strcmp(found, "new") == 0) ? stateNew : stateOld;
        int ok2 = 0;
        imageRestore(&image);
        sqlite3_free(readState(keySql, &ok2));
        s2 = readState(keySql, &ok2);
        if (s2 == NULL || !ok2 || strcmp(s2, expect) != 0)
          FAIL("%s %s at call %d of %d: state changed on second open", name, modeNames[mode], k, total);
        sqlite3_free(s2);
        if (mode == MODE_IOERR && ioerrHit && rcOp == SQLITE_OK && strcmp(found, "new") != 0)
          FAIL("%s ioerr at call %d of %d: operation reported success, database in old state", name, k, total);
      }

      /*
      ** An application may first open the database without a key, with a
      ** wrong one, or (after a key change) with the other key. That must not
      ** destroy a hot journal: afterwards the right key must find the same
      ** state as before.
      */
      if (found != NULL)
      {
        const char* keySql = (strcmp(found, "new") == 0) ? keyAfter : (strcmp(found, "old") == 0) ? c->keyOld : saltSql;
        const char* expect = (strcmp(found, "new") == 0) ? stateNew : stateOld;
        int okW = 0;
        /* After an interrupted key change, the application may also try the other key first */
        const char* otherKey = (strcmp(found, "new") == 0) ? c->keyOld : keyAfter;
        imageRestore(&image);
        sqlite3_free(readState(NULL, &okW));
        sqlite3_free(readState(c->wrong, &okW));
        if (otherKey != NULL && otherKey != keySql) sqlite3_free(readState(otherKey, &okW));
        s2 = readState(keySql, &okW);
        if (s2 == NULL || !okW || strcmp(s2, expect) != 0)
          FAIL("%s %s at call %d of %d: state lost after opening without key or with a wrong key (%s)",
               name, modeNames[mode], k, total, s2 ? s2 : "no db");
        sqlite3_free(s2);
      }

      /* No plaintext on the disk, unless the database was decrypted */
      plainExpected = (op == OP_DECRYPT);
      if (!plainExpected && imageContains(&image, MARKER))
        FAIL("%s %s at call %d of %d: plaintext on disk", name, modeNames[mode], k, total);

      sqlite3_free(sNew);
      sqlite3_free(sOld);
      imageFree(&image);
    }
  }
  printf("  %-40s %4d calls  %s\n", name, total, scenarioFailures ? "FAILED" : "ok");
  sqlite3_free(stateOld);
  sqlite3_free(stateNew);
  imageFree(&start);
}

int main(int argc, char** argv)
{
  int full = 0;
  const char* filter = NULL;
  int i, j, p, op;
  static const int pageSizes[] = { 1024, 4096 };
  for (i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "full") == 0) full = 1;
    else if (strcmp(argv[i], "verbose") == 0) verbose = 1;
    else filter = argv[i];
  }
  if (installCrashVfs() != SQLITE_OK)
  {
    printf("Could not install the test VFS\n");
    return 1;
  }
  for (i = 0; i < (int) (sizeof(ciphers) / sizeof(ciphers[0])); i++)
  {
    for (j = 0; j < (int) (sizeof(journalModes) / sizeof(journalModes[0])); j++)
    {
      if (!full && j != 0 && j != 3) continue;          /* delete and wal */
      for (p = 0; p < 2; p++)
      {
        if (!full && p != 1) continue;                  /* 4096 */
        for (op = OP_UPDATE; op <= OP_VACUUM; op++)
        {
          if (!full && op != OP_UPDATE && op != OP_REKEY && op != OP_REKEY_CIPHER) continue;
          runScenario(&ciphers[i], journalModes[j], pageSizes[p], op, filter);
        }
      }
    }
  }
  if (saltRuns > 0) printf("%d interrupted decryptions could only be rolled back with the old salt\n", saltRuns);
  printf("%d runs, %d failures\n", runs, failures);
  return failures != 0;
}
