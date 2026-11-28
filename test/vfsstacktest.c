/*
** Tests for the SQLite3 Multiple Ciphers VFS in different positions of a
** VFS stack:
**
**   mc            the Multiple Ciphers VFS alone (for comparison)
**   shim/mc       a pass-through VFS above the Multiple Ciphers VFS
**   shim/shim/mc  two pass-through VFSs above it
**   mc/mc         the Multiple Ciphers VFS twice
**   split/mc      a VFS above it that splits the writes to the main database
**                 into parts that do not match the page boundaries: the
**                 writes must fail, and no plaintext may reach the files
**
** The pass-through VFS wraps every file and forwards every call, as VFS
** shims of other libraries do. For every stack and cipher the test creates
** an encrypted database (rollback journal and WAL), attaches a database with
** a key (KEY clause and URI parameters), changes the key, changes the cipher
** (done through VACUUM), encrypts a plaintext database and decrypts an
** encrypted one. After every step the database must open with the expected
** key, and no file may contain the plaintext of the rows.
**
** Usage: vfsstacktest
*/

#include "sqlite3mc.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MARKER "VFSSTACKMARKER"

static int failures;
static int checks;

#define CHECK(cond, ...) do { \
  checks++; \
  if (!(cond)) { failures++; printf("    [FAIL] "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

/*
** Pass-through VFS
*/
typedef struct ShimVfs ShimVfs;
struct ShimVfs
{
  sqlite3_vfs base;
  sqlite3_vfs* below;
  char zName[64];
  int splitWrites;          /* split the writes to the main database into odd-sized parts */
};

typedef struct ShimFile ShimFile;
struct ShimFile
{
  sqlite3_file base;
  int splitWrites;
  sqlite3_file* real;       /* file of the VFS below, allocated directly after this struct */
};

#define BELOW(v) (((ShimVfs*) (v))->below)
#define REAL(f)  (((ShimFile*) (f))->real)

static int shimClose(sqlite3_file* f)
{
  int rc = SQLITE_OK;
  if (REAL(f)->pMethods != NULL) rc = REAL(f)->pMethods->xClose(REAL(f));
  return rc;
}
static int shimRead(sqlite3_file* f, void* b, int n, sqlite3_int64 o) { return REAL(f)->pMethods->xRead(REAL(f), b, n, o); }
static int shimWrite(sqlite3_file* f, const void* b, int n, sqlite3_int64 o)
{
  if (((ShimFile*) f)->splitWrites)
  {
    /* Like a VFS that aligns or logs writes: parts that do not match the page boundaries */
    static const int parts[] = { 100, 777, 1, 4000, 13 };
    static unsigned int next = 0;
    const unsigned char* p = (const unsigned char*) b;
    int rc = SQLITE_OK;
    while (n > 0 && rc == SQLITE_OK)
    {
      int len = parts[next++ % (sizeof(parts) / sizeof(parts[0]))];
      if (len > n) len = n;
      rc = REAL(f)->pMethods->xWrite(REAL(f), p, len, o);
      p += len; n -= len; o += len;
    }
    return rc;
  }
  return REAL(f)->pMethods->xWrite(REAL(f), b, n, o);
}
static int shimTruncate(sqlite3_file* f, sqlite3_int64 s) { return REAL(f)->pMethods->xTruncate(REAL(f), s); }
static int shimSync(sqlite3_file* f, int fl) { return REAL(f)->pMethods->xSync(REAL(f), fl); }
static int shimFileSize(sqlite3_file* f, sqlite3_int64* s) { return REAL(f)->pMethods->xFileSize(REAL(f), s); }
static int shimLock(sqlite3_file* f, int l) { return REAL(f)->pMethods->xLock(REAL(f), l); }
static int shimUnlock(sqlite3_file* f, int l) { return REAL(f)->pMethods->xUnlock(REAL(f), l); }
static int shimCheckReserved(sqlite3_file* f, int* r) { return REAL(f)->pMethods->xCheckReservedLock(REAL(f), r); }
static int shimFileControl(sqlite3_file* f, int op, void* a) { return REAL(f)->pMethods->xFileControl(REAL(f), op, a); }
static int shimSectorSize(sqlite3_file* f) { return REAL(f)->pMethods->xSectorSize(REAL(f)); }
static int shimDevChar(sqlite3_file* f) { return REAL(f)->pMethods->xDeviceCharacteristics(REAL(f)); }
static int shimShmMap(sqlite3_file* f, int i, int sz, int ext, void volatile** pp) { return REAL(f)->pMethods->xShmMap(REAL(f), i, sz, ext, pp); }
static int shimShmLock(sqlite3_file* f, int o, int n, int fl) { return REAL(f)->pMethods->xShmLock(REAL(f), o, n, fl); }
static void shimShmBarrier(sqlite3_file* f) { REAL(f)->pMethods->xShmBarrier(REAL(f)); }
static int shimShmUnmap(sqlite3_file* f, int d) { return REAL(f)->pMethods->xShmUnmap(REAL(f), d); }
static int shimFetch(sqlite3_file* f, sqlite3_int64 o, int n, void** pp) { return REAL(f)->pMethods->xFetch(REAL(f), o, n, pp); }
static int shimUnfetch(sqlite3_file* f, sqlite3_int64 o, void* p) { return REAL(f)->pMethods->xUnfetch(REAL(f), o, p); }

static const sqlite3_io_methods shimMethods1 =
{
  1, shimClose, shimRead, shimWrite, shimTruncate, shimSync, shimFileSize,
  shimLock, shimUnlock, shimCheckReserved, shimFileControl, shimSectorSize, shimDevChar
};
static const sqlite3_io_methods shimMethods2 =
{
  2, shimClose, shimRead, shimWrite, shimTruncate, shimSync, shimFileSize,
  shimLock, shimUnlock, shimCheckReserved, shimFileControl, shimSectorSize, shimDevChar,
  shimShmMap, shimShmLock, shimShmBarrier, shimShmUnmap
};
static const sqlite3_io_methods shimMethods3 =
{
  3, shimClose, shimRead, shimWrite, shimTruncate, shimSync, shimFileSize,
  shimLock, shimUnlock, shimCheckReserved, shimFileControl, shimSectorSize, shimDevChar,
  shimShmMap, shimShmLock, shimShmBarrier, shimShmUnmap, shimFetch, shimUnfetch
};

static int shimOpen(sqlite3_vfs* v, const char* zName, sqlite3_file* f, int flags, int* outFlags)
{
  ShimFile* p = (ShimFile*) f;
  int rc;
  p->real = (sqlite3_file*) &p[1];
  p->base.pMethods = NULL;
  p->splitWrites = ((ShimVfs*) v)->splitWrites && (flags & SQLITE_OPEN_MAIN_DB) != 0;
  rc = BELOW(v)->xOpen(BELOW(v), zName, p->real, flags, outFlags);
  if (p->real->pMethods != NULL)
  {
    int iVersion = p->real->pMethods->iVersion;
    p->base.pMethods = (iVersion >= 3) ? &shimMethods3 : (iVersion == 2) ? &shimMethods2 : &shimMethods1;
  }
  return rc;
}
static int shimDelete(sqlite3_vfs* v, const char* z, int s) { return BELOW(v)->xDelete(BELOW(v), z, s); }
static int shimAccess(sqlite3_vfs* v, const char* z, int fl, int* r) { return BELOW(v)->xAccess(BELOW(v), z, fl, r); }
static int shimFullPathname(sqlite3_vfs* v, const char* z, int n, char* o) { return BELOW(v)->xFullPathname(BELOW(v), z, n, o); }
static void* shimDlOpen(sqlite3_vfs* v, const char* z) { return BELOW(v)->xDlOpen(BELOW(v), z); }
static void shimDlError(sqlite3_vfs* v, int n, char* z) { BELOW(v)->xDlError(BELOW(v), n, z); }
static void (*shimDlSym(sqlite3_vfs* v, void* p, const char* z))(void) { return BELOW(v)->xDlSym(BELOW(v), p, z); }
static void shimDlClose(sqlite3_vfs* v, void* p) { BELOW(v)->xDlClose(BELOW(v), p); }
static int shimRandomness(sqlite3_vfs* v, int n, char* z) { return BELOW(v)->xRandomness(BELOW(v), n, z); }
static int shimSleep(sqlite3_vfs* v, int us) { return BELOW(v)->xSleep(BELOW(v), us); }
static int shimCurrentTime(sqlite3_vfs* v, double* t) { return BELOW(v)->xCurrentTime(BELOW(v), t); }
static int shimGetLastError(sqlite3_vfs* v, int n, char* z) { return BELOW(v)->xGetLastError(BELOW(v), n, z); }
static int shimCurrentTimeInt64(sqlite3_vfs* v, sqlite3_int64* t) { return BELOW(v)->xCurrentTimeInt64(BELOW(v), t); }

static ShimVfs shims[3];

static const char* registerShim(ShimVfs* shim, const char* zName, const char* zBelow)
{
  sqlite3_vfs* below = sqlite3_vfs_find(zBelow);
  if (below == NULL) return NULL;
  memset(shim, 0, sizeof(*shim));
  sqlite3_snprintf(sizeof(shim->zName), shim->zName, "%s", zName);
  shim->below = below;
  shim->base.iVersion = 2;
  shim->base.szOsFile = (int) sizeof(ShimFile) + below->szOsFile;
  shim->base.mxPathname = below->mxPathname;
  shim->base.zName = shim->zName;
  shim->base.xOpen = shimOpen;
  shim->base.xDelete = shimDelete;
  shim->base.xAccess = shimAccess;
  shim->base.xFullPathname = shimFullPathname;
  shim->base.xDlOpen = shimDlOpen;
  shim->base.xDlError = shimDlError;
  shim->base.xDlSym = shimDlSym;
  shim->base.xDlClose = shimDlClose;
  shim->base.xRandomness = shimRandomness;
  shim->base.xSleep = shimSleep;
  shim->base.xCurrentTime = shimCurrentTime;
  shim->base.xGetLastError = shimGetLastError;
  shim->base.xCurrentTimeInt64 = shimCurrentTimeInt64;
  if (sqlite3_vfs_register(&shim->base, 0) != SQLITE_OK) return NULL;
  return shim->zName;
}

/*
** Helpers
*/
static void removeFiles(const char* zName)
{
  static const char* suffixes[] = { "", "-journal", "-wal", "-shm" };
  char path[256];
  size_t i;
  for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++)
  {
    sqlite3_snprintf(sizeof(path), path, "%s%s", zName, suffixes[i]);
    remove(path);
  }
}

static int fileContains(const char* zName, const char* marker)
{
  FILE* f = fopen(zName, "rb");
  char* buf;
  long n, i;
  size_t m = strlen(marker);
  int found = 0;
  if (f == NULL) return 0;
  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);
  buf = (char*) malloc(n > 0 ? n : 1);
  n = (long) fread(buf, 1, n, f);
  fclose(f);
  for (i = 0; i + (long) m <= n; i++)
  {
    if (memcmp(buf + i, marker, m) == 0) { found = 1; break; }
  }
  free(buf);
  return found;
}

static int anyFileContains(const char* zName, const char* marker)
{
  char path[256];
  int found = fileContains(zName, marker);
  sqlite3_snprintf(sizeof(path), path, "%s-journal", zName);
  found |= fileContains(path, marker);
  sqlite3_snprintf(sizeof(path), path, "%s-wal", zName);
  found |= fileContains(path, marker);
  return found;
}

static int exec(sqlite3* db, const char* sql, char* err, int nErr)
{
  char* zErr = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &zErr);
  sqlite3_snprintf(nErr, err, "%s", zErr ? zErr : "");
  sqlite3_free(zErr);
  return rc;
}

/* Count the rows of table t, -1 if the database can't be read with this key */
static int countRows(const char* zFile, const char* zVfs, const char* keySql, const char* table)
{
  sqlite3* db = NULL;
  sqlite3_stmt* st = NULL;
  char sql[200];
  int n = -1;
  if (sqlite3_open_v2(zFile, &db, SQLITE_OPEN_READWRITE, zVfs) == SQLITE_OK &&
      (keySql == NULL || sqlite3_exec(db, keySql, NULL, NULL, NULL) == SQLITE_OK))
  {
    sqlite3_snprintf(sizeof(sql), sql, "SELECT count(*) FROM %s;", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
      n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
  }
  sqlite3_close(db);
  return n;
}

/*
** The tests for one stack and one cipher
*/
typedef struct Cipher Cipher;
struct Cipher
{
  const char* name;
  const char* key1;
  const char* key2;     /* same cipher, new key */
  const char* other;    /* other cipher (key change through VACUUM) */
  const char* otherRekey;
  const char* uriParams;
};

static const Cipher ciphers[] =
{
  { "chacha20",  "PRAGMA cipher='chacha20'; PRAGMA key='k1';",  "PRAGMA cipher='chacha20'; PRAGMA key='k2';",
    "PRAGMA cipher='aes256cbc'; PRAGMA key='k3';", "PRAGMA cipher='aes256cbc'; PRAGMA rekey='k3';", "cipher=chacha20&key=k1" },
  { "aes256cbc", "PRAGMA cipher='aes256cbc'; PRAGMA key='k1';", "PRAGMA cipher='aes256cbc'; PRAGMA key='k2';",
    "PRAGMA cipher='chacha20'; PRAGMA key='k3';", "PRAGMA cipher='chacha20'; PRAGMA rekey='k3';", "cipher=aes256cbc&key=k1" },
  { "sqlcipher", "PRAGMA cipher='sqlcipher'; PRAGMA key='k1';", "PRAGMA cipher='sqlcipher'; PRAGMA key='k2';",
    "PRAGMA cipher='chacha20'; PRAGMA key='k3';", "PRAGMA cipher='chacha20'; PRAGMA rekey='k3';", "cipher=sqlcipher&key=k1" },
  { "aegis",     "PRAGMA cipher='aegis'; PRAGMA key='k1';",     "PRAGMA cipher='aegis'; PRAGMA key='k2';",
    "PRAGMA cipher='chacha20'; PRAGMA key='k3';", "PRAGMA cipher='chacha20'; PRAGMA rekey='k3';", "cipher=aegis&key=k1" },
  { "aes256gcm", "PRAGMA cipher='aes256gcm'; PRAGMA key='k1';", "PRAGMA cipher='aes256gcm'; PRAGMA key='k2';",
    "PRAGMA cipher='chacha20'; PRAGMA key='k3';", "PRAGMA cipher='chacha20'; PRAGMA rekey='k3';", "cipher=aes256gcm&key=k1" },
};

static const char* fillSql =
  "CREATE TABLE t(i INTEGER PRIMARY KEY, x TEXT);"
  "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 500)"
  " INSERT INTO t SELECT n, printf('" MARKER " %d %.*c', n, 60, 'x') FROM c;";

#define DB  "vfsstack.db"
#define ATT "vfsstack-att.db"
#define URI "vfsstack-uri.db"

/* Create a fresh encrypted database with 500 rows */
static int createDb(const char* zVfs, const Cipher* c, char* err, int nErr)
{
  sqlite3* db = NULL;
  int rc;
  removeFiles(DB);
  rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, zVfs);
  if (rc == SQLITE_OK) rc = exec(db, c->key1, err, nErr);
  if (rc == SQLITE_OK) rc = exec(db, fillSql, err, nErr);
  if (rc != SQLITE_OK && err[0] == 0) sqlite3_snprintf(nErr, err, "%s", sqlite3_errmsg(db));
  sqlite3_close(db);
  return rc;
}

static void testStack(const char* label, const char* zVfs, const Cipher* c)
{
  sqlite3* db = NULL;
  char err[256], sql[300];
  int rc, before = failures;
  char rekey2[200];
  const char* k = strstr(c->key2, "PRAGMA key=");
  (void) db;
  sqlite3_snprintf(sizeof(rekey2), rekey2, "%.*sPRAGMA rekey=%s", (int) (k - c->key2), c->key2, k + 11);

  removeFiles(DB); removeFiles(ATT); removeFiles(URI);

  /* 1. Encrypted database with a rollback journal */
  rc = createDb(zVfs, c, err, sizeof(err));
  CHECK(rc == SQLITE_OK, "%s %s: create: %s", label, c->name, err);
  CHECK(!anyFileContains(DB, MARKER), "%s %s: plaintext in the database", label, c->name);
  CHECK(countRows(DB, zVfs, c->key1, "t") == 500, "%s %s: reopen with key", label, c->name);
  CHECK(countRows(DB, zVfs, NULL, "t") < 0, "%s %s: readable without key", label, c->name);

  /* 2. WAL: the WAL file must be encrypted as well */
  createDb(zVfs, c, err, sizeof(err));
  rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE, zVfs);
  if (rc == SQLITE_OK) rc = exec(db, c->key1, err, sizeof(err));
  if (rc == SQLITE_OK) rc = exec(db, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
                                     "UPDATE t SET x = x || ' wal';", err, sizeof(err));
  CHECK(rc == SQLITE_OK, "%s %s: WAL: %s", label, c->name, err);
  CHECK(!anyFileContains(DB, MARKER), "%s %s: plaintext in the WAL", label, c->name);
  exec(db, "PRAGMA journal_mode=DELETE;", err, sizeof(err));
  sqlite3_close(db);
  CHECK(countRows(DB, zVfs, c->key1, "t") == 500, "%s %s: reopen after WAL", label, c->name);

  /* 3. ATTACH with KEY clause and with URI parameters */
  createDb(zVfs, c, err, sizeof(err));
  rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, zVfs);
  if (rc == SQLITE_OK) rc = exec(db, c->key1, err, sizeof(err));
  if (rc == SQLITE_OK) rc = exec(db, "ATTACH '" ATT "' AS a KEY 'ka';"
                                     "CREATE TABLE a.t AS SELECT * FROM main.t;", err, sizeof(err));
  CHECK(rc == SQLITE_OK, "%s %s: ATTACH ... KEY: %s", label, c->name, err);
  sqlite3_snprintf(sizeof(sql), sql, "ATTACH 'file:" URI "?%s' AS u; CREATE TABLE u.t AS SELECT * FROM main.t;", c->uriParams);
  rc = exec(db, sql, err, sizeof(err));
  CHECK(rc == SQLITE_OK, "%s %s: ATTACH with URI key: %s", label, c->name, err);
  sqlite3_close(db);
  CHECK(!anyFileContains(ATT, MARKER), "%s %s: plaintext in the database attached with KEY", label, c->name);
  CHECK(!anyFileContains(URI, MARKER), "%s %s: plaintext in the database attached with URI key", label, c->name);
  k = strstr(c->key1, "PRAGMA key=");
  sqlite3_snprintf(sizeof(sql), sql, "%.*sPRAGMA key='ka';", (int) (k - c->key1), c->key1);
  CHECK(countRows(ATT, zVfs, sql, "t") == 500, "%s %s: attached database (KEY) not readable", label, c->name);
  CHECK(countRows(URI, zVfs, c->key1, "t") == 500, "%s %s: attached database (URI) not readable", label, c->name);

  /* 4. New key, same cipher */
  createDb(zVfs, c, err, sizeof(err));
  rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE, zVfs);
  if (rc == SQLITE_OK) rc = exec(db, c->key1, err, sizeof(err));
  if (rc == SQLITE_OK) rc = exec(db, rekey2, err, sizeof(err));
  CHECK(rc == SQLITE_OK, "%s %s: rekey: %s", label, c->name, err);
  sqlite3_close(db);
  CHECK(countRows(DB, zVfs, c->key2, "t") == 500, "%s %s: new key after rekey", label, c->name);
  CHECK(countRows(DB, zVfs, c->key1, "t") < 0, "%s %s: old key still works after rekey", label, c->name);

  /* 5. Other cipher (through VACUUM) */
  createDb(zVfs, c, err, sizeof(err));
  rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE, zVfs);
  if (rc == SQLITE_OK) rc = exec(db, c->key1, err, sizeof(err));
  if (rc == SQLITE_OK) rc = exec(db, c->otherRekey, err, sizeof(err));
  CHECK(rc == SQLITE_OK, "%s %s: cipher change: %s", label, c->name, err);
  sqlite3_close(db);
  CHECK(countRows(DB, zVfs, c->other, "t") == 500, "%s %s: new cipher after cipher change", label, c->name);
  CHECK(!anyFileContains(DB, MARKER), "%s %s: plaintext after cipher change", label, c->name);

  /* 6. Decrypt, then encrypt the plaintext database again */
  createDb(zVfs, c, err, sizeof(err));
  rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE, zVfs);
  if (rc == SQLITE_OK) rc = exec(db, c->key1, err, sizeof(err));
  if (rc == SQLITE_OK) rc = exec(db, "PRAGMA rekey='';", err, sizeof(err));
  CHECK(rc == SQLITE_OK, "%s %s: decrypt: %s", label, c->name, err);
  sqlite3_close(db);
  CHECK(countRows(DB, zVfs, NULL, "t") == 500, "%s %s: plaintext database after decrypt", label, c->name);
  rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE, zVfs);
  if (rc == SQLITE_OK) rc = exec(db, rekey2, err, sizeof(err));
  CHECK(rc == SQLITE_OK, "%s %s: encrypt plaintext database: %s", label, c->name, err);
  sqlite3_close(db);
  CHECK(countRows(DB, zVfs, c->key2, "t") == 500, "%s %s: key after encrypting", label, c->name);
  CHECK(!anyFileContains(DB, MARKER), "%s %s: plaintext after encrypting", label, c->name);

  printf("  %-14s %-10s %s\n", label, c->name, failures == before ? "ok" : "FAILED");
  removeFiles(DB); removeFiles(ATT); removeFiles(URI);
}

/*
** A VFS above the Multiple Ciphers VFS reads the WAL file. Only a read of a
** frame's page data, which follows the 24-byte frame header, needs the page
** number from the header. A read of one page size at any other offset (for
** example at offset 0) must not look for a frame header in front of it.
*/
static void testWalRead(const char* zVfs, const Cipher* c)
{
  sqlite3* db = NULL;
  sqlite3_file* wal = NULL;
  unsigned char* buf;
  char err[256];
  const int pageSize = 4096;
  int rc, before = failures;
  removeFiles(DB); removeFiles(ATT); removeFiles(URI);
  rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, zVfs);
  if (rc == SQLITE_OK) rc = exec(db, c->key1, err, sizeof(err));
  if (rc == SQLITE_OK) rc = exec(db, "PRAGMA page_size=4096; PRAGMA journal_mode=wal; PRAGMA wal_autocheckpoint=0;", err, sizeof(err));
  if (rc == SQLITE_OK) rc = exec(db, "CREATE TABLE t(a, b); INSERT INTO t VALUES (1, randomblob(100)), (2, randomblob(100));", err, sizeof(err));
  CHECK(rc == SQLITE_OK, "wal %s: database created (%s)", c->name, err);
  buf = (unsigned char*) sqlite3_malloc(pageSize);
  if (rc == SQLITE_OK && buf != NULL &&
      sqlite3_file_control(db, "main", SQLITE_FCNTL_JOURNAL_POINTER, &wal) == SQLITE_OK &&
      wal != NULL && wal->pMethods != NULL)
  {
    /* The WAL header: bytes 0..3 are the magic number 0x377f0682 or 0x377f0683 */
    memset(buf, 0, pageSize);
    rc = wal->pMethods->xRead(wal, buf, pageSize, 0);
    CHECK(rc == SQLITE_OK, "wal %s: read of a page size at offset 0 fails (rc=%d)", c->name, rc);
    CHECK(buf[0] == 0x37 && buf[1] == 0x7f, "wal %s: read at offset 0 returns the WAL header", c->name);
    /* Page data of the first and the second frame */
    rc = wal->pMethods->xRead(wal, buf, pageSize, 32 + 24);
    CHECK(rc == SQLITE_OK, "wal %s: read of the page data of frame 1 fails (rc=%d)", c->name, rc);
    rc = wal->pMethods->xRead(wal, buf, pageSize, 32 + 24 + (pageSize + 24));
    CHECK(rc == SQLITE_OK, "wal %s: read of the page data of frame 2 fails (rc=%d)", c->name, rc);
    /* Not aligned to a frame */
    rc = wal->pMethods->xRead(wal, buf, pageSize, 32 + 100);
    CHECK(rc == SQLITE_OK, "wal %s: read at an offset inside a frame fails (rc=%d)", c->name, rc);
  }
  else
  {
    CHECK(0, "wal %s: no access to the WAL file", c->name);
  }
  sqlite3_free(buf);
  sqlite3_close(db);
  removeFiles(DB); removeFiles(ATT); removeFiles(URI);
  printf("  %-14s %-10s %s\n", "wal read", c->name, (failures == before) ? "ok" : "FAILED");
}

/*
** A VFS above the Multiple Ciphers VFS that splits the writes to the main
** database gets an error, and no plaintext reaches the files.
*/
static void testSplitWrites(const char* zVfs, const Cipher* c)
{
  sqlite3* db = NULL;
  char err[256];
  int rc, before = failures;
  removeFiles(DB); removeFiles(ATT); removeFiles(URI);
  rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, zVfs);
  if (rc == SQLITE_OK) rc = exec(db, c->key1, err, sizeof(err));
  if (rc == SQLITE_OK) rc = exec(db, "CREATE TABLE splitwritetable(x); INSERT INTO splitwritetable VALUES('" MARKER "')", err, sizeof(err));
  CHECK(rc != SQLITE_OK, "split/mc %s: split writes were accepted", c->name);
  sqlite3_close(db);
  CHECK(!anyFileContains(DB, "splitwritetable") && !anyFileContains(DB, MARKER), "split/mc %s: plaintext in the database", c->name);
  printf("  %-14s %-10s %s\n", "split/mc", c->name, (failures == before) ? "ok" : "FAILED");
}

int main(void)
{
  const char* mcVfs = sqlite3_vfs_find(NULL)->zName;   /* the Multiple Ciphers VFS */
  char mcTwice[100];
  const char* shim1;
  const char* shim2;
  const char* shim3;
  size_t i;

  shim1 = registerShim(&shims[0], "shim1", mcVfs);
  shim2 = registerShim(&shims[1], "shim2", "shim1");
  shim3 = registerShim(&shims[2], "shim3", mcVfs);
  if (shim3 != NULL) shims[2].splitWrites = 1;
  sqlite3_snprintf(sizeof(mcTwice), mcTwice, "multipleciphers-%s", mcVfs);
  if (shim1 == NULL || shim2 == NULL || shim3 == NULL || sqlite3mc_vfs_create(mcVfs, 0) != SQLITE_OK || sqlite3_vfs_find(mcTwice) == NULL)
  {
    printf("Could not set up the VFS stacks\n");
    return 1;
  }
  printf("VFS stacks on top of %s\n", mcVfs);

  for (i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); i++)
  {
    testStack("mc", mcVfs, &ciphers[i]);
    testStack("shim/mc", shim1, &ciphers[i]);
    testStack("shim/shim/mc", shim2, &ciphers[i]);
    testStack("mc/mc", mcTwice, &ciphers[i]);
    testSplitWrites(shim3, &ciphers[i]);
    testWalRead(shim1, &ciphers[i]);
  }
  printf("%d checks, %d failures\n", checks, failures);
  return failures != 0;
}
