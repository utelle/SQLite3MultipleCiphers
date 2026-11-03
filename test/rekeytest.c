/*
** Test: rekey with failures (SQLite3 Multiple Ciphers)
**
** Fault-injection VFS BELOW the SQLite3MC VFS (also passes shared memory through for WAL):
**   F_DB_SYNC         : let xSync() on the main DB file fail once
**   F_JOURNAL_DELETE  : let xDelete() of the "-journal" fail once
**   F_WAL_SYNC        : let xSync() on the WAL file fail once
**
** Fault-injection allocator (SQLITE_CONFIG_MALLOC):
**   the N-th allocation after arming fails (once)
**
** Part 1 : commit failures in all rekey variants (rollback journal)   (scenarios[])
** Part 2 : rekey inside an open transaction                           (txnScenarios[])
** Part 2b: rekey with an active SELECT and via PRAGMA rekey           (miscScenarios[])
** Part 3 : OOM loop over N, optionally with a sync failure            (oomScenarios[])
** Part 4 : commit failures in WAL mode                                (walScenarios[])
** Part 5 : salt behaviour: default (old salt is kept) and PRAGMA rekey_salt,
**          rollback journal and WAL, incl. cipher_salt as PRAGMA and as URI parameter
** Part 6 : OOM loop in WAL mode                                       (oomWalScenarios[])
** Part 7 : plaintext_header_size: the salt is not stored in the file and must
**          always be supplied (rekey, failure case, plain -> encrypted)
** Part 8 : salt management (random salt, salt in memory across several rekeys,
**          rekey_salt=on/off) and behaviour when reading the file header
**          (unencrypted/empty/too short file, I/O error while reading the header)
**
** Invariant in parts 3 and 6 (after every rekey, whether it failed or not):
**   exactly ONE of the two states (old/new) is completely readable
**   (all rows, integrity_check ok). Both or neither = FAIL.
**   Further FAILs:
**     - rekey reports OK, but the file still has the old state
**     - connection no longer usable after the rekey although the file is ok
**   WARN (not a FAIL): rekey reports an error, but the file has the new state.
**
** Usage:
**   ./rekey_test                  everything
**   ./rekey_test --no-oom         without parts 3 and 6
**   ./rekey_test --no-wal         without parts 4, 5 (WAL cases) and 6
**   ./rekey_test --oom-stride 5   from N=50 test only every 5th allocation
**
** Build (example):
**   gcc -O1 -g -o rekey_test rekey_commit_fail_test.c \
**       sqlite3mc_amalgamation.c -DSQLITE_THREADSAFE=1 -lpthread -ldl -lm
*/
#include "sqlite3mc.c"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#endif

#ifndef SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE
#define SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE 1006
#endif

#define DBFILE   "rekey_test.db"
#define OOM_MAX  20000

enum
{
  F_NONE           = 0,
  F_DB_SYNC        = 1,
  F_JOURNAL_DELETE = 2,
  F_WAL_SYNC       = 3,
  F_READ_HDR       = 4 /* next read at offset 0 of the main DB fails */
};

static int g_nrows     = 5000;     /* number of rows in table t */
static int g_fault     = F_NONE;   /* currently armed fault type */
static int g_faultsHit = 0;
static int g_failures  = 0;
static int g_warnings  = 0;
static int g_skipped   = 0;
static int g_wal       = 0;        /* 1: test DBs in WAL mode */
static char g_newSalt[40];         /* salt (hex) returned by PRAGMA rekey_salt, "" = none */
static int g_plainHdr  = 0;        /* >0: plaintext_header_size for all encrypted connections */
static char g_oldSalt[40];         /* salt of the initial state (setup_db, only with g_plainHdr) */
static char g_ctx[200];            /* context for the crash message */

#define CHECK(cond, msg) do { \
  if (cond) printf("    [ok]   %s\n", msg); \
  else { printf("    [FAIL] %s\n", msg); g_failures++; } \
} while (0)

/* ------------------------------------------------------------------ */
/* Fault-injection allocator                                          */
/* ------------------------------------------------------------------ */
static sqlite3_mem_methods g_baseMem;
static int g_oomCountdown = 0;   /* >0: the countdown-th allocation fails */
static int g_oomHit = 0;

static int oomCheck(void)
{
  if (g_oomCountdown > 0 && --g_oomCountdown == 0) { g_oomHit++; return 1; }
  return 0;
}
static void* mMalloc(int n) { return oomCheck() ? 0 : g_baseMem.xMalloc(n); }
static void  mFree(void* p) { g_baseMem.xFree(p); }
static void* mRealloc(void* p, int n) { return oomCheck() ? 0 : g_baseMem.xRealloc(p, n); }
static int   mSize(void* p) { return g_baseMem.xSize(p); }
static int   mRoundup(int n) { return g_baseMem.xRoundup(n); }
static int   mInit(void* a) { (void) a; return g_baseMem.xInit(g_baseMem.pAppData); }
static void  mShutdown(void* a) { (void) a; g_baseMem.xShutdown(g_baseMem.pAppData); }

static sqlite3_mem_methods g_oomMem = { mMalloc, mFree, mRealloc, mSize, mRoundup, mInit, mShutdown, 0 };

/* ------------------------------------------------------------------ */
/* Fault-injection VFS                                                */
/* ------------------------------------------------------------------ */
typedef struct FFile
{
  sqlite3_file base;
  int isMainDb;
  int isWal;
  sqlite3_file* pReal;
} FFile;

static sqlite3_vfs* g_root = 0;

static int fClose(sqlite3_file* f)
{
  FFile* p = (FFile*) f;
  int rc = SQLITE_OK;
  if (p->pReal->pMethods) rc = p->pReal->pMethods->xClose(p->pReal);
  return rc;
}

static int fRead(sqlite3_file* f, void* b, int n, sqlite3_int64 o)
{
  FFile* p = (FFile*) f;
  if (p->isMainDb && o == 0 && g_fault == F_READ_HDR)
  {
    g_fault = F_NONE;
    g_faultsHit++;
    return SQLITE_IOERR_READ;
  }
  return p->pReal->pMethods->xRead(p->pReal, b, n, o);
}

static int fWrite(sqlite3_file* f, const void* b, int n, sqlite3_int64 o)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xWrite(p->pReal, b, n, o);
}

static int fTruncate(sqlite3_file* f, sqlite3_int64 s)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xTruncate(p->pReal, s);
}

static int fSync(sqlite3_file* f, int flags)
{
  FFile* p = (FFile*) f;
  if (p->isMainDb && g_fault == F_DB_SYNC)
  {
    g_fault = F_NONE;
    g_faultsHit++;
    return SQLITE_IOERR_FSYNC;
  }
  if (p->isWal && g_fault == F_WAL_SYNC)
  {
    g_fault = F_NONE;
    g_faultsHit++;
    return SQLITE_IOERR_FSYNC;
  }
  return p->pReal->pMethods->xSync(p->pReal, flags);
}

static int fFileSize(sqlite3_file* f, sqlite3_int64* s)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xFileSize(p->pReal, s);
}

static int fLock(sqlite3_file* f, int l)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xLock(p->pReal, l);
}

static int fUnlock(sqlite3_file* f, int l) {
  FFile* p = (FFile*) f; return p->pReal->pMethods->xUnlock(p->pReal, l);
}

static int fCheckReservedLock(sqlite3_file* f, int* r)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xCheckReservedLock(p->pReal, r);
}

static int fFileControl(sqlite3_file* f, int op, void* a)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xFileControl(p->pReal, op, a);
}

static int fSectorSize(sqlite3_file* f)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xSectorSize(p->pReal);
}

static int fDeviceCharacteristics(sqlite3_file* f)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xDeviceCharacteristics(p->pReal);
}

/* shared memory (WAL): simply pass through */
static int fShmMap(sqlite3_file* f, int iPg, int pgsz, int bExtend, void volatile** pp)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xShmMap(p->pReal, iPg, pgsz, bExtend, pp);
}

static int fShmLock(sqlite3_file* f, int offset, int n, int flags)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xShmLock(p->pReal, offset, n, flags);
}

static void fShmBarrier(sqlite3_file* f)
{
  FFile* p = (FFile*) f; p->pReal->pMethods->xShmBarrier(p->pReal);
}

static int fShmUnmap(sqlite3_file* f, int deleteFlag)
{
  FFile* p = (FFile*) f; return p->pReal->pMethods->xShmUnmap(p->pReal, deleteFlag);
}

static const sqlite3_io_methods g_ioMethods =
{
  2,
  fClose,
  fRead,
  fWrite,
  fTruncate,
  fSync,
  fFileSize,
  fLock,
  fUnlock,
  fCheckReservedLock,
  fFileControl,
  fSectorSize,
  fDeviceCharacteristics,
  fShmMap,
  fShmLock,
  fShmBarrier,
  fShmUnmap
};

static int vOpen(sqlite3_vfs* v, const char* z, sqlite3_file* f, int flags, int* pOut)
{
  FFile* p = (FFile*) f;
  int rc;
  (void) v;
  memset(p, 0, sizeof(*p));
  p->isMainDb = (flags & SQLITE_OPEN_MAIN_DB) != 0;
  p->isWal = (flags & SQLITE_OPEN_WAL) != 0;
  p->pReal = (sqlite3_file*) &p[1];
  rc = g_root->xOpen(g_root, z, p->pReal, flags, pOut);
  if (rc == SQLITE_OK) p->base.pMethods = &g_ioMethods;
  return rc;
}

static int vDelete(sqlite3_vfs* v, const char* z, int s)
{
  (void) v;
  if (g_fault == F_JOURNAL_DELETE && z)
  {
    size_t n = strlen(z);
    if (n >= 8 && strcmp(z + n - 8, "-journal") == 0)
    {
      g_fault = F_NONE;
      g_faultsHit++;
      return SQLITE_IOERR_DELETE;
    }
  }
  return g_root->xDelete(g_root, z, s);
}

static int vAccess(sqlite3_vfs* v, const char* z, int fl, int* r)
{
  (void) v; return g_root->xAccess(g_root, z, fl, r);
}

static int vFullPathname(sqlite3_vfs* v, const char* z, int n, char* o)
{
  (void) v; return g_root->xFullPathname(g_root, z, n, o);
}

static int vRandomness(sqlite3_vfs* v, int n, char* o)
{
  (void) v; return g_root->xRandomness(g_root, n, o);
}

static int vSleep(sqlite3_vfs* v, int us)
{
  (void) v; return g_root->xSleep(g_root, us);
}

static int vCurrentTime(sqlite3_vfs* v, double* d)
{
  (void) v; return g_root->xCurrentTime(g_root, d);
}

static int vGetLastError(sqlite3_vfs* v, int n, char* z)
{
  (void) v; return g_root->xGetLastError(g_root, n, z);
}

static sqlite3_vfs g_faultVfs;

static int install_vfs(void)
{
  g_root = sqlite3_vfs_find("unix");
  if (!g_root) g_root = sqlite3_vfs_find("win32");
  if (!g_root) { printf("No base VFS found\n"); return 1; }

  memset(&g_faultVfs, 0, sizeof(g_faultVfs));
  g_faultVfs.iVersion = 1;
  g_faultVfs.szOsFile = (int) sizeof(FFile) + g_root->szOsFile;
  g_faultVfs.mxPathname = g_root->mxPathname;
  g_faultVfs.zName = "faulty";
  g_faultVfs.xOpen = vOpen;
  g_faultVfs.xDelete = vDelete;
  g_faultVfs.xAccess = vAccess;
  g_faultVfs.xFullPathname = vFullPathname;
  g_faultVfs.xRandomness = vRandomness;
  g_faultVfs.xSleep = vSleep;
  g_faultVfs.xCurrentTime = vCurrentTime;
  g_faultVfs.xGetLastError = vGetLastError;
  if (sqlite3_vfs_register(&g_faultVfs, 0) != SQLITE_OK) return 1;

  if (sqlite3mc_vfs_create("faulty", 0) != SQLITE_OK)
  {
    printf("sqlite3mc_vfs_create failed\n");
    return 1;
  }
  if (!sqlite3_vfs_find("multipleciphers-faulty"))
  {
    printf("VFS 'multipleciphers-faulty' not found\n");
    return 1;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Helper functions                                                   */
/* ------------------------------------------------------------------ */
static int query_int(sqlite3* db, const char* sql, int* out)
{
  sqlite3_stmt* st = 0;
  int rc = sqlite3_prepare_v2(db, sql, -1, &st, 0);
  if (rc == SQLITE_OK) {
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW)
    {
      *out = sqlite3_column_int(st, 0); rc = SQLITE_OK;
    }
  }
  sqlite3_finalize(st);
  return rc;
}

/* first column of the first row as text (e.g. for PRAGMAs) */
static int get_text(sqlite3* db, const char* sql, char* buf, size_t n)
{
  sqlite3_stmt* st = 0;
  int rc;
  buf[0] = 0;
  rc = sqlite3_prepare_v2(db, sql, -1, &st, 0);
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW)
    {
      const char* t = (const char*) sqlite3_column_text(st, 0);
      if (t) snprintf(buf, n, "%s", t);
      rc = SQLITE_OK;
    }
  }
  sqlite3_finalize(st);
  return rc;
}

static int integrity_ok(sqlite3* db)
{
  sqlite3_stmt* st = 0;
  int ok = 0;
  if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &st, 0) == SQLITE_OK &&
      sqlite3_step(st) == SQLITE_ROW)
  {
    const char* t = (const char*) sqlite3_column_text(st, 0);
    ok = (t && strcmp(t, "ok") == 0);
  }
  sqlite3_finalize(st);
  return ok;
}

/* current reserved bytes of the btree (-1 only queries, sets nothing); -2 on error */
static int get_reserve(sqlite3* db)
{
  int r = -1;
  if (sqlite3_file_control(db, "main", SQLITE_FCNTL_RESERVE_BYTES, &r) != SQLITE_OK)
    return -2;
  return r;
}

/* keep only the hex digits of text (strips an x'..' wrapper and blanks), lower case */
static void extract_hex(const char* text, char* out, size_t n)
{
  size_t k = 0;
  const char* p;
  for (p = text; *p && k + 1 < n; p++)
  {
    if (isxdigit((unsigned char) *p))
      out[k++] = (char) tolower((unsigned char) *p);
  }
  out[k] = 0;
}

/* 1 if the 16 bytes of salt match the hex text */
static int hex_matches(const unsigned char* salt, const char* text)
{
  char h[40], expect[40];
  int i;
  extract_hex(text, h, sizeof(h));
  for (i = 0; i < 16; i++)
    snprintf(expect + 2 * i, 3, "%02x", salt[i]);
  return strlen(h) >= 32 && strncmp(h, expect, 32) == 0;
}

static void bytes_to_hex(const unsigned char* b, char* out)
{
  int i;
  for (i = 0; i < 16; i++)
    snprintf(out + 2 * i, 3, "%02x", b[i]);
}

/* PRAGMA cipher_salt (without a value, after the key) returns the current salt;
** 1 if it equals hex (32 characters, lower case) */
static int cipher_salt_is(sqlite3* db, const char* hex)
{
  char raw[128], cur[40];
  if (get_text(db, "PRAGMA cipher_salt", raw, sizeof(raw)) != SQLITE_OK) return 0;
  extract_hex(raw, cur, sizeof(cur));
  return strlen(cur) == 32 && strcmp(cur, hex) == 0;
}

/* 1 if the 16 bytes are the standard SQLite header */
static int is_sqlite_magic(const unsigned char* h) {
  return memcmp(h, "SQLite format 3\0", 16) == 0;
}

/* 1 if the cipher stores the salt in the first 16 bytes of the file */
static int header_salt_cipher(const char* c)
{
  return c != NULL &&
         strcmp(c, "aes128cbc") != 0 &&
         strcmp(c, "aes256cbc") != 0 &&
         strcmp(c, "rc4") != 0;
}

/* reads the first 16 bytes of the DB file (salt for chacha20) */
static int read_header_salt(unsigned char* out)
{
  FILE* f = fopen(DBFILE, "rb");
  size_t n;
  if (!f) return 0;
  n = fread(out, 1, 16, f);
  fclose(f);
  return n == 16;
}

static void set_cipher(sqlite3* db, const char* cipher)
{
  if (cipher)
  {
    char sql[64];
    snprintf(sql, sizeof(sql), "PRAGMA cipher='%s'", cipher);
    sqlite3_exec(db, sql, 0, 0, 0);
  }
}

/* cipher parameters always come BEFORE the key */
static void set_params(sqlite3* db, const char* cipher)
{
  set_cipher(db, cipher);
  if (g_plainHdr > 0)
  {
    char sql[64];
    snprintf(sql, sizeof(sql), "PRAGMA plaintext_header_size=%d", g_plainHdr);
    sqlite3_exec(db, sql, 0, 0, 0);
  }
}

/* sets cipher and key (key==NULL: unencrypted) */
static void apply_state(sqlite3* db, const char* cipher, const char* key)
{
  if (key)
  {
    set_params(db, cipher);
    sqlite3_key(db, key, (int) strlen(key));
  }
}

/* In WAL mode: closing must not trigger a checkpoint, otherwise
** the new page 1 silently moves into the DB file. */
static void conn_setup(sqlite3* db)
{
  if (g_wal)
    sqlite3_db_config(db, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, 0);
}

/* Opens the DB in state (cipher,key); key==NULL: unencrypted.
** salt (hex) is passed as PRAGMA cipher_salt (viaUri=0) or as URI parameter (viaUri=1).
** SQLITE_OK only if the table is readable. */
static int open_state_ex(const char* cipher, const char* key, const char* salt, int viaUri,
                         sqlite3** pDb, int* pCount)
{
  int rc, n = -1, flags = SQLITE_OPEN_READWRITE;
  char fn[300];
  const char* name = DBFILE;
  *pDb = 0;
  if (salt && salt[0] && viaUri)
  {
    snprintf(fn, sizeof(fn), "file:%s?cipher_salt=%s", DBFILE, salt);
    name = fn;
    flags |= SQLITE_OPEN_URI;
  }
  rc = sqlite3_open_v2(name, pDb, flags, "multipleciphers-faulty");
  if (rc != SQLITE_OK) return rc;
  conn_setup(*pDb);
  if (key)
  {
    set_params(*pDb, cipher);
    if (salt && salt[0] && !viaUri)
    {
      char sql[128];
      snprintf(sql, sizeof(sql), "PRAGMA cipher_salt='%s'", salt);
      sqlite3_exec(*pDb, sql, 0, 0, 0);
    }
    sqlite3_key(*pDb, key, (int) strlen(key));
  }
  rc = query_int(*pDb, "SELECT count(*) FROM t", &n);
  if (pCount) *pCount = n;
  if (rc != SQLITE_OK)
  {
    sqlite3_close(*pDb);
    *pDb = 0;
  }
  return rc;
}

static int open_state(const char* cipher, const char* key, sqlite3** pDb, int* pCount)
{
  return open_state_ex(cipher, key, NULL, 0, pDb, pCount);
}

/* 1 if the state is completely readable (rows rows, integrity_check ok) */
static int state_ok_ex(const char* cipher, const char* key, const char* salt, int rows)
{
  sqlite3* db = 0;
  int n = -1, ok = 0;
  if (open_state_ex(cipher, key, salt, 0, &db, &n) == SQLITE_OK)
  {
    ok = (n == rows) && integrity_ok(db);
    sqlite3_close(db);
  }
  return ok;
}

static int state_ok(const char* cipher, const char* key, int rows)
{
  return state_ok_ex(cipher, key, NULL, rows);
}

static void remove_files(void)
{
  remove(DBFILE);
  remove(DBFILE "-journal");
  remove(DBFILE "-wal");
  remove(DBFILE "-shm");
}

typedef struct Scen
{
  const char* label;
  const char* oldCipher; const char* oldKey;   /* oldKey NULL = unencrypted */
  const char* newCipher; const char* newKey;   /* newKey NULL = decrypt */
  int fault;
  int cache;                                   /* 0 = default */
  int useSalt;                                 /* 1: call PRAGMA rekey_salt=on before the rekey */
} Scen;

/* Creates the DB in the old state with g_nrows rows; NULL on error.
** In WAL mode everything is checkpointed into the DB file afterwards and the WAL is empty. */
static sqlite3* setup_db(const Scen* s)
{
  sqlite3* db = 0;
  char* err = 0;
  char sql[512];
  int rc;

  remove_files();
  g_faultsHit = 0;
  g_fault = F_NONE;
  g_oomCountdown = 0;
  g_newSalt[0] = 0;

  rc = sqlite3_open_v2(DBFILE, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "multipleciphers-faulty");
  if (rc != SQLITE_OK)
  {
    printf("    open failed\n"); g_failures++; return NULL;
  }
  conn_setup(db);
  apply_state(db, s->oldCipher, s->oldKey);
  g_oldSalt[0] = 0;
  if (g_plainHdr > 0 && s->oldKey)
  {
    /* PRAGMA cipher_salt without a value returns the current salt after the key */
    char rawSalt[128];
    if (get_text(db, "PRAGMA cipher_salt", rawSalt, sizeof(rawSalt)) == SQLITE_OK)
      extract_hex(rawSalt, g_oldSalt, sizeof(g_oldSalt));
  }
  snprintf(sql, sizeof(sql),
    "PRAGMA journal_mode=%s;"
    "PRAGMA synchronous=FULL;"
    "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT);"
    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<%d) "
    "INSERT INTO t SELECT x, hex(randomblob(100)) FROM c;", g_wal ? "WAL" : "DELETE", g_nrows);
  rc = sqlite3_exec(db, sql, 0, 0, &err);
  if (rc != SQLITE_OK)
  {
    printf("    setup failed: %s\n", err ? err : "?");
    sqlite3_free(err); g_failures++; sqlite3_close(db);
    return NULL;
  }
  if (g_wal)
  {
    char jm[32];
    sqlite3_exec(db, "PRAGMA wal_autocheckpoint=0", 0, 0, 0);
    sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", 0, 0, 0);
    get_text(db, "PRAGMA journal_mode", jm, sizeof(jm));
    if (strcmp(jm, "wal") != 0)
    {
      printf("    WAL not available (journal_mode=%s)\n", jm);
      g_failures++; sqlite3_close(db);
      return NULL;
    }
  }
  if (s->cache > 0)
  {
    snprintf(sql, sizeof(sql), "PRAGMA cache_size=%d", s->cache);
    sqlite3_exec(db, sql, 0, 0, 0);
  }
  return db;
}

/* PRAGMA rekey_salt=on creates a NEW salt for the next rekey on every call;
** PRAGMA rekey_salt without a value shows the salt that is set. */
static int rekey_salt_on(sqlite3* db, char* buf, size_t n)
{
  sqlite3_exec(db, "PRAGMA rekey_salt=on", 0, 0, 0);
  return get_text(db, "PRAGMA rekey_salt", buf, n);
}

/* creates rekey_salt (after set_params of the target cipher) and stores it in g_newSalt */
static int fetch_rekey_salt(sqlite3* db)
{
  char raw[128];
  int rc = rekey_salt_on(db, raw, sizeof(raw));
  extract_hex(raw, g_newSalt, sizeof(g_newSalt));
  printf("    rekey_salt: rc=%d '%s'\n", rc, raw);
  return rc;
}

static int do_rekey(sqlite3* db, const Scen* s)
{
  g_newSalt[0] = 0;
  if (s->newKey)
  {
    set_params(db, s->newCipher);
    if (s->useSalt) fetch_rekey_salt(db);
    return sqlite3_rekey(db, s->newKey, (int) strlen(s->newKey));
  }
  return sqlite3_rekey(db, NULL, 0);
}

/* open the new state; in WAL mode with the rekey_salt salt, otherwise without */
static int open_new_state(const Scen* s, sqlite3** pDb, int* pN)
{
  const char* salt = (g_wal && s->useSalt && g_newSalt[0]) ? g_newSalt : NULL;
  return open_state_ex(s->newCipher, s->newKey, salt, 0, pDb, pN);
}

/* ------------------------------------------------------------------ */
/* Part 1 (and 4): commit failures                                    */
/* ------------------------------------------------------------------ */
static const Scen scenarios[] =
{
  /* encrypted -> encrypted, same reserved bytes (normal path) */
  { "chacha20 -> chacha20: control",               "chacha20",  "old-key", "chacha20",  "new-key", F_NONE,           0  },
  { "chacha20 -> chacha20: sync failure",          "chacha20",  "old-key", "chacha20",  "new-key", F_DB_SYNC,        0  },
  { "chacha20 -> chacha20: sync failure, spill",   "chacha20",  "old-key", "chacha20",  "new-key", F_DB_SYNC,        10 },
  { "chacha20 -> chacha20: journal delete failure", "chacha20",  "old-key", "chacha20",  "new-key", F_JOURNAL_DELETE, 0  },
  /* encrypted -> encrypted, different reserved bytes (VACUUM path) */
  { "aes128cbc -> chacha20 [VACUUM]: control",     "aes128cbc", "old-key", "chacha20",  "new-key", F_NONE,           0  },
  { "aes128cbc -> chacha20 [VACUUM]: sync failure", "aes128cbc", "old-key", "chacha20",  "new-key", F_DB_SYNC,        0  },
  { "aes128cbc -> chacha20 [VACUUM]: journal delete", "aes128cbc", "old-key", "chacha20",  "new-key", F_JOURNAL_DELETE, 0  },
  /* unencrypted -> encrypted */
  { "plain -> aes128cbc: control",                 NULL,        NULL,      "aes128cbc", "new-key", F_NONE,           0  },
  { "plain -> aes128cbc: sync failure",            NULL,        NULL,      "aes128cbc", "new-key", F_DB_SYNC,        0  },
  { "plain -> chacha20 [VACUUM]: control",         NULL,        NULL,      "chacha20",  "new-key", F_NONE,           0  },
  { "plain -> chacha20 [VACUUM]: sync failure",    NULL,        NULL,      "chacha20",  "new-key", F_DB_SYNC,        0  },
  /* encrypted -> unencrypted */
  { "aes128cbc -> plain: control",                 "aes128cbc", "old-key", NULL,        NULL,      F_NONE,           0  },
  { "aes128cbc -> plain: sync failure",            "aes128cbc", "old-key", NULL,        NULL,      F_DB_SYNC,        0  },
  { "chacha20 -> plain [VACUUM]: control",         "chacha20",  "old-key", NULL,        NULL,      F_NONE,           0  },
  { "chacha20 -> plain [VACUUM]: sync failure",    "chacha20",  "old-key", NULL,        NULL,      F_DB_SYNC,        0  },
  /* Legacy cipher with reserved bytes (isLegacy != 0), VACUUM path.
  ** Note: sqlcipher uses many KDF iterations, these scenarios are slow. */
  { "plain -> sqlcipher [VACUUM]: control",        NULL,        NULL,      "sqlcipher", "new-key", F_NONE,           0  },
  { "plain -> sqlcipher [VACUUM]: sync failure",   NULL,        NULL,      "sqlcipher", "new-key", F_DB_SYNC,        0  },
  { "sqlcipher -> plain [VACUUM]: control",        "sqlcipher", "old-key", NULL,        NULL,      F_NONE,           0  },
  { "sqlcipher -> plain [VACUUM]: sync failure",   "sqlcipher", "old-key", NULL,        NULL,      F_DB_SYNC,        0  },
};

/* WAL mode: commit failure = sync failure on the WAL file.
** With a cipher/salt change (rekey_salt) the new page 1 exists only in the WAL; the
** check of the new state then passes the salt via cipher_salt. */
static const Scen walScenarios[] =
{
  { "WAL chacha20 -> chacha20 (old salt): control",         "chacha20",  "old-key", "chacha20", "new-key", F_NONE,     0,  0 },
  { "WAL chacha20 -> chacha20 (old salt): WAL sync",        "chacha20",  "old-key", "chacha20", "new-key", F_WAL_SYNC, 0,  0 },
  { "WAL chacha20 -> chacha20 (old salt): WAL sync, spill", "chacha20",  "old-key", "chacha20", "new-key", F_WAL_SYNC, 10, 0 },
  { "WAL chacha20 -> chacha20 (rekey_salt): control",       "chacha20",  "old-key", "chacha20", "new-key", F_NONE,     0,  1 },
  { "WAL chacha20 -> chacha20 (rekey_salt): WAL sync",      "chacha20",  "old-key", "chacha20", "new-key", F_WAL_SYNC, 0,  1 },
  { "WAL aes128cbc -> chacha20 [VACUUM] (rekey_salt): control",   "aes128cbc", "old-key", "chacha20", "new-key", F_NONE,     0, 1 },
  { "WAL aes128cbc -> chacha20 [VACUUM] (rekey_salt): WAL sync",  "aes128cbc", "old-key", "chacha20", "new-key", F_WAL_SYNC, 0, 1 },
  { "WAL plain -> chacha20 [VACUUM] (rekey_salt): control",       NULL,        NULL,      "chacha20", "new-key", F_NONE,     0, 1 },
  { "WAL plain -> chacha20 [VACUUM] (rekey_salt): WAL sync",      NULL,        NULL,      "chacha20", "new-key", F_WAL_SYNC, 0, 1 },
  { "WAL chacha20 -> plain [VACUUM]: control",              "chacha20",  "old-key", NULL,       NULL,      F_NONE,     0,  0 },
  { "WAL chacha20 -> plain [VACUUM]: WAL sync",             "chacha20",  "old-key", NULL,       NULL,      F_WAL_SYNC, 0,  0 },
};

static void run(const Scen* s)
{
  sqlite3* db;
  int rc, n = -1;
  int expect;             /* expected number of rows after the failure */
  int journalLeft = 0;    /* 1: -journal exists after the rekey */
  unsigned char h0[16];   /* DB header (salt or SQLite header) before the rekey */
  int haveH0;
  FILE* fj;

  printf("\n== %s (cache_size=%d) ==\n", s->label, s->cache);
  snprintf(g_ctx, sizeof(g_ctx), "run: %s", s->label);
  g_nrows = 5000;
  expect = g_nrows;
  db = setup_db(s);
  if (!db) return;

  haveH0 = read_header_salt(h0);
  g_fault = s->fault;
  rc = do_rekey(db, s);
  g_fault = F_NONE;
  printf("    rekey rc=%d (%s), faults triggered: %d\n", rc, sqlite3_errmsg(db), g_faultsHit);

  /* WAL: rekey deliberately not supported in this path -> skip */
  if (g_wal && rc != SQLITE_OK && g_faultsHit == 0 && strstr(sqlite3_errmsg(db), "WAL"))
  {
    printf("    [skip] not supported in WAL mode: %s\n", sqlite3_errmsg(db));
    g_skipped++;
    sqlite3_close(db);
    return;
  }

  fj = fopen(DBFILE "-journal", "rb");
  journalLeft = (fj != NULL);
  printf("    journal after rekey: %s\n", fj ? "present" : "gone");
  if (fj) fclose(fj);

  if (s->fault != F_NONE)
  {
    CHECK(g_faultsHit == 1, "fault was triggered exactly once");
    CHECK(rc != SQLITE_OK, "rekey reports an error");
    {
      const char* m = sqlite3_errmsg(db);
      if (!m || !m[0] || strcmp(m, "not an error") == 0) {
        printf("    [WARN] no meaningful error message after failed rekey ('%s')\n", m ? m : "");
        g_warnings++;
      }
    }
    CHECK(sqlite3_get_autocommit(db) == 1 && sqlite3_txn_state(db, "main") == SQLITE_TXN_NONE,
          "no transaction left open after the failure (autocommit, txn_state)");
    if (s->fault == F_DB_SYNC)
    {
      /* The rollback inside rekey must run to completion. If the journal
      ** stays behind, it failed (e.g. because of a wrong reserved-bytes value)
      ** and was only replayed on the next access. */
      CHECK(!journalLeft, "rollback complete: no hot journal after sync failure");
    }

    n = -1;
    rc = query_int(db, "SELECT count(*) FROM t", &n);
    printf("    query on old connection: rc=%d (%s) n=%d\n", rc, sqlite3_errmsg(db), n);
    CHECK(rc == SQLITE_OK && n == g_nrows, "connection usable after the failure, all rows readable");
    CHECK(integrity_ok(db), "integrity_check on existing connection ok");
    {
      /* Writing after the failure: reveals discrepancies between the in-memory btree
      ** (reserved bytes, page size) and the file */
      char sql[96];
      snprintf(sql, sizeof(sql), "INSERT INTO t VALUES(%d,'after-fail')", g_nrows + 1);
      rc = sqlite3_exec(db, sql, 0, 0, 0);
      printf("    INSERT after failure: rc=%d (%s), reserve=%d\n", rc, sqlite3_errmsg(db), get_reserve(db));
      CHECK(rc == SQLITE_OK, "writing on the existing connection possible after the failure");
      if (rc == SQLITE_OK) expect++;
    }
    sqlite3_close(db);

    if (haveH0 && (!s->oldKey || header_salt_cipher(s->oldCipher)))
    {
      /* Even for plain -> encrypted no random salt may be in the header after a
      ** failure: the old unencrypted state is preserved. */
      unsigned char h1[16];
      CHECK(read_header_salt(h1) && memcmp(h0, h1, 16) == 0,
            "DB header (salt or SQLite header) unchanged after the failure");
    }

    rc = open_state(s->oldCipher, s->oldKey, &db, &n);
    CHECK(rc == SQLITE_OK && n == expect, "reopen in the OLD state: all rows readable");
    if (db)
    {
      CHECK(integrity_ok(db), "integrity_check in the old state ok"); sqlite3_close(db);
    }

    rc = open_new_state(s, &db, &n);
    CHECK(rc != SQLITE_OK, "NEW state does NOT work");
    if (db) sqlite3_close(db);
  }
  else
  {
    CHECK(rc == SQLITE_OK, "rekey without fault succeeds");
    CHECK(sqlite3_get_autocommit(db) == 1 && sqlite3_txn_state(db, "main") == SQLITE_TXN_NONE,
          "no transaction left open after the rekey (autocommit, txn_state)");
    sqlite3_close(db);
    if (!g_wal && haveH0)
    {
      /* In WAL mode the new header is in the file only after a checkpoint */
      unsigned char h1[16];
      int haveH1 = read_header_salt(h1);
      if (s->newKey && header_salt_cipher(s->newCipher))
      {
        if (s->useSalt && g_newSalt[0])
          CHECK(haveH1 && hex_matches(h1, g_newSalt), "DB header contains the salt set with rekey_salt");
        else if (s->oldKey && header_salt_cipher(s->oldCipher))
          CHECK(haveH1 && memcmp(h0, h1, 16) == 0, "old salt is kept in the DB header");
        else if (!s->oldKey)
          CHECK(haveH1 && memcmp(h0, h1, 16) != 0, "random salt in the DB header (no longer the SQLite header)");
      }
      else if (!s->newKey)
      {
        CHECK(haveH1 && is_sqlite_magic(h1), "DB header is the unencrypted SQLite header again");
      }
    }
    rc = open_new_state(s, &db, &n);
    CHECK(rc == SQLITE_OK && n == g_nrows, "NEW state: all rows readable");
    if (db)
    {
      CHECK(integrity_ok(db), "integrity_check in the new state ok"); sqlite3_close(db);
    }
    rc = open_state(s->oldCipher, s->oldKey, &db, &n);
    CHECK(rc != SQLITE_OK, "OLD state no longer works");
    if (db) sqlite3_close(db);
  }
}

/* ------------------------------------------------------------------ */
/* Part 2: rekey inside an open transaction                           */
/* ------------------------------------------------------------------ */
static const Scen txnScenarios[] =
{
  { "aes128cbc -> chacha20 [VACUUM]", "aes128cbc", "old-key", "chacha20", "new-key", F_NONE, 0 },
  { "plain -> chacha20 [VACUUM]",     NULL,        NULL,      "chacha20", "new-key", F_NONE, 0 },
  { "chacha20 -> plain [VACUUM]",     "chacha20",  "old-key", NULL,       NULL,      F_NONE, 0 },
  /* in-place paths (same reserved bytes) */
  { "chacha20 -> chacha20 [in-place]",  "chacha20",  "old-key", "chacha20",  "new-key", F_NONE, 0 },
  { "plain -> aes128cbc [in-place]",    NULL,        NULL,      "aes128cbc", "new-key", F_NONE, 0 },
  { "aes128cbc -> plain [in-place]",    "aes128cbc", "old-key", NULL,        NULL,      F_NONE, 0 },
};

static void run_in_txn(const Scen* s)
{
  sqlite3* db;
  char* err = 0;
  int rc, n = -1;
  char sql[128];

  printf("\n== rekey inside a transaction: %s ==\n", s->label);
  snprintf(g_ctx, sizeof(g_ctx), "Part 2: %s", s->label);
  g_nrows = 5000;
  db = setup_db(s);
  if (!db) return;

  snprintf(sql, sizeof(sql), "BEGIN; INSERT INTO t VALUES(%d,'extra');", g_nrows + 1);
  rc = sqlite3_exec(db, sql, 0, 0, &err);
  CHECK(rc == SQLITE_OK, "BEGIN and INSERT");
  sqlite3_free(err); err = 0;

  printf("    reserve before rekey: %d\n", get_reserve(db));
  rc = do_rekey(db, s);
  printf("    rekey rc=%d (%s), reserve after: %d\n", rc, sqlite3_errmsg(db), get_reserve(db));
  CHECK(rc != SQLITE_OK, "rekey inside an open transaction is rejected");

  /* Keep working and commit: must not produce a mixed state.
  ** Run the steps one by one to see which of them fails. */
  rc = query_int(db, "SELECT count(*) FROM t", &n);
  printf("    SELECT in transaction: rc=%d (%s) n=%d, autocommit=%d\n",
         rc, sqlite3_errmsg(db), n, sqlite3_get_autocommit(db));
  snprintf(sql, sizeof(sql), "INSERT INTO t VALUES(%d,'extra2')", g_nrows + 2);
  rc = sqlite3_exec(db, sql, 0, 0, &err);
  printf("    INSERT: rc=%d (%s)\n", rc, err ? err : "ok");
  sqlite3_free(err); err = 0;
  if (rc == SQLITE_OK)
  {
    rc = sqlite3_exec(db, "COMMIT", 0, 0, &err);
    printf("    COMMIT: rc=%d (%s)\n", rc, err ? err : "ok");
    sqlite3_free(err); err = 0;
  }
  CHECK(rc == SQLITE_OK, "INSERT and COMMIT after rejected rekey");
  rc = query_int(db, "SELECT count(*) FROM t", &n);
  CHECK(rc == SQLITE_OK && n == g_nrows + 2, "connection reads all rows (including the 2 new ones)");
  sqlite3_close(db);

  rc = open_state(s->oldCipher, s->oldKey, &db, &n);
  CHECK(rc == SQLITE_OK && n == g_nrows + 2, "reopen in the OLD state: all rows readable");
  if (db)
  {
    CHECK(integrity_ok(db), "integrity_check in the old state ok"); sqlite3_close(db);
  }

  rc = open_state(s->newCipher, s->newKey, &db, &n);
  CHECK(rc != SQLITE_OK, "NEW state does NOT work");
  if (db) sqlite3_close(db);
}

/* ------------------------------------------------------------------ */
/* Part 2b: rekey with an active statement and via PRAGMA rekey       */
/* ------------------------------------------------------------------ */
static const Scen miscScenarios[] =
{
  { "chacha20 -> chacha20 [in-place]", "chacha20",  "old-key", "chacha20", "new-key", F_NONE, 0 },
  { "aes128cbc -> chacha20 [VACUUM]",  "aes128cbc", "old-key", "chacha20", "new-key", F_NONE, 0 },
  { "plain -> chacha20 [VACUUM]",      NULL,        NULL,      "chacha20", "new-key", F_NONE, 0 },
};

/* A SELECT is in the middle of its run (read transaction open, autocommit=1).
** Expectation: rekey is rejected, afterwards everything is still usable unchanged. */
static void run_active_stmt(const Scen* s)
{
  sqlite3* db;
  sqlite3_stmt* st = 0;
  char* err = 0;
  char sql[96];
  int rc, n = -1;

  printf("\n== rekey with an active SELECT: %s ==\n", s->label);
  snprintf(g_ctx, sizeof(g_ctx), "Part 2b (active SELECT): %s", s->label);
  g_nrows = 5000;
  db = setup_db(s);
  if (!db) return;

  rc = sqlite3_prepare_v2(db, "SELECT a FROM t", -1, &st, 0);
  if (rc == SQLITE_OK) rc = sqlite3_step(st);
  CHECK(rc == SQLITE_ROW, "SELECT is running (read transaction open)");

  rc = do_rekey(db, s);
  printf("    rekey rc=%d (%s)\n", rc, sqlite3_errmsg(db));
  CHECK(rc != SQLITE_OK, "rekey with an active statement is rejected");
  sqlite3_finalize(st);

  snprintf(sql, sizeof(sql), "INSERT INTO t VALUES(%d,'extra')", g_nrows + 1);
  rc = sqlite3_exec(db, sql, 0, 0, &err);
  printf("    INSERT afterwards: rc=%d (%s)\n", rc, err ? err : "ok");
  sqlite3_free(err);
  CHECK(rc == SQLITE_OK, "writing possible after rejected rekey");
  sqlite3_close(db);

  rc = open_state(s->oldCipher, s->oldKey, &db, &n);
  CHECK(rc == SQLITE_OK && n == g_nrows + 1, "reopen in the OLD state: all rows readable");
  if (db) { CHECK(integrity_ok(db), "integrity_check in the old state ok"); sqlite3_close(db); }
  rc = open_state(s->newCipher, s->newKey, &db, &n);
  CHECK(rc != SQLITE_OK, "NEW state does NOT work");
  if (db) sqlite3_close(db);
}

/* PRAGMA rekey calls sqlite3_rekey_v2 from the SQL layer. It must not be
** rejected wrongly by the transaction check. */
static void run_pragma_rekey(const Scen* s)
{
  sqlite3* db;
  char* err = 0;
  char sql[96];
  int rc, n = -1;

  printf("\n== PRAGMA rekey: %s ==\n", s->label);
  snprintf(g_ctx, sizeof(g_ctx), "Part 2b (PRAGMA rekey): %s", s->label);
  g_nrows = 5000;
  db = setup_db(s);
  if (!db) return;

  set_cipher(db, s->newCipher);
  snprintf(sql, sizeof(sql), "PRAGMA rekey='%s'", s->newKey);
  rc = sqlite3_exec(db, sql, 0, 0, &err);
  printf("    PRAGMA rekey rc=%d (%s)\n", rc, err ? err : "ok");
  sqlite3_free(err);
  CHECK(rc == SQLITE_OK, "PRAGMA rekey is not rejected");
  sqlite3_close(db);

  rc = open_state(s->newCipher, s->newKey, &db, &n);
  CHECK(rc == SQLITE_OK && n == g_nrows, "NEW state: all rows readable");
  if (db)
  {
    CHECK(integrity_ok(db), "integrity_check in the new state ok"); sqlite3_close(db);
  }
  rc = open_state(s->oldCipher, s->oldKey, &db, &n);
  CHECK(rc != SQLITE_OK, "OLD state no longer works");
  if (db) sqlite3_close(db);
}

/* ------------------------------------------------------------------ */
/* Part 3 and 6: OOM loop                                             */
/* ------------------------------------------------------------------ */
static const Scen oomScenarios[] =
{
  { "chacha20 -> chacha20",              "chacha20",  "old-key", "chacha20",  "new-key", F_NONE,    0 },
  { "chacha20 -> chacha20 + sync failure","chacha20",  "old-key", "chacha20",  "new-key", F_DB_SYNC, 0 },
  { "aes128cbc -> chacha20 [VACUUM]",    "aes128cbc", "old-key", "chacha20",  "new-key", F_NONE,    0 },
  { "aes128cbc -> chacha20 [VACUUM] + sync failure", "aes128cbc", "old-key", "chacha20", "new-key", F_DB_SYNC, 0 },
  { "plain -> chacha20 [VACUUM]",        NULL,        NULL,      "chacha20",  "new-key", F_NONE,    0 },
  { "plain -> chacha20 [VACUUM] + sync failure",    NULL,        NULL,      "chacha20", "new-key", F_DB_SYNC, 0 },
  { "chacha20 -> plain [VACUUM]",        "chacha20",  "old-key", NULL,        NULL,      F_NONE,    0 },
  { "chacha20 -> plain [VACUUM] + sync failure",    "chacha20",  "old-key", NULL,        NULL,      F_DB_SYNC, 0 },
  { "plain -> aes128cbc",                NULL,        NULL,      "aes128cbc", "new-key", F_NONE,    0 },
  { "plain -> aes128cbc + sync failure", NULL,        NULL,      "aes128cbc", "new-key", F_DB_SYNC, 0 },
  { "aes128cbc -> plain",                "aes128cbc", "old-key", NULL,        NULL,      F_NONE,    0 },
  { "aes128cbc -> plain + sync failure", "aes128cbc", "old-key", NULL,        NULL,      F_DB_SYNC, 0 },
};

/* WAL: only cases in which the new state can be opened without cipher_salt
** (old salt is kept or unencrypted) */
static const Scen oomWalScenarios[] =
{
  { "WAL chacha20 -> chacha20",                    "chacha20", "old-key", "chacha20", "new-key", F_NONE,     0 },
  { "WAL chacha20 -> chacha20 + WAL sync failure", "chacha20", "old-key", "chacha20", "new-key", F_WAL_SYNC, 0 },
  { "WAL chacha20 -> plain [VACUUM]",              "chacha20", "old-key", NULL,       NULL,      F_NONE,     0 },
  { "WAL chacha20 -> plain [VACUUM] + WAL sync failure", "chacha20", "old-key", NULL,  NULL,      F_WAL_SYNC, 0 },
};

static void run_oom(const Scen* s, int stride)
{
  int N, tested = 0, fails0 = g_failures, warns0 = g_warnings, finished = 0;

  printf("\n== OOM: %s ==\n", s->label);
  g_nrows = 300;   /* keep it small, the loop recreates the DB very often */

  for (N = 1; N <= OOM_MAX; N += (N < 50 ? 1 : stride))
  {
    sqlite3* db;
    int rc, hit, oldOk, newOk, connOk = -1, n = -1;
    int connRc = 0, connReserve = -1;
    char connMsg[100] = "";

    snprintf(g_ctx, sizeof(g_ctx), "OOM: %s, N=%d", s->label, N);
    db = setup_db(s);
    if (!db) return;

    set_cipher(db, s->newKey ? s->newCipher : NULL);   /* configuration before arming */
    g_oomHit = 0;
    g_faultsHit = 0;
    g_fault = s->fault;
    g_oomCountdown = N;
    rc = s->newKey ? sqlite3_rekey(db, s->newKey, (int) strlen(s->newKey))
                   : sqlite3_rekey(db, NULL, 0);
    g_oomCountdown = 0;
    g_fault = F_NONE;
    hit = g_oomHit;

    if (!hit)
    {            /* fewer than N allocations: everything covered */
      sqlite3_close(db);
      finished = 1;
      break;
    }
    tested++;

    /* No transaction may remain open. Must be checked BEFORE sqlite3_close:
    ** close rolls back an open transaction and would hide it. */
    if (sqlite3_get_autocommit(db) != 1 || sqlite3_txn_state(db, "main") != SQLITE_TXN_NONE)
    {
      printf("    [FAIL] N=%d rc=%d: a transaction is still open after the rekey (autocommit=%d, txn_state=%d)\n",
             N, rc, sqlite3_get_autocommit(db), sqlite3_txn_state(db, "main"));
      g_failures++;
    }

    /* check the connection while it is still open */
    {
      int q = query_int(db, "SELECT count(*) FROM t", &n);
      connOk = (q == SQLITE_OK && n == g_nrows);
      connRc = q;
      snprintf(connMsg, sizeof(connMsg), "%s", sqlite3_errmsg(db));
      connReserve = get_reserve(db);
    }
    sqlite3_close(db);

    oldOk = state_ok(s->oldCipher, s->oldKey, g_nrows);
    newOk = state_ok(s->newCipher, s->newKey, g_nrows);

    if (oldOk && newOk)
    {
      printf("    [FAIL] N=%d rc=%d: BOTH states readable\n", N, rc); g_failures++;
    }
    else if (!oldOk && !newOk)
    {
      printf("    [FAIL] N=%d rc=%d: NEITHER old NOR new state readable\n", N, rc); g_failures++;
    }
    else if (rc == SQLITE_OK && oldOk)
    {
      printf("    [FAIL] N=%d: rekey reports OK, but the file still has the old state\n", N); g_failures++;
    }
    else if (rc != SQLITE_OK && newOk)
    {
      printf("    [WARN] N=%d rc=%d: error reported, but the file has the new state\n", N, rc); g_warnings++;
    }
    else if (!connOk)
    {
      printf("    [FAIL] N=%d rc=%d: file ok (%s), but connection not usable afterwards: "
             "query rc=%d (%s), n=%d, reserve=%d\n",
             N, rc, oldOk ? "old state" : "new state", connRc, connMsg, n, connReserve);
      g_failures++;
    }
  }

  printf("    %d OOM positions tested%s, %d FAIL, %d WARN\n",
         tested, finished ? "" : " (OOM_MAX reached, not all covered)",
         g_failures - fails0, g_warnings - warns0);
}

/* ------------------------------------------------------------------ */
/* Part 5: salt behaviour (default / PRAGMA rekey_salt, journal / WAL) */
/* ------------------------------------------------------------------ */
static void run_salt(int wal, int useRekeySalt)
{
  Scen s = { "salt", "chacha20", "old-key", "chacha20", "new-key", F_NONE, 0, 0 };
  sqlite3* db = 0;
  unsigned char h0[16], h1[16];
  char raw[128], salt[40] = "";
  int rc, n = -1, haveH0, haveH1;

  printf("\n== Salt: %s, %s ==\n", wal ? "WAL" : "rollback journal",
         useRekeySalt ? "with PRAGMA rekey_salt" : "default (old salt is kept)");
  snprintf(g_ctx, sizeof(g_ctx), "Part 5: salt wal=%d rekey_salt=%d", wal, useRekeySalt);
  g_wal = wal;
  g_nrows = 5000;
  db = setup_db(&s);
  if (!db) { g_wal = 0; return; }

  haveH0 = read_header_salt(h0);
  CHECK(haveH0, "salt read from the DB header (before the rekey)");
  set_cipher(db, "chacha20");
  if (useRekeySalt)
  {
    rc = rekey_salt_on(db, raw, sizeof(raw));
    extract_hex(raw, salt, sizeof(salt));
    printf("    rekey_salt: rc=%d '%s'\n", rc, raw);
    CHECK(rc == SQLITE_OK && strlen(salt) == 32, "rekey_salt returns 16 bytes (32 hex characters)");
    CHECK(haveH0 && !hex_matches(h0, salt), "rekey_salt is a NEW salt");
  }
  rc = sqlite3_rekey(db, "new-key", 7);
  printf("    rekey rc=%d (%s)\n", rc, sqlite3_errmsg(db));
  CHECK(rc == SQLITE_OK, "rekey succeeds");
  sqlite3_close(db);
  haveH1 = read_header_salt(h1);
  CHECK(haveH1, "salt read from the DB header (after the rekey)");

  if (!wal)
  {
    if (useRekeySalt)
      CHECK(hex_matches(h1, salt), "DB header contains the new salt");
    else
      CHECK(memcmp(h0, h1, 16) == 0, "DB header salt unchanged (old salt is kept)");
    rc = open_state("chacha20", "new-key", &db, &n);
    CHECK(rc == SQLITE_OK && n == g_nrows, "new key without cipher_salt: all rows readable");
    if (db)
    {
      char h1hex[40];
      CHECK(integrity_ok(db), "integrity_check ok");
      bytes_to_hex(h1, h1hex);
      CHECK(cipher_salt_is(db, h1hex), "PRAGMA cipher_salt returns the salt from the header after key");
      sqlite3_close(db);
    }
  }
  else
  {
    CHECK(memcmp(h0, h1, 16) == 0, "DB header still unchanged (new page 1 exists only in the WAL)");
    if (useRekeySalt)
    {
      rc = open_state_ex("chacha20", "new-key", NULL, 0, &db, &n);
      CHECK(rc != SQLITE_OK, "cannot be opened without cipher_salt (salt comes from the DB header)");
      if (db) sqlite3_close(db);
      rc = open_state_ex("chacha20", "new-key", salt, 0, &db, &n);
      CHECK(rc == SQLITE_OK && n == g_nrows, "with PRAGMA cipher_salt: all rows readable");
      if (db)
      {
        CHECK(integrity_ok(db), "integrity_check ok (PRAGMA cipher_salt)");
        CHECK(cipher_salt_is(db, salt), "PRAGMA cipher_salt returns the supplied salt after key");
        sqlite3_close(db);
      }
      rc = open_state_ex("chacha20", "new-key", salt, 1, &db, &n);
      CHECK(rc == SQLITE_OK && n == g_nrows, "with URI parameter cipher_salt: all rows readable");
      if (db)
      {
        CHECK(integrity_ok(db), "integrity_check ok (URI parameter)");
        sqlite3_close(db);
      }
    }
    else
    {
      rc = open_state_ex("chacha20", "new-key", NULL, 0, &db, &n);
      CHECK(rc == SQLITE_OK && n == g_nrows, "without cipher_salt: all rows readable (old salt)");
      if (db)
      {
        CHECK(integrity_ok(db), "integrity_check ok"); sqlite3_close(db);
      }
    }

    /* checkpoint: page 1 moves from the WAL into the DB file */
    rc = open_state_ex("chacha20", "new-key", useRekeySalt ? salt : NULL, 0, &db, &n);
    CHECK(rc == SQLITE_OK, "opened for the checkpoint");
    if (db)
    {
      rc = sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", 0, 0, 0);
      CHECK(rc == SQLITE_OK, "wal_checkpoint(TRUNCATE) succeeds");
      sqlite3_close(db);
    }
    haveH1 = read_header_salt(h1);
    if (useRekeySalt)
      CHECK(haveH1 && hex_matches(h1, salt), "after checkpoint: DB header contains the new salt");
    else
      CHECK(haveH1 && memcmp(h0, h1, 16) == 0, "after checkpoint: DB header salt unchanged");
    rc = open_state_ex("chacha20", "new-key", NULL, 0, &db, &n);
    CHECK(rc == SQLITE_OK && n == g_nrows, "after checkpoint without cipher_salt: all rows readable");
    if (db)
    {
      CHECK(integrity_ok(db), "integrity_check ok (after checkpoint)"); sqlite3_close(db);
    }
  }
  rc = open_state("chacha20", "old-key", &db, &n);
  CHECK(rc != SQLITE_OK, "old key no longer works");
  if (db) sqlite3_close(db);
  g_wal = 0;
}

/* Failed rekey after rekey_salt, then a retry on the same connection. It is open
** whether the salt that was set is still valid after the failure; the check is that
** the new state is readable either with the old salt or with the rekey_salt salt (WAL)
** or without cipher_salt (rollback journal). */
static void run_salt_fail(int wal)
{
  Scen s = { "salt-fail", "chacha20", "old-key", "chacha20", "new-key", F_NONE, 0, 0 };
  sqlite3* db = 0;
  unsigned char h0[16], h1[16];
  char raw[128], salt[40] = "";
  int rc, n = -1;
  int fault = wal ? F_WAL_SYNC : F_DB_SYNC;

  printf("\n== Salt: failed rekey after rekey_salt, %s ==\n", wal ? "WAL" : "rollback journal");
  snprintf(g_ctx, sizeof(g_ctx), "Part 5: salt failure wal=%d", wal);
  g_wal = wal;
  g_nrows = 5000;
  db = setup_db(&s);
  if (!db) { g_wal = 0; return; }

  CHECK(read_header_salt(h0), "salt read from the DB header");
  set_cipher(db, "chacha20");
  rc = rekey_salt_on(db, raw, sizeof(raw));
  extract_hex(raw, salt, sizeof(salt));
  CHECK(rc == SQLITE_OK && strlen(salt) == 32, "rekey_salt returned");

  g_faultsHit = 0;
  g_fault = fault;
  rc = sqlite3_rekey(db, "new-key", 7);
  g_fault = F_NONE;
  printf("    rekey rc=%d (%s)\n", rc, sqlite3_errmsg(db));
  CHECK(g_faultsHit == 1, "fault was triggered exactly once");
  CHECK(rc != SQLITE_OK, "rekey reports an error");
  rc = query_int(db, "SELECT count(*) FROM t", &n);
  CHECK(rc == SQLITE_OK && n == g_nrows, "connection usable after the failure, all rows readable");

  /* retry without calling rekey_salt again */
  rc = sqlite3_rekey(db, "new-key", 7);
  printf("    retry rekey rc=%d (%s)\n", rc, sqlite3_errmsg(db));
  CHECK(rc == SQLITE_OK, "retry of the rekey on the same connection succeeds");
  sqlite3_close(db);
  CHECK(read_header_salt(h1), "salt read from the DB header (after the retry)");

  if (!wal)
  {
    int usedNew = hex_matches(h1, salt), usedOld = (memcmp(h0, h1, 16) == 0);
    printf("    salt used: %s\n", usedNew ? "rekey_salt salt" : (usedOld ? "old salt" : "unknown"));
    CHECK(usedNew || usedOld, "DB header contains the rekey_salt salt or the old salt");
    rc = open_state("chacha20", "new-key", &db, &n);
    CHECK(rc == SQLITE_OK && n == g_nrows, "new key without cipher_salt: all rows readable");
    if (db) sqlite3_close(db);
  }
  else
  {
    int okOld = state_ok_ex("chacha20", "new-key", NULL, g_nrows);
    int okNew = state_ok_ex("chacha20", "new-key", salt, g_nrows);
    printf("    readable without cipher_salt: %d, with rekey_salt salt: %d\n", okOld, okNew);
    CHECK(okOld || okNew, "new state readable (old salt or rekey_salt salt)");
  }
  CHECK(!state_ok("chacha20", "old-key", g_nrows), "old key no longer works");
  g_wal = 0;
}

/* ------------------------------------------------------------------ */
/* Part 7: plaintext_header_size                                      */
/* The first bytes of the file stay unencrypted (SQLite header),      */
/* the salt is NOT stored in the file and must always be supplied.    */
/* ------------------------------------------------------------------ */
#define PH_CIPHER "chacha20"   /* use "sqlcipher" if the option only applies there */
#define PH_SIZE   32

static int ph_header_is_plain(void)
{
  unsigned char h[16];
  return read_header_salt(h) && is_sqlite_magic(h);
}

/* 1 if plaintext_header_size is active for this connection */
static int ph_active(sqlite3* db)
{
  char v[32];
  return get_text(db, "PRAGMA plaintext_header_size", v, sizeof(v)) == SQLITE_OK && atoi(v) == PH_SIZE;
}

/* WAL checkpoint through a connection in the given state */
static void ph_checkpoint(const char* cipher, const char* key, const char* salt)
{
  sqlite3* db = 0;
  int n = -1;
  if (open_state_ex(cipher, key, salt, 0, &db, &n) == SQLITE_OK)
  {
    int rc = sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", 0, 0, 0);
    CHECK(rc == SQLITE_OK, "wal_checkpoint(TRUNCATE) succeeds");
    sqlite3_close(db);
  }
  else
  {
    CHECK(0, "opened for the checkpoint");
  }
}

/* encrypted (with plaintext_header_size) -> encrypted */
static void ph_rekey(int wal, int useRekeySalt, int fault)
{
  Scen s = { "ph", PH_CIPHER, "old-key", PH_CIPHER, "new-key", F_NONE, 0, 0 };
  sqlite3* db = 0;
  char s0[40], s1[40] = "", sn[40];
  int rc, n = -1;

  printf("\n== plaintext_header_size: %s, %s, %s ==\n", wal ? "WAL" : "rollback journal",
         useRekeySalt ? "with rekey_salt" : "old salt is kept", fault ? "with sync failure" : "without failure");
  snprintf(g_ctx, sizeof(g_ctx), "Part 7: ph_rekey wal=%d rekey_salt=%d fault=%d", wal, useRekeySalt, fault);
  g_wal = wal;
  g_nrows = 5000;
  g_plainHdr = PH_SIZE;
  db = setup_db(&s);
  if (!db) goto done;
  if (!ph_active(db))
  {
    printf("    [skip] plaintext_header_size=%d cannot be activated for %s\n", PH_SIZE, PH_CIPHER);
    g_skipped++;
    sqlite3_close(db);
    goto done;
  }

  snprintf(s0, sizeof(s0), "%s", g_oldSalt);
  CHECK(strlen(s0) == 32, "PRAGMA cipher_salt returns the salt after key (32 hex characters)");
  CHECK(ph_header_is_plain(), "DB header stays plain text (salt is not stored in the file)");
  CHECK(state_ok_ex(PH_CIPHER, "old-key", s0, g_nrows), "initial state readable with cipher_salt");
  CHECK(!state_ok_ex(PH_CIPHER, "old-key", NULL, g_nrows), "initial state NOT readable without cipher_salt");

  set_params(db, PH_CIPHER);
  if (useRekeySalt)
  {
    fetch_rekey_salt(db);
    snprintf(s1, sizeof(s1), "%s", g_newSalt);
    CHECK(strlen(s1) == 32 && strcmp(s0, s1) != 0, "rekey_salt returns a new salt");
    snprintf(sn, sizeof(sn), "%s", s1);
  }
  else
  {
    snprintf(sn, sizeof(sn), "%s", s0);
  }

  g_faultsHit = 0;
  g_fault = fault ? (wal ? F_WAL_SYNC : F_DB_SYNC) : F_NONE;
  rc = sqlite3_rekey(db, "new-key", 7);
  g_fault = F_NONE;
  printf("    rekey rc=%d (%s), faults triggered: %d\n", rc, sqlite3_errmsg(db), g_faultsHit);

  if (fault)
  {
    CHECK(g_faultsHit == 1, "fault was triggered exactly once");
    CHECK(rc != SQLITE_OK, "rekey reports an error");
    n = -1;
    rc = query_int(db, "SELECT count(*) FROM t", &n);
    CHECK(rc == SQLITE_OK && n == g_nrows, "connection usable after the failure, all rows readable");
    sqlite3_close(db);
    CHECK(ph_header_is_plain(), "DB header still plain text");
    CHECK(state_ok_ex(PH_CIPHER, "old-key", s0, g_nrows), "OLD state readable with the old salt");
    CHECK(!state_ok_ex(PH_CIPHER, "new-key", sn, g_nrows), "NEW state does NOT work");
  }
  else
  {
    CHECK(rc == SQLITE_OK, "rekey succeeds");
    sqlite3_close(db);
    CHECK(ph_header_is_plain(), "DB header still plain text");
    CHECK(state_ok_ex(PH_CIPHER, "new-key", sn, g_nrows), "NEW state readable with cipher_salt");
    CHECK(!state_ok_ex(PH_CIPHER, "new-key", NULL, g_nrows), "NEW state NOT readable without cipher_salt");
    if (useRekeySalt)
      CHECK(!state_ok_ex(PH_CIPHER, "new-key", s0, g_nrows), "new key with the OLD salt NOT readable");
    if (wal)
    {
      ph_checkpoint(PH_CIPHER, "new-key", sn);
      CHECK(ph_header_is_plain(), "after checkpoint: DB header still plain text");
      CHECK(state_ok_ex(PH_CIPHER, "new-key", sn, g_nrows), "after checkpoint: readable with cipher_salt");
      CHECK(!state_ok_ex(PH_CIPHER, "new-key", NULL, g_nrows), "after checkpoint: still NOT readable without cipher_salt");
    }
    CHECK(!state_ok_ex(PH_CIPHER, "old-key", s0, g_nrows), "OLD key no longer works");
  }
done:
  g_plainHdr = 0;
  g_wal = 0;
}

/* unencrypted -> encrypted with plaintext_header_size (salt via rekey_salt) */
static void ph_encrypt(int wal, int fault)
{
  Scen s = { "ph-encrypt", NULL, NULL, PH_CIPHER, "new-key", F_NONE, 0, 0 };
  sqlite3* db = 0;
  char s1[40] = "";
  int rc, n = -1;

  printf("\n== plaintext_header_size: plain -> encrypted, %s, %s ==\n",
         wal ? "WAL" : "rollback journal", fault ? "with sync failure" : "without failure");
  snprintf(g_ctx, sizeof(g_ctx), "Part 7: ph_encrypt wal=%d fault=%d", wal, fault);
  g_wal = wal;
  g_nrows = 5000;
  g_plainHdr = PH_SIZE;
  db = setup_db(&s);
  if (!db) goto done;
  CHECK(ph_header_is_plain(), "initial state: unencrypted SQLite header");

  set_params(db, PH_CIPHER);
  if (!ph_active(db))
  {
    printf("    [skip] plaintext_header_size=%d cannot be activated for %s\n", PH_SIZE, PH_CIPHER);
    g_skipped++;
    sqlite3_close(db);
    goto done;
  }
  fetch_rekey_salt(db);
  snprintf(s1, sizeof(s1), "%s", g_newSalt);
  CHECK(strlen(s1) == 32, "rekey_salt returns a salt (32 hex characters)");

  g_faultsHit = 0;
  g_fault = fault ? (wal ? F_WAL_SYNC : F_DB_SYNC) : F_NONE;
  rc = sqlite3_rekey(db, "new-key", 7);
  g_fault = F_NONE;
  printf("    rekey rc=%d (%s), faults triggered: %d\n", rc, sqlite3_errmsg(db), g_faultsHit);

  if (wal && rc != SQLITE_OK && g_faultsHit == 0 && strstr(sqlite3_errmsg(db), "WAL"))
  {
    printf("    [skip] not supported in WAL mode: %s\n", sqlite3_errmsg(db));
    g_skipped++;
    sqlite3_close(db);
    goto done;
  }

  if (fault)
  {
    CHECK(g_faultsHit == 1, "fault was triggered exactly once");
    CHECK(rc != SQLITE_OK, "rekey reports an error");
    n = -1;
    rc = query_int(db, "SELECT count(*) FROM t", &n);
    CHECK(rc == SQLITE_OK && n == g_nrows, "connection usable after the failure, all rows readable");
    sqlite3_close(db);
    CHECK(ph_header_is_plain(), "DB header still the SQLite header");
    CHECK(state_ok_ex(NULL, NULL, NULL, g_nrows), "OLD unencrypted state readable");
    CHECK(!state_ok_ex(PH_CIPHER, "new-key", s1, g_nrows), "NEW state does NOT work");
  }
  else
  {
    CHECK(rc == SQLITE_OK, "rekey succeeds");
    sqlite3_close(db);
    CHECK(ph_header_is_plain(), "DB header still plain text (salt not in the file)");
    CHECK(state_ok_ex(PH_CIPHER, "new-key", s1, g_nrows), "NEW state readable with the rekey_salt salt");
    CHECK(!state_ok_ex(PH_CIPHER, "new-key", NULL, g_nrows), "NEW state NOT readable without cipher_salt");
    if (wal)
    {
      ph_checkpoint(PH_CIPHER, "new-key", s1);
      CHECK(ph_header_is_plain(), "after checkpoint: DB header still plain text");
      CHECK(state_ok_ex(PH_CIPHER, "new-key", s1, g_nrows), "after checkpoint: readable with cipher_salt");
      CHECK(!state_ok_ex(PH_CIPHER, "new-key", NULL, g_nrows), "after checkpoint: still NOT readable without cipher_salt");
    }
    CHECK(!state_ok_ex(NULL, NULL, NULL, g_nrows), "unencrypted access no longer works");
  }
done:
  g_plainHdr = 0;
  g_wal = 0;
}

static void run_plainhdr_all(int doWal)
{
  int w;
  for (w = 0; w <= (doWal ? 1 : 0); w++)
  {
    ph_rekey(w, 0, 0);
    ph_rekey(w, 1, 0);
    ph_rekey(w, 0, 1);
    ph_rekey(w, 1, 1);
    ph_encrypt(w, 0);
    ph_encrypt(w, 1);
  }
}

/* ------------------------------------------------------------------ */
/* Part 8: salt management and behaviour when reading the file header */
/* ------------------------------------------------------------------ */

/* FNV-1a over the whole file (size in *pSize, -1 if not readable) */
static unsigned long long file_hash(const char* path, long* pSize)
{
  FILE* f = fopen(path, "rb");
  unsigned long long h = 1469598103934665603ULL;
  long n = 0;
  int c;
  if (!f) { if (pSize) *pSize = -1; return 0; }
  while ((c = fgetc(f)) != EOF)
  {
    h ^= (unsigned char) c;
    h *= 1099511628211ULL;
    n++;
  }
  fclose(f);
  if (pSize) *pSize = n;
  return h;
}

/* writes n bytes 'A'..'Z' (no SQLite header, no valid salt) */
static void write_bytes(const char* path, size_t n)
{
  FILE* f = fopen(path, "wb");
  size_t i;
  if (!f) return;
  for (i = 0; i < n; i++)
    fputc('A' + (int) (i % 26), f);
  fclose(f);
}

static int rk(sqlite3* db, const char* key)
{
  return sqlite3_rekey(db, key, (int) strlen(key));
}

/* two plain -> chacha20 rekeys with the same password must produce different salts */
static void t8_random_salt(void)
{
  Scen s = { "plain->chacha20", NULL, NULL, "chacha20", "same-key", F_NONE, 0, 0 };
  unsigned char ha[16], hb[16];
  int i, rc, ok[2] = { 0, 0 };

  printf("\n== random salt: two plain -> chacha20 with the same password ==\n");
  snprintf(g_ctx, sizeof(g_ctx), "Part 8: random salt");
  g_wal = 0;
  g_nrows = 300;
  for (i = 0; i < 2; i++)
  {
    sqlite3* db = setup_db(&s);
    if (!db) return;
    rc = do_rekey(db, &s);
    sqlite3_close(db);
    ok[i] = (rc == SQLITE_OK) && read_header_salt(i ? hb : ha);
  }
  CHECK(ok[0] && ok[1], "both rekeys succeed");
  CHECK(ok[0] && ok[1] && !is_sqlite_magic(ha) && !is_sqlite_magic(hb), "header is no longer the SQLite header");
  CHECK(ok[0] && ok[1] && memcmp(ha, hb, 16) != 0, "two rekeys with the same password produce different salts");
}

/* Salt across several rekeys on ONE connection (with plaintext_header_size it exists
** only in memory). Sequence: rekey_salt=on (S1) -> rekey k1 -> rekey k2 without rekey_salt
** (S1 stays) -> rekey_salt=on (S2, different) -> rekey k3 -> rekey_salt=on (S3) + =off ->
** rekey k4 (S2 stays, S3 discarded). With withFault a rekey fails before k2. */
static void t8_salt_chain(int plainHdr, int withFault)
{
  Scen s = { "chain", "chacha20", "k0", "chacha20", "k1", F_NONE, 0, 0 };
  sqlite3* db = 0;
  char raw[128], s0[40], s1[40], s2[40], s3[40], cur[40];
  unsigned char h[16];
  int rc;

  printf("\n== salt across several rekeys: %s, %s ==\n",
         plainHdr ? "plaintext_header_size (salt only in memory)" : "salt in the header",
         withFault ? "with a failed rekey in between" : "without failure");
  snprintf(g_ctx, sizeof(g_ctx), "Part 8: salt_chain plainHdr=%d fault=%d", plainHdr, withFault);
  g_wal = 0;
  g_nrows = 500;
  g_plainHdr = plainHdr ? PH_SIZE : 0;
  db = setup_db(&s);
  if (!db) goto done;
  if (plainHdr && !ph_active(db))
  {
    printf("    [skip] plaintext_header_size=%d cannot be activated for %s\n", PH_SIZE, PH_CIPHER);
    g_skipped++;
    sqlite3_close(db);
    goto done;
  }
  get_text(db, "PRAGMA cipher_salt", raw, sizeof(raw));
  extract_hex(raw, s0, sizeof(s0));
  CHECK(strlen(s0) == 32, "PRAGMA cipher_salt returns the salt after key");

  /* A: rekey_salt=on, rekey k1 */
  set_params(db, "chacha20");
  rekey_salt_on(db, raw, sizeof(raw));
  extract_hex(raw, s1, sizeof(s1));
  CHECK(strlen(s1) == 32 && strcmp(s0, s1) != 0, "rekey_salt=on returns a new salt S1");
  rc = rk(db, "k1");
  CHECK(rc == SQLITE_OK, "rekey k1 succeeds");
  CHECK(state_ok_ex("chacha20", "k1", s1, g_nrows), "state k1 readable with S1");

  if (withFault)
  {
    /* rekey k2 fails: S1 must stay unchanged in memory */
    g_faultsHit = 0;
    g_fault = F_DB_SYNC;
    rc = rk(db, "k2");
    g_fault = F_NONE;
    CHECK(g_faultsHit == 1 && rc != SQLITE_OK, "rekey k2 fails (sync failure)");
    CHECK(state_ok_ex("chacha20", "k1", s1, g_nrows), "state k1 still readable with S1");
    CHECK(!state_ok_ex("chacha20", "k2", s1, g_nrows), "state k2 does NOT work");
  }

  /* B: rekey k2 without rekey_salt -> salt stays S1 */
  rc = rk(db, "k2");
  CHECK(rc == SQLITE_OK, "rekey k2 without rekey_salt succeeds");
  CHECK(state_ok_ex("chacha20", "k2", s1, g_nrows), "state k2 readable with S1 (salt is kept)");

  /* C: another rekey_salt=on creates a new salt */
  rekey_salt_on(db, raw, sizeof(raw));
  extract_hex(raw, s2, sizeof(s2));
  CHECK(strlen(s2) == 32 && strcmp(s1, s2) != 0, "second rekey_salt=on returns a different salt S2");
  rc = rk(db, "k3");
  CHECK(rc == SQLITE_OK, "rekey k3 succeeds");
  CHECK(state_ok_ex("chacha20", "k3", s2, g_nrows), "state k3 readable with S2");
  CHECK(!state_ok_ex("chacha20", "k3", s1, g_nrows), "state k3 NOT readable with S1");

  /* D: rekey_salt=on (S3) and =off discards the salt that was set */
  rekey_salt_on(db, raw, sizeof(raw));
  extract_hex(raw, s3, sizeof(s3));
  CHECK(strlen(s3) == 32 && strcmp(s2, s3) != 0, "third rekey_salt=on returns a different salt S3");
  sqlite3_exec(db, "PRAGMA rekey_salt=off", 0, 0, 0);
  get_text(db, "PRAGMA rekey_salt", raw, sizeof(raw));
  extract_hex(raw, cur, sizeof(cur));
  CHECK(strlen(cur) != 32, "rekey_salt=off deletes the salt that was set");
  rc = rk(db, "k4");
  CHECK(rc == SQLITE_OK, "rekey k4 succeeds");
  CHECK(state_ok_ex("chacha20", "k4", s2, g_nrows), "state k4 readable with S2 (salt of the read cipher)");
  CHECK(!state_ok_ex("chacha20", "k4", s3, g_nrows), "state k4 NOT readable with the discarded S3");
  sqlite3_close(db);

  if (!plainHdr)
  {
    CHECK(read_header_salt(h) && hex_matches(h, s2), "DB header contains S2");
    CHECK(state_ok_ex("chacha20", "k4", NULL, g_nrows), "readable without cipher_salt (salt from the header)");
  }
  else
  {
    CHECK(ph_header_is_plain(), "DB header stays plain text");
    CHECK(!state_ok_ex("chacha20", "k4", NULL, g_nrows), "NOT readable without cipher_salt");
  }
done:
  g_plainHdr = 0;
  g_wal = 0;
}

/* open an unencrypted DB with a key: must fail and leave the file unchanged */
static void t8_plain_with_key(void)
{
  Scen s = { "plain", NULL, NULL, NULL, NULL, F_NONE, 0, 0 };
  sqlite3* db = 0;
  char* err = 0;
  unsigned long long h0, h1;
  long sz0, sz1;
  int rc, n = -1;

  printf("\n== open an unencrypted database with a key ==\n");
  snprintf(g_ctx, sizeof(g_ctx), "Part 8: plain_with_key");
  g_wal = 0;
  g_nrows = 500;
  db = setup_db(&s);
  if (!db) return;
  sqlite3_close(db);
  h0 = file_hash(DBFILE, &sz0);

  rc = open_state("chacha20", "some-key", &db, &n);
  CHECK(rc != SQLITE_OK, "read access with a key on an unencrypted DB fails");
  if (db) sqlite3_close(db);

  rc = sqlite3_open_v2(DBFILE, &db, SQLITE_OPEN_READWRITE, "multipleciphers-faulty");
  if (rc == SQLITE_OK)
  {
    set_params(db, "chacha20");
    sqlite3_key(db, "some-key", 8);
    rc = sqlite3_exec(db, "CREATE TABLE evil(x)", 0, 0, &err);
    printf("    write attempt: rc=%d (%s)\n", rc, err ? err : "ok");
    sqlite3_free(err);
    CHECK(rc != SQLITE_OK, "write attempt with a key on an unencrypted DB fails");
    sqlite3_close(db);
  }
  h1 = file_hash(DBFILE, &sz1);
  CHECK(h0 == h1 && sz0 == sz1, "file stays unchanged (content and size)");
  CHECK(state_ok_ex(NULL, NULL, NULL, g_nrows), "unencrypted still completely readable");
}

/* Empty and too short files: empty -> new encrypted DB with random salt,
** too short or no header -> access fails, file stays unchanged */
static void t8_short_header(void)
{
  static const size_t sizes[] = { 1, 8, 15, 16, 100 };
  sqlite3* db = 0;
  unsigned char h[16];
  unsigned long long h0, h1;
  long sz0, sz1;
  int rc, keyRc, n = -1;
  size_t i;

  printf("\n== open empty and too short files with a key ==\n");
  snprintf(g_ctx, sizeof(g_ctx), "Part 8: short_header");
  g_wal = 0;
  g_nrows = 100;

  remove_files();
  write_bytes(DBFILE, 0);
  rc = sqlite3_open_v2(DBFILE, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "multipleciphers-faulty");
  CHECK(rc == SQLITE_OK, "empty file opened");
  if (rc == SQLITE_OK)
  {
    set_params(db, "chacha20");
    keyRc = sqlite3_key(db, "k", 1);
    rc = sqlite3_exec(db, "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT); INSERT INTO t VALUES(1,'x')", 0, 0, 0);
    CHECK(keyRc == SQLITE_OK && rc == SQLITE_OK, "empty file + key: new encrypted DB created");
    sqlite3_close(db);
    CHECK(read_header_salt(h) && !is_sqlite_magic(h), "header contains a random salt");
    rc = open_state("chacha20", "k", &db, &n);
    CHECK(rc == SQLITE_OK && n == 1, "reopened and readable without cipher_salt");
    if (db) sqlite3_close(db);

    /* A second new DB with the same key must get a different salt */
    {
      unsigned char h2[16];
      remove_files();
      write_bytes(DBFILE, 0);
      rc = sqlite3_open_v2(DBFILE, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "multipleciphers-faulty");
      if (rc == SQLITE_OK)
      {
        set_params(db, "chacha20");
        keyRc = sqlite3_key(db, "k", 1);
        rc = sqlite3_exec(db, "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT)", 0, 0, 0);
        if (keyRc != SQLITE_OK) rc = keyRc;
      }
      sqlite3_close(db);
      db = 0;
      CHECK(rc == SQLITE_OK && read_header_salt(h2) && memcmp(h, h2, 16) != 0,
            "second empty file + same key: different salt");
    }
  }

  for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
  {
    char msg[96];
    remove_files();
    write_bytes(DBFILE, sizes[i]);
    h0 = file_hash(DBFILE, &sz0);
    rc = open_state("chacha20", "k", &db, &n);
    if (db) sqlite3_close(db);
    h1 = file_hash(DBFILE, &sz1);
    snprintf(msg, sizeof(msg), "file with %u bytes: access fails, file unchanged", (unsigned) sizes[i]);
    CHECK(rc != SQLITE_OK && h0 == h1 && sz0 == sz1, msg);
  }
}

/* I/O error while reading the file header while the key is being set.
** Expectation: no silent success, nothing is damaged, afterwards it works with the correct key. */
static void t8_header_read_error(void)
{
  Scen s = { "hdr-read", "chacha20", "old-key", "chacha20", "new-key", F_NONE, 0, 0 };
  sqlite3* db = 0;
  unsigned long long h0, h1;
  long sz0, sz1;
  int rc, keyRc, qRc, n = -1;

  printf("\n== I/O error while reading the file header ==\n");
  snprintf(g_ctx, sizeof(g_ctx), "Part 8: header_read_error");
  g_wal = 0;
  g_nrows = 500;
  db = setup_db(&s);
  if (!db) return;
  sqlite3_close(db);
  h0 = file_hash(DBFILE, &sz0);

  rc = sqlite3_open_v2(DBFILE, &db, SQLITE_OPEN_READWRITE, "multipleciphers-faulty");
  CHECK(rc == SQLITE_OK, "DB opened");
  if (rc == SQLITE_OK)
  {
    conn_setup(db);
    set_params(db, "chacha20");
    g_faultsHit = 0;
    g_fault = F_READ_HDR;
    keyRc = sqlite3_key(db, "old-key", 7);
    qRc = query_int(db, "SELECT count(*) FROM t", &n);
    g_fault = F_NONE;
    printf("    key rc=%d, query rc=%d (%s), faults triggered: %d\n",
           keyRc, qRc, sqlite3_errmsg(db), g_faultsHit);
    CHECK(g_faultsHit == 1, "read failure at the start of the file was triggered");
    CHECK(keyRc != SQLITE_OK || qRc != SQLITE_OK, "no silent success despite the read failure");
    if (keyRc == SQLITE_OK && qRc == SQLITE_NOTADB)
    {
      printf("    [WARN] header read failure was not reported, NOTADB only later\n");
      g_warnings++;
    }
    sqlite3_close(db);
  }
  h1 = file_hash(DBFILE, &sz1);
  CHECK(h0 == h1 && sz0 == sz1, "file stays unchanged");
  CHECK(state_ok("chacha20", "old-key", g_nrows), "afterwards completely readable with the correct key");
}

static void run_part8(void)
{
  t8_random_salt();
  t8_salt_chain(0, 0);
  t8_salt_chain(0, 1);
  t8_salt_chain(1, 0);
  t8_salt_chain(1, 1);
  t8_plain_with_key();
  t8_short_header();
  t8_header_read_error();
}

/* ------------------------------------------------------------------ */
#ifndef _WIN32
static void on_crash(int sig)
{
  static const char m1[] = "\n*** CRASH in: ";
  (void) sig;
  if (write(2, m1, sizeof(m1) - 1)) {}
  if (write(2, g_ctx, strlen(g_ctx))) {}
  if (write(2, "\n", 1)) {}
  _exit(139);
}
#endif

int main(int argc, char** argv)
{
  size_t i;
  int doOom = 1, doWal = 1, stride = 1, oomAvail = 0;

  for (i = 1; (int) i < argc; i++)
  {
    if (strcmp(argv[i], "--no-oom") == 0)
      doOom = 0;
    else if (strcmp(argv[i], "--no-wal") == 0)
      doWal = 0;
    else if (strcmp(argv[i], "--oom-stride") == 0 && (int) i + 1 < argc)
      stride = atoi(argv[++i]);
  }
  if (stride < 1) stride = 1;

#ifndef _WIN32
  signal(SIGSEGV, on_crash);
  signal(SIGABRT, on_crash);
#endif

  /* the allocator must be set BEFORE SQLite is initialized */
  if (doOom)
  {
    if (sqlite3_config(SQLITE_CONFIG_GETMALLOC, &g_baseMem) == SQLITE_OK
        && sqlite3_config(SQLITE_CONFIG_MALLOC, &g_oomMem) == SQLITE_OK)
    {
      oomAvail = 1;
    }
    else
    {
      printf("SQLITE_CONFIG_MALLOC cannot be set (SQLite already initialized?), OOM parts are skipped\n");
    }
  }

  if (install_vfs() != 0) return 2;

  printf("##### Part 1: commit failures #####\n");
  for (i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++)
    run(&scenarios[i]);

  printf("\n##### Part 2: rekey inside an open transaction #####\n");
  for (i = 0; i < sizeof(txnScenarios) / sizeof(txnScenarios[0]); i++)
    run_in_txn(&txnScenarios[i]);

  printf("\n##### Part 2b: active statement and PRAGMA rekey #####\n");
  for (i = 0; i < sizeof(miscScenarios) / sizeof(miscScenarios[0]); i++)
  {
    run_active_stmt(&miscScenarios[i]);
    run_pragma_rekey(&miscScenarios[i]);
  }

  printf("\n##### Part 7: plaintext_header_size (salt must always be supplied) #####\n");
  run_plainhdr_all(doWal);

  printf("\n##### Part 8: salt management and header reading #####\n");
  run_part8();

  if (oomAvail)
  {
    printf("\n##### Part 3: OOM loop (stride=%d) #####\n", stride);
    for (i = 0; i < sizeof(oomScenarios) / sizeof(oomScenarios[0]); i++)
      run_oom(&oomScenarios[i], stride);
  }

  if (doWal)
  {
    printf("\n##### Part 4: commit failures in WAL mode #####\n");
    g_wal = 1;
    for (i = 0; i < sizeof(walScenarios) / sizeof(walScenarios[0]); i++)
      run(&walScenarios[i]);
    g_wal = 0;

    printf("\n##### Part 5: salt behaviour #####\n");
    run_salt(0, 0);
    run_salt(0, 1);
    run_salt(1, 0);
    run_salt(1, 1);
    run_salt_fail(0);
    run_salt_fail(1);

    if (oomAvail)
    {
      printf("\n##### Part 6: OOM loop in WAL mode (stride=%d) #####\n", stride);
      g_wal = 1;
      for (i = 0; i < sizeof(oomWalScenarios) / sizeof(oomWalScenarios[0]); i++)
        run_oom(&oomWalScenarios[i], stride);
      g_wal = 0;
    }
  }

  remove_files();
  printf("\n%s (%d failures, %d warnings, %d skipped)\n",
         g_failures ? "FAILED" : "ALL TESTS PASSED", g_failures, g_warnings, g_skipped);
  return g_failures ? 1 : 0;
}
