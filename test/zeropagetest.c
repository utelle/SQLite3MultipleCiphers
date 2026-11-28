/*
** Tests for the handling of all-zero pages in the main database file.
**
** A page of the database that was written has a nonce and a MAC, so its raw
** form is never all zero. SQLite, however, reads pages that were never written
** (pages behind the end of the database in a write transaction, for example
** after it moved pages in auto-vacuum mode) and expects zeros. The VFS must
** tell the two cases apart:
**
**   gap      a page that was never written is read as zeros without an error,
**            even if a savepoint or VACUUM wrote page 1 with a larger size
**            than the database had at the start of the transaction.
**            A randomized transaction with savepoints, rollbacks, deletes and
**            auto-vacuum runs for every seed; the fixed seeds failed before
**            (chacha20: 866, 1127, 1299, 1574 with the original sequence).
**   damage   an all-zero page inside the database is an error: when the
**            database is idle, in a write transaction and after the rollback
**            to a savepoint.
**   eof      a page behind the end of the file is never read as zeros, unless
**            the file is empty or it is behind the database size in a write
**            transaction. In WAL mode the main file can be shorter than the
**            database, and a truncated file must not go unnoticed.
**
** The ciphers without MAC (for example aes128cbc) cannot tell a zero page from damage
** and are not tested.
**
** Usage: zeropagetest [seeds] [cipher]
**   seeds   number of seeds for the gap test (default 20)
**   cipher  only this cipher (default: a selection)
*/

#include "sqlite3mc.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

static int zpFailures = 0;

#define CHECK(cond, ...) \
  do { if (!(cond)) { ++zpFailures; printf("    [FAIL] "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int zpExec(sqlite3* db, const char* sql)
{
  char* err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  sqlite3_free(err);
  return rc;
}

static void zpRemoveDb(const char* fn)
{
  char name[128];
  remove(fn);
  snprintf(name, sizeof(name), "%s-journal", fn); remove(name);
  snprintf(name, sizeof(name), "%s-wal", fn); remove(name);
  snprintf(name, sizeof(name), "%s-shm", fn); remove(name);
}

static sqlite3* zpOpenDb(const char* fn, const char* cipher)
{
  sqlite3* db = NULL;
  char sql[128];
  if (sqlite3_open(fn, &db) != SQLITE_OK) return NULL;
  snprintf(sql, sizeof(sql), "PRAGMA cipher='%s'", cipher);
  zpExec(db, sql);
  zpExec(db, "PRAGMA key='zeropagetest'");
  return db;
}

/*
** Gap test: random transactions
*/
static unsigned long long zpRndState;

static unsigned zpRnd(unsigned n)
{
  zpRndState = zpRndState * 6364136223846793005ULL + 1442695040888963407ULL;
  return (unsigned) ((zpRndState >> 33) % n);
}

/* Deterministic replacement for randomblob() */
static void rndBlobFunc(sqlite3_context* ctx, int argc, sqlite3_value** argv)
{
  int len = sqlite3_value_int(argv[0]);
  unsigned char* b;
  int i;
  (void) argc;
  if (len < 1) len = 1;
  b = (unsigned char*) sqlite3_malloc(len);
  if (b == NULL) { sqlite3_result_error_nomem(ctx); return; }
  for (i = 0; i < len; ++i) b[i] = (unsigned char) zpRnd(256);
  sqlite3_result_blob(ctx, b, len, sqlite3_free);
}

static int gapSeed(const char* cipher, int seed, char* msg, int msgSize)
{
  static const int pageSizes[] = { 512, 1024, 4096 };
  const char* fn = "zeropagetest-gap.db";
  sqlite3* db;
  char sql[256];
  int errors = 0, depth = 0, i, av, ps;

  zpRndState = (unsigned long long) seed * 7919ULL;
  zpRemoveDb(fn);
  db = zpOpenDb(fn, cipher);
  if (db == NULL) return 1;
  sqlite3_create_function(db, "rb", 1, SQLITE_UTF8, NULL, rndBlobFunc, NULL, NULL);
  ps = pageSizes[zpRnd(3)];
  av = (int) zpRnd(3);
  msg[0] = 0;

#define RUN(s) do { char* e_ = NULL; int rc_ = sqlite3_exec(db, (s), NULL, NULL, &e_); \
                    if (rc_ != SQLITE_OK) { if (!errors) snprintf(msg, msgSize, "ps=%d av=%d rc=%d %s [%s]", ps, av, rc_, e_ ? e_ : "", (s)); ++errors; } \
                    sqlite3_free(e_); } while (0)
#define RUNR(s, ok) do { char* e_ = NULL; int rc_ = sqlite3_exec(db, (s), NULL, NULL, &e_); \
                    if (rc_ != SQLITE_OK) { if (!errors) snprintf(msg, msgSize, "ps=%d av=%d rc=%d %s [%s]", ps, av, rc_, e_ ? e_ : "", (s)); ++errors; } \
                    else { ok; } sqlite3_free(e_); } while (0)

  snprintf(sql, sizeof(sql), "PRAGMA page_size=%d", ps); RUN(sql);
  snprintf(sql, sizeof(sql), "PRAGMA auto_vacuum=%d", av); RUN(sql);
  snprintf(sql, sizeof(sql), "PRAGMA cache_size=%d", 3 + (int) zpRnd(12)); RUN(sql);
  RUN("CREATE TABLE t1(a INTEGER PRIMARY KEY, b BLOB); CREATE INDEX i1 ON t1(b); CREATE TABLE t2(x,y);");
  RUN("BEGIN");
  for (i = 0; i < 4000 && !errors; ++i)
  {
    int op = (int) zpRnd(100);
    if (op < 35)      { snprintf(sql, sizeof(sql), "INSERT INTO t1(b) VALUES(rb(%u))", zpRnd(2500)); RUN(sql); }
    else if (op < 45) { snprintf(sql, sizeof(sql), "INSERT INTO t2 SELECT rb(30), rb(%u) FROM (SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3)", zpRnd(3000)); RUN(sql); }
    else if (op < 60) { snprintf(sql, sizeof(sql), "DELETE FROM t1 WHERE a IN (SELECT a FROM t1 ORDER BY rb(4) LIMIT %u)", 1 + zpRnd(25)); RUN(sql); }
    else if (op < 65) { snprintf(sql, sizeof(sql), "DELETE FROM t2 WHERE rowid %% %u = 0", 2 + zpRnd(5)); RUN(sql); }
    else if (op < 75) { snprintf(sql, sizeof(sql), "SAVEPOINT s%d", depth); RUNR(sql, ++depth); }
    else if (op < 82 && depth > 0) { int k = (int) zpRnd(depth); snprintf(sql, sizeof(sql), "ROLLBACK TO s%d", k); RUNR(sql, depth = k + 1); }
    else if (op < 88 && depth > 0) { int k = (int) zpRnd(depth); snprintf(sql, sizeof(sql), "RELEASE s%d", k); RUNR(sql, depth = k); }
    else if (op < 92 && av == 2) { snprintf(sql, sizeof(sql), "PRAGMA incremental_vacuum(%u)", 1 + zpRnd(10)); RUN(sql); }
    else if (op < 95) { int t = (int) zpRnd(10); snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS x%d(a,b); INSERT INTO x%d SELECT rb(10),rb(%u) FROM t2 LIMIT 5", t, t, zpRnd(2000)); RUN(sql); }
    else if (op < 98) { snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS x%d", (int) zpRnd(10)); RUN(sql); }
    else RUN("UPDATE t1 SET b=rb(1+a%700) WHERE a%13=0");
  }
  while (depth > 0 && !errors) { snprintf(sql, sizeof(sql), "RELEASE s%d", --depth); RUN(sql); }
  if (!errors) RUN("COMMIT");
#undef RUN
#undef RUNR
  sqlite3_close(db);
  zpRemoveDb(fn);
  return errors;
}

static void testGap(const char* cipher, int firstSeed, int lastSeed)
{
  int seed, bad = 0;
  char msg[400];
  printf("  gap     %-14s seeds %d..%d\n", cipher, firstSeed, lastSeed);
  for (seed = firstSeed; seed <= lastSeed; ++seed)
  {
    if (gapSeed(cipher, seed, msg, sizeof(msg)))
    {
      ++bad;
      CHECK(0, "%s seed %d: %s", cipher, seed, msg);
    }
  }
}

/*
** Damage test: an all-zero page inside the database
*/
static void zpZeroPage(const char* fn, int page, int pageSize)
{
  FILE* f = fopen(fn, "r+b");
  unsigned char* z = (unsigned char*) calloc(1, pageSize);
  if (f != NULL && z != NULL)
  {
    fseek(f, (long) (page - 1) * pageSize, SEEK_SET);
    fwrite(z, 1, pageSize, f);
  }
  if (f != NULL) fclose(f);
  free(z);
}

static long zpFileLength(const char* fn)
{
  long size = -1;
  FILE* f = fopen(fn, "rb");
  if (f != NULL) { fseek(f, 0, SEEK_END); size = ftell(f); fclose(f); }
  return size;
}

static int zpTruncate(const char* fn, long size)
{
#ifdef _WIN32
  FILE* f = fopen(fn, "r+b");
  int rc = (f != NULL) ? _chsize(_fileno(f), size) : -1;
  if (f != NULL) fclose(f);
  return rc;
#else
  return truncate(fn, size);
#endif
}

static const char* fillSql =
  "CREATE TABLE t(a INTEGER PRIMARY KEY, b BLOB);"
  "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<400) "
  "INSERT INTO t SELECT x, zeroblob(500) FROM c";

static void testDamage(const char* cipher)
{
  const char* fn = "zeropagetest-damage.db";
  const int pageSize = 1024;
  sqlite3* db;
  int nPages, rc, scenario;
  printf("  damage  %-14s\n", cipher);

  for (scenario = 0; scenario < 3; ++scenario)
  {
    int page;
    zpRemoveDb(fn);
    db = zpOpenDb(fn, cipher);
    zpExec(db, "PRAGMA page_size=1024");
    zpExec(db, fillSql);
    sqlite3_close(db);
    nPages = (int) (zpFileLength(fn) / pageSize);
    page = (scenario == 2) ? nPages / 3 : nPages / 2;
    zpZeroPage(fn, page, pageSize);

    db = zpOpenDb(fn, cipher);
    if (scenario == 0)
    {
      rc = zpExec(db, "SELECT sum(length(b)) FROM t");
      CHECK(rc != SQLITE_OK, "%s: zeroed page %d not detected when idle", cipher, page);
    }
    else if (scenario == 1)
    {
      zpExec(db, "PRAGMA cache_size=5");
      zpExec(db, "BEGIN IMMEDIATE");
      rc = zpExec(db, "SELECT sum(length(b)) FROM t");
      CHECK(rc != SQLITE_OK, "%s: zeroed page %d not detected in a write transaction", cipher, page);
      zpExec(db, "ROLLBACK");
    }
    else
    {
      /* The transaction grows the database, so page 1 in the file is not the start size */
      zpExec(db, "PRAGMA cache_size=5");
      zpExec(db, "BEGIN");
      zpExec(db, "INSERT INTO t(b) VALUES(zeroblob(30000))");
      zpExec(db, "SAVEPOINT s");
      zpExec(db, "INSERT INTO t(b) VALUES(zeroblob(30000))");
      zpExec(db, "ROLLBACK TO s");
      rc = zpExec(db, "SELECT sum(length(b)) FROM t");
      CHECK(rc != SQLITE_OK, "%s: zeroed page %d not detected after ROLLBACK TO", cipher, page);
      zpExec(db, "ROLLBACK");
    }
    sqlite3_close(db);
  }
  zpRemoveDb(fn);
}

/*
** EOF test: reading behind the end of the main file
*/
static int readBehindEof(sqlite3* db, int pageSize, int nPagesBehind)
{
  sqlite3_file* file = NULL;
  sqlite3_int64 size = 0;
  unsigned char* buf = (unsigned char*) calloc(1, pageSize);
  int rc = sqlite3_file_control(db, "main", SQLITE_FCNTL_FILE_POINTER, &file);
  if (rc == SQLITE_OK && file != NULL && file->pMethods != NULL && buf != NULL)
  {
    rc = file->pMethods->xFileSize(file, &size);
    if (rc == SQLITE_OK)
    {
      memset(buf, 0, pageSize);
      rc = file->pMethods->xRead(file, buf, pageSize, size + (sqlite3_int64) nPagesBehind * pageSize);
    }
  }
  else
  {
    rc = SQLITE_ERROR;
  }
  free(buf);
  return rc;
}

static void testEof(const char* cipher)
{
  const char* fn = "zeropagetest-eof.db";
  const int pageSize = 1024;
  sqlite3* db;
  int rc;
  printf("  eof     %-14s\n", cipher);

  /* New, empty database: page 1 is read behind the end of the empty file */
  zpRemoveDb(fn);
  db = zpOpenDb(fn, cipher);
  rc = zpExec(db, "CREATE TABLE t(a)");
  CHECK(rc == SQLITE_OK, "%s: creating a database failed (rc=%d)", cipher, rc);
  sqlite3_close(db);

  /* Idle database with all pages in the file: a page behind the end is damage */
  zpRemoveDb(fn);
  db = zpOpenDb(fn, cipher);
  zpExec(db, "PRAGMA page_size=1024");
  zpExec(db, fillSql);
  rc = zpExec(db, "SELECT count(*) FROM t");
  CHECK(rc == SQLITE_OK, "%s: query failed (rc=%d)", cipher, rc);
  rc = readBehindEof(db, pageSize, 0);
  CHECK(rc != SQLITE_OK && rc != SQLITE_IOERR_SHORT_READ,
        "%s: page behind the end of the file read without error (rc=%d)", cipher, rc);
  sqlite3_close(db);

  /* WAL mode: the main file is truncated, the WAL holds a newer database size */
  zpRemoveDb(fn);
  db = zpOpenDb(fn, cipher);
  zpExec(db, "PRAGMA page_size=1024");
  zpExec(db, "PRAGMA journal_mode=wal");
  zpExec(db, "PRAGMA wal_autocheckpoint=0");
  zpExec(db, "CREATE TABLE t(a INTEGER PRIMARY KEY, b BLOB);CREATE TABLE u(a INTEGER PRIMARY KEY, b BLOB);"
              "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<40) "
              "INSERT INTO u SELECT x, randomblob(8000) FROM c");
  zpExec(db, "INSERT INTO t SELECT * FROM u");
  zpExec(db, "DELETE FROM u");
  zpExec(db, "PRAGMA wal_checkpoint(TRUNCATE)");
  zpExec(db, "DELETE FROM t");
  zpExec(db, "PRAGMA wal_checkpoint(TRUNCATE)");
  zpExec(db, "INSERT INTO t VALUES(1, zeroblob(10))");
  {
    long size = zpFileLength(fn);
    sqlite3* db2;
    CHECK(size > 0, "%s: no main file", cipher);
    if (size > 0 && zpTruncate(fn, (size / pageSize / 2) * pageSize) == 0)
    {
      db2 = zpOpenDb(fn, cipher);
      rc = zpExec(db2, "SELECT count(*) FROM t");
      CHECK(rc == SQLITE_OK, "%s: query failed (rc=%d)", cipher, rc);
      rc = readBehindEof(db2, pageSize, 0);
      CHECK(rc != SQLITE_OK && rc != SQLITE_IOERR_SHORT_READ,
            "%s: page behind the end of the truncated file read without error (rc=%d)", cipher, rc);
      sqlite3_close(db2);
    }
  }
  sqlite3_close(db);
  zpRemoveDb(fn);
}

int main(int argc, char** argv)
{
  static const char* ciphers[] = { "chacha20", "aes256gcm", "aegis", "ascon128", "sqlcipher" };
  static const int gapSeeds[] = { 866, 1127, 1299, 1574 };
  int nSeeds = (argc > 1) ? atoi(argv[1]) : 20;
  const char* only = (argc > 2) ? argv[2] : NULL;
  size_t i;
  int k;

  sqlite3_initialize();
  for (i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); ++i)
  {
    if (only != NULL && strcmp(only, ciphers[i]) != 0) continue;
    printf("%s\n", ciphers[i]);
    testDamage(ciphers[i]);
    testEof(ciphers[i]);
    /* sqlcipher derives the key with many iterations, so only a few seeds */
    if (strcmp(ciphers[i], "sqlcipher") == 0)
    {
      testGap(ciphers[i], 1, 2);
    }
    else
    {
      testGap(ciphers[i], 1, nSeeds);
      if (strcmp(ciphers[i], "chacha20") == 0)
      {
        for (k = 0; k < (int) (sizeof(gapSeeds) / sizeof(gapSeeds[0])); ++k)
        {
          testGap(ciphers[i], gapSeeds[k], gapSeeds[k]);
        }
      }
    }
  }
  printf("%s: %d failure(s)\n", zpFailures ? "FAILED" : "OK", zpFailures);
  sqlite3_shutdown();
  return zpFailures ? 1 : 0;
}
