/*
** Tests for the use from several threads:
**
** 1. A large ORDER BY or CREATE INDEX lets the sorter hand parts of its work
**    to worker threads (PRAGMA threads). The worker threads open temporary
**    files of their own while the thread running the statement holds the
**    connection mutex. Opening them must not wait for that mutex, and for an
**    encrypted database the files must be encrypted. The table needs enough
**    rows, otherwise the sorter keeps everything in memory.
** 2. sqlite3_backup_init must release both connection mutexes in every case,
**    also if it refuses the backup because the source and destination
**    databases do not match.
**
** A VFS below the SQLite3 Multiple Ciphers VFS sees every write that reaches
** the disk. It counts the sorter's temporary files, the ones opened by a
** worker thread, and the writes that contain a marker text from the rows.
** A statement that does not finish within a minute counts as a deadlock.
**
** Usage: threadtest [rows]
*/

#include "sqlite3mc.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <pthread.h>
#endif

#define DBFILE "threadtest.db"
#define SRCFILE "threadtest-src.db"
#define DESTFILE "threadtest-dest.db"
#define MARKER "PLAINTEXTMARKER"
#define TIMEOUT_SECONDS 60

static int failures;

#define CHECK(cond, msg) do { \
  if (cond) printf("  [ok]   %s\n", msg); \
  else { printf("  [FAIL] %s\n", msg); failures++; } \
} while (0)

#if SQLITE_MAX_WORKER_THREADS > 0

#ifdef _WIN32
typedef DWORD ThreadId;
static ThreadId currentThread(void) { return GetCurrentThreadId(); }
static int sameThread(ThreadId a, ThreadId b) { return a == b; }
#else
typedef pthread_t ThreadId;
static ThreadId currentThread(void) { return pthread_self(); }
static int sameThread(ThreadId a, ThreadId b) { return pthread_equal(a, b); }
#endif

static ThreadId mainThread;

/*
** The VFS below the one under test
*/
static sqlite3_vfs* realVfs;
static sqlite3_vfs spyVfs;
static sqlite3_mutex* spyMutex;
static int nTempOpen, nTempOpenWorker, nTempWrite, nTempMarker;

typedef struct SpyFile { sqlite3_file base; int flags; sqlite3_file* real; } SpyFile;
#define REAL(f) (((SpyFile*) (f))->real)

static int hasMarker(const void* b, int n)
{
  const char* p = (const char*) b;
  int m = (int) strlen(MARKER), i;
  for (i = 0; i + m <= n; i++) if (p[i] == MARKER[0] && memcmp(p + i, MARKER, m) == 0) return 1;
  return 0;
}

static int spyClose(sqlite3_file* f) { return REAL(f)->pMethods ? REAL(f)->pMethods->xClose(REAL(f)) : SQLITE_OK; }
static int spyRead(sqlite3_file* f, void* b, int n, sqlite3_int64 o) { return REAL(f)->pMethods->xRead(REAL(f), b, n, o); }
static int spyWrite(sqlite3_file* f, const void* b, int n, sqlite3_int64 o)
{
  if (((SpyFile*) f)->flags & SQLITE_OPEN_TEMP_JOURNAL)
  {
    int marker = hasMarker(b, n);
    sqlite3_mutex_enter(spyMutex);
    nTempWrite++;
    if (marker) nTempMarker++;
    sqlite3_mutex_leave(spyMutex);
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
  p->flags = flags;
  if (flags & SQLITE_OPEN_TEMP_JOURNAL)
  {
    int worker = !sameThread(currentThread(), mainThread);
    sqlite3_mutex_enter(spyMutex);
    nTempOpen++;
    if (worker) nTempOpenWorker++;
    sqlite3_mutex_leave(spyMutex);
  }
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

static int installSpy(void)
{
#ifdef _WIN32
  realVfs = sqlite3_vfs_find("win32");
#else
  realVfs = sqlite3_vfs_find("unix");
#endif
  spyMutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
  if (realVfs == NULL || spyMutex == NULL) return SQLITE_ERROR;
  memset(&spyVfs, 0, sizeof(spyVfs));
  spyVfs.iVersion = 1; spyVfs.szOsFile = (int) sizeof(SpyFile) + realVfs->szOsFile; spyVfs.mxPathname = realVfs->mxPathname;
  spyVfs.zName = "spy"; spyVfs.xOpen = spyOpen; spyVfs.xDelete = spyDelete; spyVfs.xAccess = spyAccess;
  spyVfs.xFullPathname = spyFullPath; spyVfs.xRandomness = spyRandomness; spyVfs.xSleep = spySleep;
  spyVfs.xCurrentTime = spyCurrentTime; spyVfs.xGetLastError = spyLastError;
  sqlite3_vfs_register(&spyVfs, 0);
  return sqlite3mc_vfs_create("spy", 1);
}

static void resetSpy(void)
{
  sqlite3_mutex_enter(spyMutex);
  nTempOpen = nTempOpenWorker = nTempWrite = nTempMarker = 0;
  sqlite3_mutex_leave(spyMutex);
}

/*
** A statement that does not finish in time ends the test
*/
static SQLiteThread* watchdogThread;
static const char* watchdogLabel;
static int watchdogStop;

static void* watchdog(void* arg)
{
  int ticks = 0, stop = 0;
  (void) arg;
  while (!stop)
  {
    sqlite3_mutex_enter(spyMutex);
    stop = watchdogStop;
    sqlite3_mutex_leave(spyMutex);
    if (!stop && ++ticks > TIMEOUT_SECONDS * 10)
    {
      printf("  [FAIL] %s did not finish within %d seconds (deadlock?)\nFAILED\n", watchdogLabel, TIMEOUT_SECONDS);
      fflush(stdout);
      exit(1);
    }
    sqlite3_sleep(100);
  }
  return NULL;
}

static void startWatchdog(const char* label)
{
  watchdogLabel = label;
  watchdogStop = 0;
  if (sqlite3ThreadCreate(&watchdogThread, watchdog, NULL) != SQLITE_OK) watchdogThread = NULL;
}

static void stopWatchdog(void)
{
  void* out;
  sqlite3_mutex_enter(spyMutex);
  watchdogStop = 1;
  sqlite3_mutex_leave(spyMutex);
  if (watchdogThread) sqlite3ThreadJoin(watchdogThread, &out);
  watchdogThread = NULL;
}

static void removeFiles(const char* name)
{
  char buf[100];
  remove(name);
  snprintf(buf, sizeof(buf), "%s-journal", name);
  remove(buf);
}

static int exec(sqlite3* db, const char* sql)
{
  char* err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) printf("  error %d (%s) in: %.70s\n", rc, err ? err : "", sql);
  sqlite3_free(err);
  return rc;
}

static void checkTempFiles(int encrypted)
{
  char msg[100];
  snprintf(msg, sizeof(msg), "worker threads opened temporary files (%d of %d)", nTempOpenWorker, nTempOpen);
  CHECK(nTempOpenWorker > 0, msg);
  if (encrypted)
  {
#if SQLITE3MC_ENCRYPT_TEMP_FILES
    snprintf(msg, sizeof(msg), "no plaintext in the temporary files (%d writes)", nTempWrite);
    CHECK(nTempWrite > 0 && nTempMarker == 0, msg);
#endif
  }
  else
  {
    snprintf(msg, sizeof(msg), "rows of a plaintext database are visible in the temporary files (%d of %d writes)", nTempMarker, nTempWrite);
    CHECK(nTempMarker > 0, msg);
  }
}

/*
** Sort the rows of a table with worker threads, and build an index on them
*/
static void sorterTest(int encrypted, int rows)
{
  sqlite3* db = NULL;
  sqlite3_stmt* stmt = NULL;
  char sql[300], prev[200] = "";
  int rc, n = 0, sorted = 1, threads = 0;

  printf("\n== sorter with worker threads, %s database, %d rows ==\n", encrypted ? "encrypted" : "plaintext", rows);
  removeFiles(DBFILE);
  rc = sqlite3_open(DBFILE, &db);
  if (rc == SQLITE_OK && encrypted) rc = sqlite3_key(db, "threadtest", 10);
  if (rc == SQLITE_OK)
  {
    snprintf(sql, sizeof(sql), "CREATE TABLE t(a, b);"
             "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < %d) "
             "INSERT INTO t SELECT random(), '" MARKER "' || hex(randomblob(50)) FROM c;", rows);
    rc = exec(db, sql);
  }
  if (rc == SQLITE_OK) rc = exec(db, "PRAGMA temp_store = FILE; PRAGMA cache_size = 10; PRAGMA threads = 4;");
  if (rc == SQLITE_OK && sqlite3_prepare_v2(db, "PRAGMA threads", -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW)
    threads = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);
  stmt = NULL;
  CHECK(rc == SQLITE_OK && threads > 0, "database filled, worker threads allowed");
  if (rc != SQLITE_OK || threads == 0) { sqlite3_close(db); return; }

  resetSpy();
  startWatchdog("ORDER BY");
  rc = sqlite3_prepare_v2(db, "SELECT b FROM t ORDER BY b", -1, &stmt, NULL);
  if (rc == SQLITE_OK)
  {
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
      const char* b = (const char*) sqlite3_column_text(stmt, 0);
      if (b == NULL || strlen(b) >= sizeof(prev) || strcmp(prev, b) > 0) sorted = 0;
      else strcpy(prev, b);
      n++;
    }
  }
  sqlite3_finalize(stmt);
  stopWatchdog();
  CHECK(rc == SQLITE_DONE && n == rows && sorted, "ORDER BY returns all rows in order");
  checkTempFiles(encrypted);

  resetSpy();
  startWatchdog("CREATE INDEX");
  rc = exec(db, "CREATE INDEX tb ON t(b)");
  stopWatchdog();
  CHECK(rc == SQLITE_OK, "CREATE INDEX succeeds");
  checkTempFiles(encrypted);
  stmt = NULL;
  rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, NULL);
  if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
  CHECK(rc == SQLITE_ROW && sqlite3_column_text(stmt, 0) != NULL &&
        strcmp((const char*) sqlite3_column_text(stmt, 0), "ok") == 0, "integrity check of the new index");
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  removeFiles(DBFILE);
}

/*
** Can another thread take the mutexes of both connections?
*/
static sqlite3* lockDb[2];
static int lockFree[2];
static ThreadId lockThread;

static void* tryLocks(void* arg)
{
  int i;
  (void) arg;
  lockThread = currentThread();
  for (i = 0; i < 2; i++)
  {
    sqlite3_mutex* mutex = sqlite3_db_mutex(lockDb[i]);
    lockFree[i] = mutex == NULL || sqlite3_mutex_try(mutex) == SQLITE_OK;
    if (mutex != NULL && lockFree[i]) sqlite3_mutex_leave(mutex);
  }
  return NULL;
}

static void checkLocksFree(sqlite3* src, sqlite3* dest)
{
  SQLiteThread* thread;
  void* out;
  lockDb[0] = src;
  lockDb[1] = dest;
  lockFree[0] = lockFree[1] = 0;
  lockThread = mainThread;
  if (sqlite3ThreadCreate(&thread, tryLocks, NULL) != SQLITE_OK) { CHECK(0, "second thread started"); return; }
  sqlite3ThreadJoin(thread, &out);
  if (sameThread(lockThread, mainThread))
  {
    printf("  no second thread available, mutexes not checked\n");
    return;
  }
  CHECK(lockFree[0], "another thread can use the source connection");
  CHECK(lockFree[1], "another thread can use the destination connection");
}

static void backupTest(const char* label, const char* srcKey, const char* destKey, int supported)
{
  sqlite3* src = NULL;
  sqlite3* dest = NULL;
  sqlite3_backup* backup;
  sqlite3_stmt* stmt;
  int rc;

  printf("\n== backup, %s ==\n", label);
  removeFiles(SRCFILE);
  removeFiles(DESTFILE);
  rc = sqlite3_open(SRCFILE, &src);
  if (rc == SQLITE_OK && srcKey) rc = sqlite3_key(src, srcKey, (int) strlen(srcKey));
  if (rc == SQLITE_OK) rc = exec(src, "CREATE TABLE t(a); INSERT INTO t VALUES (1), (2), (3);");
  if (rc == SQLITE_OK) rc = sqlite3_open(DESTFILE, &dest);
  if (rc == SQLITE_OK && destKey) rc = sqlite3_key(dest, destKey, (int) strlen(destKey));
  if (rc == SQLITE_OK) rc = exec(dest, "CREATE TABLE d(a);");
  CHECK(rc == SQLITE_OK, "databases created");
  if (rc != SQLITE_OK) { sqlite3_close(dest); sqlite3_close(src); return; }

  backup = sqlite3_backup_init(dest, "main", src, "main");
  if (supported)
  {
    CHECK(backup != NULL, "sqlite3_backup_init returns a handle");
    if (backup != NULL)
    {
      CHECK(sqlite3_backup_step(backup, -1) == SQLITE_DONE, "sqlite3_backup_step copies all pages");
      CHECK(sqlite3_backup_finish(backup) == SQLITE_OK, "sqlite3_backup_finish succeeds");
      stmt = NULL;
      rc = sqlite3_prepare_v2(dest, "SELECT count(*) FROM t", -1, &stmt, NULL);
      if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
      CHECK(rc == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 3, "the destination holds the rows of the source");
      sqlite3_finalize(stmt);
    }
  }
  else
  {
    CHECK(backup == NULL && sqlite3_errcode(dest) == SQLITE_ERROR, "sqlite3_backup_init refuses the backup");
    if (backup != NULL) sqlite3_backup_finish(backup);
  }
  checkLocksFree(src, dest);
  sqlite3_close(dest);
  sqlite3_close(src);
  removeFiles(SRCFILE);
  removeFiles(DESTFILE);
}

int main(int argc, char** argv)
{
  int rows = argc > 1 ? atoi(argv[1]) : 100000;

  sqlite3_initialize();
  if (!sqlite3_threadsafe())
  {
    printf("built without thread support, nothing to test\n");
    return 0;
  }
  mainThread = currentThread();
  if (installSpy() != SQLITE_OK) { printf("VFS setup failed\nFAILED\n"); return 1; }

  sorterTest(1, rows);
  sorterTest(0, rows);

  backupTest("both encrypted", "source key", "destination key", 1);
  backupTest("both plaintext", NULL, NULL, 1);
  backupTest("encrypted source, plaintext destination", "source key", NULL, 0);
  backupTest("plaintext source, encrypted destination", NULL, "destination key", 0);

  printf(failures ? "\nFAILED: %d failure(s)\n" : "\nOK: %d failure(s)\n", failures);
  return failures != 0;
}

#else

int main(void)
{
  printf("built without worker threads, nothing to test\n");
  return 0;
}

#endif
