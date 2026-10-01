/*
** Test for allocation failures: every allocation made by sqlite3_initialize
** and by sqlite3_open fails in turn. Each call must return SQLITE_OK or
** SQLITE_NOMEM, a sqlite3_initialize retried after a failure must build the
** same cipher tables as a clean start, and a connection that opened must
** carry its cipher configuration.
*/

#include "sqlite3mc.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3_mem_methods realMethods;
static int countdown = -1;  /* the allocation that reaches 0 fails */

static int failNow(void)
{
  return countdown > 0 && --countdown == 0;
}

static void* faultMalloc(int n)
{
  return failNow() ? 0 : realMethods.xMalloc(n);
}

static void* faultRealloc(void* p, int n)
{
  return failNow() ? 0 : realMethods.xRealloc(p, n);
}

static void installFaultMethods(void)
{
  sqlite3_mem_methods methods = realMethods;
  methods.xMalloc = faultMalloc;
  methods.xRealloc = faultRealloc;
  sqlite3_config(SQLITE_CONFIG_MALLOC, &methods);
}

static char* fingerprint(void)
{
  int j, k;
  sqlite3_str* str = sqlite3_str_new(NULL);
  sqlite3_str_appendf(str, "%d ciphers", globalCipherCount);
  for (j = 0; globalCodecParameterTable[j].m_name[0] != 0; ++j)
  {
    CipherParams* params = globalCodecParameterTable[j].m_params;
    sqlite3_str_appendf(str, "; %s:", globalCodecParameterTable[j].m_name);
    for (k = 0; params[k].m_name[0] != 0; ++k)
    {
      sqlite3_str_appendf(str, " %s=%d/%d", params[k].m_name, params[k].m_value, params[k].m_default);
    }
  }
  return sqlite3_str_finish(str);
}

static int unexpectedResult(const char* call, int nth, int rc)
{
  if (rc == SQLITE_OK || rc == SQLITE_NOMEM) return 0;
  printf("%s, allocation %d failed: returned %d\n", call, nth, rc);
  return 1;
}

int main(void)
{
  char* baseline;
  char* expected;
  int nth;
  int reached;
  int rc;
  int nInit;
  int nOpen;
  int failures = 0;

  sqlite3_config(SQLITE_CONFIG_GETMALLOC, &realMethods);
  installFaultMethods();
  if (sqlite3_initialize() != SQLITE_OK) return 1;
  baseline = fingerprint();
  if (baseline == NULL) return 1;
  /* SQLite must not hold allocations across the sqlite3_shutdown calls below */
  expected = (char*) malloc(strlen(baseline) + 1);
  if (expected == NULL) return 1;
  strcpy(expected, baseline);
  sqlite3_free(baseline);

  for (nth = 1;; ++nth)
  {
    char* actual;
    sqlite3_shutdown();
    installFaultMethods();
    countdown = nth;
    rc = sqlite3_initialize();
    reached = countdown == 0;
    countdown = -1;
    if (!reached) break;
    failures += unexpectedResult("sqlite3_initialize", nth, rc);
    if (rc != SQLITE_OK && sqlite3_initialize() != SQLITE_OK)
    {
      printf("sqlite3_initialize, allocation %d failed: retry failed\n", nth);
      ++failures;
      continue;
    }
    actual = fingerprint();
    if (actual == NULL || strcmp(actual, expected) != 0)
    {
      printf("sqlite3_initialize, allocation %d failed: cipher tables differ\n  expected %s\n  actual   %s\n",
             nth, expected, actual ? actual : "(out of memory)");
      ++failures;
    }
    sqlite3_free(actual);
  }
  /* The last sqlite3_initialize succeeded, so the library stays initialized for the next loop */
  nInit = nth - 1;

  for (nth = 1;; ++nth)
  {
    sqlite3* db = 0;
    countdown = nth;
    rc = sqlite3_open(":memory:", &db);
    reached = countdown == 0;
    countdown = -1;
    failures += unexpectedResult("sqlite3_open", nth, rc);
    if (rc == SQLITE_OK && sqlite3mc_config(db, "cipher", -1) != sqlite3mc_config(NULL, "cipher", -1))
    {
      printf("sqlite3_open, allocation %d failed: connection has no cipher configuration\n", nth);
      ++failures;
    }
    sqlite3_close(db);
    if (!reached) break;
  }
  nOpen = nth - 1;

  sqlite3_shutdown();
  free(expected);
  printf("%d allocations in sqlite3_initialize and %d in sqlite3_open failed in turn, %d failures\n",
         nInit, nOpen, failures);
  return failures != 0;
}
