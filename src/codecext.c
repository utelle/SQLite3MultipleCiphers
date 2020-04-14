/*
** Name:        codecext.c
** Purpose:     Implementation of SQLite codec API
** Author:      Ulrich Telle
** Created:     2006-12-06
** Copyright:   (c) 2006-2020 Ulrich Telle
** License:     MIT
*/

/*
** Prototypes for codec functions
*/
SQLITE_PRIVATE int sqlite3mcCodecAttach(sqlite3* db, int nDb, const void* zKey, int nKey);
SQLITE_PRIVATE void sqlite3mcCodecGetKey(sqlite3* db, int nDb, void** zKey, int* nKey);

/*
** Include a "special" version of the VACUUM command
*/
#include "rekeyvacuum.c"

#include "cipher_common.h"

SQLITE_API void
sqlite3_activate_see(const char *info)
{
}

/*
** Free the encryption data structure associated with a pager instance.
** (called from the modified code in pager.c) 
*/
SQLITE_PRIVATE void
sqlite3mcCodecFree(void *pCodecArg)
{
  if (pCodecArg)
  {
    sqlite3mcCodecTerm(pCodecArg);
    sqlite3_free(pCodecArg);
    pCodecArg = NULL;
  }
}

SQLITE_PRIVATE void
sqlite3mcCodecSizeChange(void *pArg, int pageSize, int reservedSize)
{
  Codec* pCodec = (Codec*) pArg;
  pCodec->m_pageSize = pageSize;
  pCodec->m_reserved = reservedSize;
}

static void
mcReportCodecError(BtShared* pBt, int error)
{
  pBt->pPager->errCode = error;
  setGetterMethod(pBt->pPager);
  pBt->db->errCode = error;
}

/*
// Encrypt/Decrypt functionality, called by pager.c
*/
SQLITE_PRIVATE void*
sqlite3mcCodec(void* pCodecArg, void* data, Pgno nPageNum, int nMode)
{
  int rc = SQLITE_OK;
  Codec* codec = NULL;
  int pageSize;
  if (pCodecArg == NULL)
  {
    return data;
  }
  codec = (Codec*) pCodecArg;
  if (!sqlite3mcIsEncrypted(codec))
  {
    return data;
  }

  pageSize = sqlite3mcGetPageSize(codec);

  switch(nMode)
  {
    case 0: /* Undo a "case 7" journal file encryption */
    case 2: /* Reload a page */
    case 3: /* Load a page */
      if (sqlite3mcHasReadCipher(codec))
      {
        rc = sqlite3mcDecrypt(codec, nPageNum, (unsigned char*) data, pageSize);
        if (rc != SQLITE_OK) mcReportCodecError(sqlite3mcGetBtShared(codec), rc);
      }
      break;

    case 6: /* Encrypt a page for the main database file */
      if (sqlite3mcHasWriteCipher(codec))
      {
        unsigned char* pageBuffer = sqlite3mcGetPageBuffer(codec);
        memcpy(pageBuffer, data, pageSize);
        data = pageBuffer;
        rc = sqlite3mcEncrypt(codec, nPageNum, (unsigned char*) data, pageSize, 1);
        if (rc != SQLITE_OK) mcReportCodecError(sqlite3mcGetBtShared(codec), rc);
      }
      break;

    case 7: /* Encrypt a page for the journal file */
      /* Under normal circumstances, the readkey is the same as the writekey.  However,
         when the database is being rekeyed, the readkey is not the same as the writekey.
         The rollback journal must be written using the original key for the
         database file because it is, by nature, a rollback journal.
         Therefore, for case 7, when the rollback is being written, always encrypt using
         the database's readkey, which is guaranteed to be the same key that was used to
         read the original data.
      */
      if (sqlite3mcHasReadCipher(codec))
      {
        unsigned char* pageBuffer = sqlite3mcGetPageBuffer(codec);
        memcpy(pageBuffer, data, pageSize);
        data = pageBuffer;
        rc = sqlite3mcEncrypt(codec, nPageNum, (unsigned char*) data, pageSize, 0);
        if (rc != SQLITE_OK) mcReportCodecError(sqlite3mcGetBtShared(codec), rc);
      }
      break;
  }
  return data;
}

SQLITE_PRIVATE Codec*
sqlite3mcGetMainCodec(sqlite3* db);

SQLITE_PRIVATE void
sqlite3mcSetCodec(sqlite3* db, int dbIndex, Codec* codec);

static int
mcAdjustBtree(Btree* pBt, int nPageSize, int nReserved, int isLegacy)
{
  int rc = SQLITE_OK;
  Pager* pager = sqlite3BtreePager(pBt);
  int pagesize = sqlite3BtreeGetPageSize(pBt);
  sqlite3BtreeSecureDelete(pBt, 1);
  if (nPageSize > 0)
  {
    pagesize = nPageSize;
  }

  /* Adjust the page size and the reserved area */
  if (pager->nReserve != nReserved)
  {
    if (isLegacy != 0)
    {
      pBt->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED;
    }
    rc = sqlite3BtreeSetPageSize(pBt, pagesize, nReserved, 0);
  }
  return rc;
}

static int
sqlite3mcCodecAttach(sqlite3* db, int nDb, const void* zKey, int nKey)
{
  /* Attach a key to a database. */
  Codec* codec = (Codec*) sqlite3_malloc(sizeof(Codec));
  int rc = (codec != NULL) ? sqlite3mcCodecInit(codec) : SQLITE_NOMEM;
  if (rc != SQLITE_OK)
  {
    /* Unable to allocate memory for the codec base structure */
    return rc;
  }

  sqlite3_mutex_enter(db->mutex);
  sqlite3mcSetDb(codec, db);

  /* No key specified, could mean either use the main db's encryption or no encryption */
  if (zKey == NULL || nKey <= 0)
  {
    /* No key specified */
    if (nDb != 0 && nKey > 0)
    {
      /* Main database possibly encrypted, no key explicitly given for attached database */
      Codec* mainCodec = sqlite3mcGetMainCodec(db);
      /* Attached database, therefore use the key of main database, if main database is encrypted */
      if (mainCodec != NULL && sqlite3mcIsEncrypted(mainCodec))
      {
        rc = sqlite3mcCodecCopy(codec, mainCodec);
        if (rc == SQLITE_OK)
        {
          int pageSize = sqlite3mcGetPageSizeWriteCipher(codec);
          int reserved = sqlite3mcGetReservedWriteCipher(codec);
          sqlite3mcSetBtree(codec, db->aDb[nDb].pBt);
          mcAdjustBtree(db->aDb[nDb].pBt, pageSize, reserved, sqlite3mcGetLegacyWriteCipher(codec));
          sqlite3mcCodecSizeChange(codec, pageSize, reserved);
          sqlite3mcSetCodec(db, nDb, codec);
        }
        else
        {
          /* Replicating main codec failed, do not attach incomplete codec */
          sqlite3mcCodecFree(codec);
        }
      }
      else
      {
        /* Main database not encrypted */
        sqlite3mcCodecFree(codec);
      }
    }
    else
    {
      /* Main database not encrypted, no key given for attached database */
      sqlite3mcCodecFree(codec);
    }
  }
  else
  {
#if (SQLITE_VERSION_NUMBER >= 3015000)
    const char* zDbName = db->aDb[nDb].zDbSName;
#else
    const char* zDbName = db->aDb[nDb].zName;
#endif
    const char* dbFileName = sqlite3_db_filename(db, zDbName);
    if (dbFileName != NULL)
    {
      /* Check whether key salt is provided in URI */
      const unsigned char* cipherSalt = (const unsigned char*)sqlite3_uri_parameter(dbFileName, "cipher_salt");
      if ((cipherSalt != NULL) && (strlen((const char*)cipherSalt) >= 2 * KEYSALT_LENGTH) && sqlite3mcIsHexKey(cipherSalt, 2 * KEYSALT_LENGTH))
      {
        codec->m_hasKeySalt = 1;
        sqlite3mcConvertHex2Bin(cipherSalt, 2 * KEYSALT_LENGTH, codec->m_keySalt);
      }
    }

    /* Configure cipher from URI in case of attached database */
    if (nDb > 0)
    {
      rc = sqlite3mcConfigureFromUri(db, dbFileName, 0);
    }
    if (rc == SQLITE_OK)
    {
      /* Key specified, setup encryption key for database */
      sqlite3mcSetBtree(codec, db->aDb[nDb].pBt);
      rc = sqlite3mcCodecSetup(codec, sqlite3mcGetCipherType(db), (char*) zKey, nKey);
      sqlite3mcClearKeySalt(codec);
    }
    if (rc == SQLITE_OK)
    {
      int pageSize = sqlite3mcGetPageSizeWriteCipher(codec);
      int reserved = sqlite3mcGetReservedWriteCipher(codec);
      mcAdjustBtree(db->aDb[nDb].pBt, pageSize, reserved, sqlite3mcGetLegacyWriteCipher(codec));
      sqlite3mcCodecSizeChange(codec, pageSize, reserved);
      sqlite3mcSetCodec(db, nDb, codec);
    }
    else
    {
      /* Setting up codec failed, do not attach incomplete codec */
      sqlite3mcCodecFree(codec);
    }
  }

  sqlite3_mutex_leave(db->mutex);

  return rc;
}

SQLITE_PRIVATE void
sqlite3mcCodecGetKey(sqlite3* db, int nDb, void** zKey, int* nKey)
{
  /*
  ** The unencrypted password is not stored for security reasons
  ** therefore always return NULL
  ** If the main database is encrypted a key length of 1 is returned.
  ** In that case an attached database will get the same encryption key
  ** as the main database if no key was explicitly given for the attached database.
  */
  Codec* mainCodec = sqlite3mcGetMainCodec(db);
  int keylen = (mainCodec != NULL && sqlite3mcIsEncrypted(mainCodec)) ? 1 : 0;
  *zKey = NULL;
  *nKey = keylen;
}

SQLITE_API int
sqlite3_key(sqlite3 *db, const void *zKey, int nKey)
{
  /* The key is only set for the main database, not the temp database  */
  return sqlite3_key_v2(db, "main", zKey, nKey);
}

SQLITE_API int
sqlite3_key_v2(sqlite3 *db, const char *zDbName, const void *zKey, int nKey)
{
  int rc = SQLITE_ERROR;
  if (zKey != NULL && nKey < 0)
  {
    /* Key is zero-terminated string */
    nKey = sqlite3Strlen30(zKey);
  }
  if ((db != NULL) && (zKey != NULL) && (nKey > 0))
  {
    int dbIndex;
    /* Configure cipher from URI parameters if requested */
    if (sqlite3FindFunction(db, "sqlite3mc_config_table", 0, SQLITE_UTF8, 0) == NULL)
    {
      /*
      ** Encryption extension of database connection not yet initialized;
      ** that is, sqlite3_key_v2 was called from the internal open function.
      ** Therefore the URI should be checked for encryption configuration parameters.
      */
      const char* dbFileName = sqlite3_db_filename(db, zDbName);
      rc = sqlite3mcConfigureFromUri(db, dbFileName, 0);
    }

    /* The key is only set for the main database, not the temp database  */
    dbIndex = sqlite3FindDbName(db, zDbName);
    if (dbIndex >= 0)
    {
      rc = sqlite3mcCodecAttach(db, dbIndex, zKey, nKey);
    }
    else
    {
      rc = SQLITE_ERROR;
    }
  }
  return rc;
}

SQLITE_API int
sqlite3_rekey_v2(sqlite3 *db, const char *zDbName, const void *zKey, int nKey)
{
  /* Changes the encryption key for an existing database. */
  int rc = SQLITE_ERROR;
  int dbIndex = sqlite3FindDbName(db, zDbName);
  if (dbIndex < 0)
  {
    return rc;
  }
  Btree* pBt = db->aDb[dbIndex].pBt;
  int nPagesize = sqlite3BtreeGetPageSize(pBt);
  int nReserved;
  Pager* pPager;
  Codec* codec;

  sqlite3BtreeEnter(pBt);
  nReserved = sqlite3BtreeGetReserveNoMutex(pBt);
  sqlite3BtreeLeave(pBt);

  pPager = sqlite3BtreePager(pBt);
  codec = sqlite3mcGetCodec(db, dbIndex);

  if ((zKey == NULL || nKey == 0) && (codec == NULL || !sqlite3mcIsEncrypted(codec)))
  {
    /* Database not encrypted and key not specified, therefore do nothing	*/
    return SQLITE_OK;
  }

  sqlite3_mutex_enter(db->mutex);

  if (codec == NULL || !sqlite3mcIsEncrypted(codec))
  {
    /* Database not encrypted, but key specified, therefore encrypt database	*/
    if (codec == NULL)
    {
      codec = (Codec*) sqlite3_malloc(sizeof(Codec));
      rc = (codec != NULL) ? sqlite3mcCodecInit(codec) : SQLITE_NOMEM;
    }
    if (rc == SQLITE_OK)
    {
      sqlite3mcSetDb(codec, db);
      sqlite3mcSetBtree(codec, pBt);
      rc = sqlite3mcSetupWriteCipher(codec, sqlite3mcGetCipherType(db), (char*) zKey, nKey);
    }
    if (rc == SQLITE_OK)
    {
      int nPagesizeWriteCipher = sqlite3mcGetPageSizeWriteCipher(codec);
      if (nPagesizeWriteCipher <= 0 || nPagesize == nPagesizeWriteCipher)
      {
        int nReservedWriteCipher;
        sqlite3mcSetHasReadCipher(codec, 0); /* Original database is not encrypted */
        mcAdjustBtree(pBt, sqlite3mcGetPageSizeWriteCipher(codec), sqlite3mcGetReservedWriteCipher(codec), sqlite3mcGetLegacyWriteCipher(codec));
        sqlite3mcSetCodec(db, dbIndex, codec);
        nReservedWriteCipher = sqlite3mcGetReservedWriteCipher(codec);
        sqlite3mcCodecSizeChange(codec, nPagesize, nReservedWriteCipher);
        if (nReserved != nReservedWriteCipher)
        {
          /* Use VACUUM to change the number of reserved bytes */
          char* err = NULL;
          sqlite3mcSetReadReserved(codec, nReserved);
          sqlite3mcSetWriteReserved(codec, nReservedWriteCipher);
#if (SQLITE_VERSION_NUMBER >= 3027000)
          rc = sqlite3mcRunVacuumForRekey(&err, db, dbIndex, NULL, nReservedWriteCipher);
#else
          rc = sqlite3mcRunVacuumForRekey(&err, db, dbIndex, nReservedWriteCipher);
#endif
          goto leave_rekey;
        }
      }
      else
      {
        /* Pagesize cannot be changed for an encrypted database */
        rc = SQLITE_ERROR;
        goto leave_rekey;
      }
    }
    else
    {
      return rc;
    }
  }
  else if (zKey == NULL || nKey == 0)
  {
    /* Database encrypted, but key not specified, therefore decrypt database */
    /* Keep read key, drop write key */
    sqlite3mcSetHasWriteCipher(codec, 0);
    if (nReserved > 0)
    {
      /* Use VACUUM to change the number of reserved bytes */
      char* err = NULL;
      sqlite3mcSetReadReserved(codec, nReserved);
      sqlite3mcSetWriteReserved(codec, 0);
#if (SQLITE_VERSION_NUMBER >= 3027000)
      rc = sqlite3mcRunVacuumForRekey(&err, db, dbIndex, NULL, 0);
#else
      rc = sqlite3mcRunVacuumForRekey(&err, db, dbIndex, 0);
#endif
      goto leave_rekey;
    }
  }
  else
  {
    /* Database encrypted and key specified, therefore re-encrypt database with new key */
    /* Keep read key, change write key to new key */
    rc = sqlite3mcSetupWriteCipher(codec, sqlite3mcGetCipherType(db), (char*) zKey, nKey);
    if (rc == SQLITE_OK)
    {
      int nPagesizeWriteCipher = sqlite3mcGetPageSizeWriteCipher(codec);
      if (nPagesizeWriteCipher <= 0 || nPagesize == nPagesizeWriteCipher)
      {
        int nReservedWriteCipher = sqlite3mcGetReservedWriteCipher(codec);
        if (nReserved != nReservedWriteCipher)
        {
          /* Use VACUUM to change the number of reserved bytes */
          char* err = NULL;
          sqlite3mcSetReadReserved(codec, nReserved);
          sqlite3mcSetWriteReserved(codec, nReservedWriteCipher);
#if (SQLITE_VERSION_NUMBER >= 3027000)
          rc = sqlite3mcRunVacuumForRekey(&err, db, dbIndex, NULL, nReservedWriteCipher);
#else
          rc = sqlite3mcRunVacuumForRekey(&err, db, dbIndex, nReservedWriteCipher);
#endif
          goto leave_rekey;
        }
      }
      else
      {
        /* Pagesize cannot be changed for an encrypted database */
        rc = SQLITE_ERROR;
        goto leave_rekey;
      }
    }
    else
    {
      /* Setup of write cipher failed */
      goto leave_rekey;
    }
  }

  /* Start transaction */
#if (SQLITE_VERSION_NUMBER >= 3025000)
  rc = sqlite3BtreeBeginTrans(pBt, 1, 0);
#else
  rc = sqlite3BtreeBeginTrans(pBt, 1);
#endif
  if (!rc)
  {
    int pageSize = sqlite3BtreeGetPageSize(pBt);
    Pgno nSkip = WX_PAGER_MJ_PGNO(pageSize);
#if (SQLITE_VERSION_NUMBER >= 3003014)
    DbPage *pPage;
#else
    void *pPage;
#endif
    Pgno n;
    /* Rewrite all pages using the new encryption key (if specified) */
#if (SQLITE_VERSION_NUMBER >= 3007001)
    Pgno nPage;
    int nPageCount = -1;
    sqlite3PagerPagecount(pPager, &nPageCount);
    nPage = nPageCount;
#elif (SQLITE_VERSION_NUMBER >= 3006000)
    int nPageCount = -1;
    int rc = sqlite3PagerPagecount(pPager, &nPageCount);
    Pgno nPage = (Pgno) nPageCount;
#elif (SQLITE_VERSION_NUMBER >= 3003014)
    Pgno nPage = sqlite3PagerPagecount(pPager);
#else
    Pgno nPage = sqlite3pager_pagecount(pPager);
#endif

    for (n = 1; rc == SQLITE_OK && n <= nPage; n++)
    {
      if (n == nSkip) continue;
#if (SQLITE_VERSION_NUMBER >= 3010000)
      rc = sqlite3PagerGet(pPager, n, &pPage, 0);
#elif (SQLITE_VERSION_NUMBER >= 3003014)
      rc = sqlite3PagerGet(pPager, n, &pPage);
#else
      rc = sqlite3pager_get(pPager, n, &pPage);
#endif
      if (!rc)
      {
#if (SQLITE_VERSION_NUMBER >= 3003014)
        rc = sqlite3PagerWrite(pPage);
        sqlite3PagerUnref(pPage);
#else
        rc = sqlite3pager_write(pPage);
        sqlite3pager_unref(pPage);
#endif
      }
    }
  }

  if (rc == SQLITE_OK)
  {
    /* Commit transaction if all pages could be rewritten */
    rc = sqlite3BtreeCommit(pBt);
  }
  if (rc != SQLITE_OK)
  {
    /* Rollback in case of error */
#if (SQLITE_VERSION_NUMBER >= 3008007)
    /* Unfortunately this change was introduced in version 3.8.7.2 which cannot be detected using the SQLITE_VERSION_NUMBER */
    /* That is, compilation will fail for version 3.8.7 or 3.8.7.1  ==> Please change manually ... or upgrade to 3.8.7.2 or higher */
    sqlite3BtreeRollback(pBt, SQLITE_OK, 0);
#elif (SQLITE_VERSION_NUMBER >= 3007011)
    sqlite3BtreeRollback(pbt, SQLITE_OK);
#else
    sqlite3BtreeRollback(pbt);
#endif
  }

leave_rekey:
  sqlite3_mutex_leave(db->mutex);

/*leave_final:*/
  if (rc == SQLITE_OK)
  {
    /* Set read key equal to write key if necessary */
    if (sqlite3mcHasWriteCipher(codec))
    {
      sqlite3mcCopyCipher(codec, 0);
      sqlite3mcSetHasReadCipher(codec, 1);
    }
    else
    {
      sqlite3mcSetIsEncrypted(codec, 0);
    }
  }
  else
  {
    /* Restore write key if necessary */
    if (sqlite3mcHasReadCipher(codec))
    {
      sqlite3mcCopyCipher(codec, 1);
    }
    else
    {
      sqlite3mcSetIsEncrypted(codec, 0);
    }
  }
  /* Reset reserved for read and write key */
  sqlite3mcSetReadReserved(codec, -1);
  sqlite3mcSetWriteReserved(codec, -1);

  if (!sqlite3mcIsEncrypted(codec))
  {
    /* Remove codec for unencrypted database */
    sqlite3mcSetCodec(db, dbIndex, NULL);
  }
  return rc;
}

SQLITE_API int
sqlite3_rekey(sqlite3 *db, const void *zKey, int nKey)
{
  return sqlite3_rekey_v2(db, "main", zKey, nKey);
}
