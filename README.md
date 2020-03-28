# About
The project **SQLite3 Multiple Ciphers** implements an encryption extension for [SQLite](https://www.sqlite.org) with support for multiple ciphers.

**SQLite3 Multiple Ciphers** is an extension to the public domain version of SQLite that allows applications to read and write encrypted database files. Currently 5 different encryption cipher schemes are supported:

- [wxSQLite3](https://github.com/utelle/wxsqlite3): AES 128 Bit CBC - No HMAC
- [wxSQLite3](https://github.com/utelle/wxsqlite3): AES 256 Bit CBC - No HMAC
- [sqleet](https://github.com/resilar/sqleet): ChaCha20 - Poly1305 HMAC
- [SQLCipher](https://www.zetetic.net/sqlcipher/): AES 256 Bit CBC - SHA1/SHA256/SHA512 HMAC
- [System.Data.SQLite](http://system.data.sqlite.org): RC4

In addition to reading and writing encrypted database files **SQLite** with the **SQLite3 Multiple Ciphers** extension is able to read and write ordinary database files created using a public domain version of SQLite. Applications can use the `ATTACH` statement of SQLite to simultaneously connect to two or more encrypted and/or unencrypted database files. For each database file a different encryption cipher scheme can be used.

**SQLite3 Multiple Ciphers** encrypts the entire database file, so that an encrypted SQLite database file appears to be white noise to an outside observer. Not only the database files themselves, but also journal files are encrypted.

## Usage

Basically, the API of the official [SQLite Encryption Extension (SEE) ](https://www.hwaci.com/sw/sqlite/see.html) is supported. This API consists of 4 functions:

```C
SQLITE_API int sqlite3_key(
  sqlite3* db,                   /* Database to set the key on */
  const void* pKey, int nKey     /* The key */
);

SQLITE_API int sqlite3_key_v2(
  sqlite3* db,                   /* Database to set the key on */
  const char* zDbName,           /* Database schema name */
  const void* pKey, int nKey     /* The key */
);

SQLITE_API int sqlite3_rekey(
  sqlite3* db,                   /* Database to be rekeyed */
  const void* pKey, int nKey     /* The new key */
);

SQLITE_API int sqlite3_rekey_v2(
  sqlite3* db,                   /* Database to be rekeyed */
  const char* zDbName,           /* Database schema name */
  const void* pKey, int nKey     /* The new key */
);
```

The functions `sqlite3_key()` and `sqlite3_key_v2()` set the database key to be used when accessing an encrypted database or creating a new encrypted database, and should usually be called immediately after `sqlite3_open()`.

`sqlite3_key()` is used to set the key for the main database, while `sqlite3_key_v2()` sets the key for the database with the schema name specified by `zDbName`. The schema name is `main` for the main database, `temp` for the temporary database, or the schema name specified in an `ATTACH` statement for an attached database.

`sqlite3_rekey()` is used to change the encryption key for the main database, while `sqlite3_rekey_v2()` changes the key for the database with the schema name specified by `zDbName`. The schema name is `main` for the main database, `temp` for the temporary database, or the schema name specified in an `ATTACH` statement for an attached database. These functions can also decrypt a previously encrypted database by specifying an empty key.

The encryption API is also accessible via `PRAGMA` statements.
