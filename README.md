---
layout: default
title: Overview
nav_order: 1
has_children: false
permalink: /
---
# Overview
The project **SQLite3 Multiple Ciphers** implements an encryption extension for [SQLite](https://www.sqlite.org) with support for multiple ciphers.

**SQLite3 Multiple Ciphers** is an extension to the public domain version of SQLite that allows applications to read and write encrypted database files. Currently **6** different encryption cipher schemes are supported:

- [wxSQLite3](https://github.com/utelle/wxsqlite3): AES 128 Bit CBC - No HMAC
- [wxSQLite3](https://github.com/utelle/wxsqlite3): AES 256 Bit CBC - No HMAC
- [sqleet](https://github.com/resilar/sqleet): **ChaCha20 - Poly1305 HMAC** (Default cipher scheme)
- [SQLCipher](https://www.zetetic.net/sqlcipher/): AES 256 Bit CBC - SHA1/SHA256/SHA512 HMAC
- [System.Data.SQLite](http://system.data.sqlite.org): RC4
- [Ascon](https://ascon.iaik.tugraz.at/): Ascon-128 v1.2

The cipher scheme **ChaCha20 - Poly1305 HMAC** is currently the **recommended** _default cipher scheme_, because it meets the following important criteria:

- Encryption and tamper detection is a modern [Internet Engineering Task Force](https://www.ietf.org) standard, also used for secure web communication (TLS/SSL) - see [RFC 7905](https://datatracker.ietf.org/doc/html/rfc7905). 
- A key derivation function ([PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)) is used to reduce vulnerability to brute force attacks. 
- Per database and per page random bytes ([cryptographic nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce)) are used to ensure that the same unencrypted database content does not result in the same encrypted content when the same encryption key is used.

Technically, the cipher schemes [SQLCipher](https://www.zetetic.net/sqlcipher/) and [Ascon](https://ascon.iaik.tugraz.at/) are almost equivalent with respect to cryptographic security. However, **SQLCipher** uses [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), which has usually lower runtime performance than **ChaCha20 - Poly1305 HMAC**. And [Ascon](https://ascon.iaik.tugraz.at/) is a relatively new player supporting _authenticated encryption schemes with associated data_ ([AEAD](https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-properties-03.html)), selected as [new standard for lightweight cryptography](https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices) in the [NIST Lightweight Cryptography competition (2019–2023)](https://csrc.nist.gov/projects/lightweight-cryptography/finalists).

The cipher schemes **AES 128/256 Bit CBC** and **RC4** ([System.Data.SQLite](http://system.data.sqlite.org)) do **not** meet the above criteria and are included for compatibility with older existing applications only. They should not be used for new development. Developers using one of these cipher schemes should consider to update their applications to use one of the more modern and secure cipher schemes.

## Technical functionality

**SQLite3 Multiple Ciphers** encrypts the entire database file, so that an encrypted SQLite database file appears to be white noise to an outside observer. Not only the database files themselves, but also journal files are encrypted.

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
**SQLite3 Multiple Ciphers** has more or less the same limitations as the official [SQLite Encryption Extension (SEE)](https://www.sqlite.org/see):

  1. `TEMP` tables are not encrypted.
  2. In-memory (`":memory:"`) databases are not encrypted.
  3. Bytes 16 through 23 of the database file contain header information that is usually **not** encrypted.

To not compromise security by leaking temporary data to disk, it is very important to keep **all** temporary data in memory. Therefore it is strongly recommended to use the compile time option `SQLITE_TEMP_STORE=2` (which is the default in the current build files) (or even `SQLITE_TEMP_STORE=3`, forcing temporary data to memory unconditionally). `PRAGMA temp_store=MEMORY;` should be used for encrypted databases, if the compile time option `SQLITE_TEMP_STORE` was **not** set to a value of `2` or `3`.

In addition to reading and writing encrypted database files **SQLite** with the **SQLite3 Multiple Ciphers** extension is able to read and write ordinary database files created using a public domain version of SQLite. Applications can use the `ATTACH` statement of SQLite to simultaneously connect to two or more encrypted and/or unencrypted database files. For each database file a different encryption cipher scheme can be used.

## Usage

The _SQLite3 Multiple Ciphers_ encryption extension can be used via the C API as well as via SQL.

### C API

Basically, the C API of the official [SQLite Encryption Extension (SEE) ](https://www.hwaci.com/sw/sqlite/see.html) is supported. This API consists of 4 functions:

```c
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

A more detailed description can be found [here]({{ site.baseurl }}{% link docs/configuration/config_capi.md %}).

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
Since _SQLite3 Multiple Ciphers_ makes use of the _automatic extension loading mechanism_ (via the function `sqlite3_auto_extension`) and dynamically allocates _Virtual File System_ (VFS) instances, it is strongly recommended to call function _**sqlite3_shutdown()**_, right before exiting the application **after** all active database connections have been closed, to **avoid memory leaks**.

### SQL API

The encryption API is also accessible via `PRAGMA` statements:

- [PRAGMA key]({{ site.baseurl }}{% link docs/configuration/config_sql_pragmas.md %}#pragma-key) allows to set the passphrase.
- [PRAGMA rekey]({{ site.baseurl }}{% link docs/configuration/config_sql_pragmas.md %}#pragma-rekey) allows to change the passphrase.

A more detailed description (especially, how to configure cipher schemes) can be found [here]({{ site.baseurl }}{% link docs/configuration/config_sql_pragmas.md %}).

Additionally, the SQL command `ATTACH` supports the `KEY` keyword to allow to attach an encrypted database file to the current database connection:
```sql
ATTACH [DATABASE] <db-file-expression> AS <schema-name> [KEY <passphrase>]
```
