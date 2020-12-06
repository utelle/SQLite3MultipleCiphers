---
layout: default
title: C Interface
parent: Cipher configuration
nav_order: 1
---
# <a name="config_capi" />C Interface

The C interface of **SQLite3 Multiple Ciphers** consists of the _official_ [SQLite C Interface](https://www.sqlite.org/c3ref/funclist.html) and the following additional functions:

| Function | Description |
| :--- | :--- |
| `sqlite3_key()` and `sqlite3_key_v2()` | Set the database key to use when accessing an encrypted database |
| `sqlite3_rekey()` and `sqlite3_rekey_v2()` | Change the database encryption key |
| `sqlite3mc_config()` | Configure database encryption parameters |
| `sqlite3mc_config_cipher()` | Configure cipher encryption parameters |
| `sqlite3mc_codec_data()` | Configure cipher encryption parameters |

A detailed description of each function and its parameters is provided in the following sections:

- [Functions `sqlite3_key()` and `sqlite3_key_v2()`](#config_key)
- [Functions `sqlite3_rekey()` and `sqlite3_rekey_v2()`](#config_rekey)
- [Function `sqlite3mc_config()`](#config_general)
- [Function `sqlite3mc_config_cipher()`](#config_cipher)
- [Function `sqlite3mc_codec_data()`](#config_codec_data)

The functions `sqlite3_key()`, `sqlite3_key_v2()`, `sqlite3_rekey()`, and `sqlite3_rekey_v2()` belong to the C interface of the _official_ (commercial) SQLite Add-On [SQLite Encryption Extension (SEE)](https://www.hwaci.com/sw/sqlite/see.html). For compatibility with this add-on the names of these functions use the typical `sqlite3_` prefix. Functions that are specific for **SQLite3 Multiple Ciphers** use the name prefix `sqlite3mc_`.

---

## <a name="config_key" />Functions `sqlite3_key()` and `sqlite3_key_v2()`

`sqlite3_key()` and `sqlite3_key_v2()` set the database key to use when accessing an encrypted database, and should usually be called immediately after `sqlite3_open()`.

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
```

`sqlite3_key()` is used to set the key for the main database, while `sqlite3_key_v2()` sets the key for the database with the schema name specified by `zDbName`. The schema name is `main` for the main database, `temp` for the temporary database, or the schema name specified in an [ATTACH](https://www.sqlite.org/lang_attach.html) statement for an attached database. If `sqlite3_key()` or `sqlite3_key_v2()` is called on an empty database, then the key will be initially set. The return value is `SQLITE_OK` on success, or a non-zero SQLite3 error code on failure.

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- These functions return `SQLITE_OK` even if the provided key isn't correct. This is because the key isn't actually used until a subsequent attempt to read or write the database is made. To check whether the provided key was actually correct, you must execute a simple query like e.g. `SELECT * FROM sqlite_master;` and check whether that succeeds.
- When setting a new key on an empty database (that is, a database with zero bytes length), you have to make a subsequent write access so that the database will actually be encrypted. You'd usually want to write to a new database anyway, but if not, you can execute the [VACUUM](https://www.sqlite.org/lang_vacuum.html) statement instead to force SQLite to write to the empty database.

---

## <a name="config_rekey" />Functions `sqlite3_rekey()` and `sqlite3_rekey_v2()`

`sqlite3_rekey()` and `sqlite3_rekey_v2()` change the database encryption key.

```c
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

`sqlite3_rekey()` is used to change the key for the main database, while `sqlite3_rekey_v2()` changes the key for the database with the schema name specified by `zDbName`. The schema name is `main` for the main database, `temp` for the temporary database, or the schema name specified in an [ATTACH](https://www.sqlite.org/lang_attach.html) statement for an attached database.

Changing the key includes encrypting the database for the first time, decrypting the database (if `pKey == NULL` or `nKey == 0`), as well as re-encrypting it with a new key. The return value is `SQLITE_OK` on success, or a non-zero SQLite3 error code on failure.

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- If the number of reserved bytes per database page differs between the current and the new encryption scheme, then `sqlite3_rekey()` performs a [VACUUM](https://www.sqlite.org/lang_vacuum.html) statement to encrypt/decrypt all pages of the database. Thus, the total disk space requirement for re-encrypting can be up to 3 times of the database size. If possible, re-encrypting is done in-place.
- On decrypting a database all reserved bytes per database page are released.
- On changing the database encryption key it is not possible to change the page size of the database at the same time. This affects mainly _legacy_ modes with a non-default page size (like legacy **SQLCipher**, which has a page size of 1024 bytes). In such cases it is necessary to adjust the legacy page size to the default page size or to adjust the page size in a separate step by executing the following SQL statements:

```sql
PRAGMA page_size=4096;
VACUUM;
```

However, please keep in mind that this works only on plain unencrypted databases.

---

## <a name="config_general" />Function `sqlite3mc_config()`

```c
SQLITE_API int sqlite3mc_config(
  sqlite3*    db,                /* Database instance */
  const char* paramName,         /* Parameter name */
  int         newValue           /* New value of the parameter */
);
```

`sqlite3mc_config()` gets or sets encryption parameters which are relevant for the entire database instance. `db` is the database instance to operate on, or `NULL` to query the compile-time default value of the parameter. `paramName` is the name of the requested parameter. To set a parameter, pass the new parameter value as `newValue`. To get the current parameter value, pass **-1** as `newValue`.

Parameter names use the following prefixes:

| Prefix | Description|
| :--- | :--- |
| *no prefix* | Get or set the *transient* parameter value. Transient values are only used **once** for the next call to `sqlite3_key()` or `sqlite3_rekey()`. Afterwards, the *permanent* default values will be used again (see below). |
| `default:` | Get or set the *permanent* default parameter value. Permanent values will be used during the entire lifetime of the `db` database instance, unless explicitly overridden by a transient value. The initial values for the permanent default values are the compile-time default values. |
| `min:` | Get the lower bound of the valid parameter value range. This is read-only. |
| `max:` | Get the upper bound of the valid parameter value range. This is read-only. |

The following parameter names are supported for `paramName`:

| Parameter name | Description | Possible values |
| :--- | :--- | :--- |
| `cipher` | The cipher to be used for encrypting the database. | `1` .. `5`<br />(see&nbsp;Cipher&nbsp;IDs&nbsp;below) |
| `hmac_check` | Boolean flag whether the HMAC should be validated on read operations for encryption schemes using HMACs | `0` <br/> `1` |

The following table lists the supported cipher identifiers:

| Cipher ID | Preprocessor Symbol | Cipher |
| :---: | :--- | :--- |
| 1 | `CODEC_TYPE_AES128` | [wxSQLite3: AES 128 Bit]({% link docs/ciphers/cipher_aes128cbc.md %}) |
| 2 | `CODEC_TYPE_AES256` | [wxSQLite3: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes256cbc.md %}) |
| 3 | `CODEC_TYPE_CHACHA20`  | [sqleet: ChaCha20](../ciphers/cipher_chacha20.md) |
| 4 | `CODEC_TYPE_SQLCIPHER` | [SQLCipher: AES 256 Bit]({../ciphers/cipher_sqlcipher.md) |
| 5 | `CODEC_TYPE_RC4` | [System.Data.SQLite: RC4](../ciphers/cipher_sds_rc4.md) |

The return value always is the current parameter value on success, or **-1** on failure.

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- Checking the HMAC on read operations is active by default. With the parameter `hmac_check` the HMAC check can be disabled in case of trying to recover a corrupted database. It is not recommended to deactivate the HMAC check for regular database operation. Therefore the default can not be changed.

<span class="label label-green">Examples</span>

```c
/* Use AES-256 cipher for the next call to sqlite3_key() or sqlite3_rekey() for the given db */
sqlite3mc_config(db, "cipher", CODEC_TYPE_AES256);
```

```c
/* Use SQLCipher during the entire lifetime of database instance */
sqlite3mc_config(db, "default:cipher", CODEC_TYPE_SQLCIPHER);
```

```c
/* Get the maximum value which can be used for the "cipher" parameter */
sqlite3mc_config(NULL, "max:cipher", -1);
```

---

## <a name="config_cipher" />Function `sqlite3mc_config_cipher()`

```c
SQLITE_API int sqlite3mc_config_cipher(
  sqlite3*    db,                /* Database instance */
  const char* cipherName,        /* Cipher name */
  const char* paramName,         /* Parameter name */
  int         newValue           /* New value of the parameter */
);
```

`sqlite3mc_config_cipher()` gets or sets encryption parameters which are relevant for a specific encryption cipher only. See the [`sqlite3mc_config()` function](#config_general) for details about the `db`, `paramName` and `newValue` parameters. See the related [cipher descriptions](#ciphers) for the parameter names supported for `paramName`.

The following cipher names are supported for `cipherName`:

| Cipher name | Refers to | Description |
| :--- | :--- | :--- |
| `aes128cbc` | `1`&nbsp;=&nbsp;`CODEC_TYPE_AES128` | [AES 128 Bit CBC - No HMAC (wxSQLite3)](../ciphers/cipher_aes128cbc.md) |
| `aes256cbc` | `2`&nbsp;=&nbsp;`CODEC_TYPE_AES256` | [AES 256 Bit CBC - No HMAC (wxSQLite3)](../ciphers/cipher_aes256cbc.md) |
| `chacha20`  | `3`&nbsp;=&nbsp;`CODEC_TYPE_CHACHA20` | [ChaCha20 - Poly1305 HMAC (sqleet)](../ciphers/cipher_chacha20.md) |
| `sqlcipher` | `4`&nbsp;=&nbsp;`CODEC_TYPE_SQLCIPHER` | [AES 256 Bit CBC - SHA1 HMAC (SQLCipher)](../ciphers/cipher_sqlcipher.md) |
| `rc4`       | `5`&nbsp;=&nbsp;`CODEC_TYPE_RC4` | [RC4 (System.Data.SQLite)](../ciphers/cipher_sds_rc4.md) |

The return value always is the current parameter value on success, or **-1** on failure.

<span class="label label-green">Example</span>

```c
/* Activate SQLCipher version 1 encryption scheme for the next key or rekey operation */
sqlite3mc_config(db, "cipher", CODEC_TYPE_SQLCIPHER);
sqlite3mc_config_cipher(db, "sqlcipher", "kdf_iter", 4000);
sqlite3mc_config_cipher(db, "sqlcipher", "fast_kdf_iter", 2);
sqlite3mc_config_cipher(db, "sqlcipher", "hmac_use", 0);
sqlite3mc_config_cipher(db, "sqlcipher", "legacy", 1);
sqlite3mc_config_cipher(db, "sqlcipher", "legacy_page_size", 1024);
```

---

## <a name="config_codec_data" />Function `sqlite3mc_codec_data()`

```c
SQLITE_API unsigned char* sqlite3mc_codec_data(
  sqlite3*    db,                /* Database instance */
  const char* schemaName,        /* Cipher name */
  const char* paramName          /* Parameter name */
);
```

`sqlite3mc_codec_data()` retrieves the value of encryption parameters after an encrypted database has been opened. `db` is the database instance to operate on. `schemaName` optionally specifies the schema name of an attached database; for the main database the parameter can be specified as `NULL`. `paramName` specifies the parameter to be queried.

The following parameter names are currently supported for `paramName`:

| Cipher name | Description |
| :--- | :--- |
| `cipher_salt` | The random cipher salt used for key derivation and stored in the database header (as a hexadecimal encoded string, 32 bytes) |
| `raw:cipher_salt` | The random cipher salt used for key derivation and stored in the database header (as a raw binary string, 16 bytes) |

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- A NULL pointer is returned if the database is not encrypted or if the encryption scheme doesn't use a cipher salt. If a non-NULL pointer is returned, it is the application's responsibility to free the memory using function `sqlite3_free`.
- Some cipher schemes use a random cipher salt on database creation. If the database header gets corrupted for some reason, it is almost impossible to recover the database without knowing the cipher salt. For critical applications it is therefore recommended to retrieve the cipher salt after the initial creation of a database and keep it in a safe place.
