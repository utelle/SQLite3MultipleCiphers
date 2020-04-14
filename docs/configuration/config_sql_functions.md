---
layout: default
title: SQL Functions
parent: SQL Interface
grand_parent: Cipher configuration
nav_order: 2
---
# SQL Functions
{: .no_toc }

**SQLite3 Multiple Ciphers** defines several SQL functions, which can be used to configure global encryption parameters or specific cipher parameters. They offer the same functionality as the [PRAGMA]({% link docs/configuration/config_sql_pragmas.md %}) statements, but can be called from any SQL statement expression.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Function sqlite3mc\_config for global parameters

This version of the function `sqlite3mc_config` gets or sets encryption parameters which are relevant for the entire database connection. `paramName` is the name of the parameter which should be get or set. To set a parameter, the new parameter value is passed into the function as parameter `newValue`. To get the current parameter value, the parameter `newValue` is simply omitted.

| SQL function | Description |
| :--- | :--- |
| `sqlite3mc_config(paramName TEXT)` | Get value of database encryption parameter `paramName` |
| `sqlite3mc_config(paramName TEXT, newValue)` | Set value of database encryption parameter `paramName` to `newValue` |

Parameter names use the following prefixes:

| Prefix | Description|
| :--- | :--- |
| *no prefix* | Get or set the *transient* parameter value. Transient values are only used **once** for the next invocation of `PRAGMA key` or `PRAGMA rekey`. Afterwards, the *permanent* default values will be used again (see below). |
| `default:` | Get or set the *permanent* default parameter value. Permanent values will be used during the entire lifetime of the  database connection, unless explicitly overridden by a transient value. The initial values for the permanent default values are the compile-time default values. |
| `min:` | Get the lower bound of the valid parameter value range. This is read-only. |
| `max:` | Get the upper bound of the valid parameter value range. This is read-only. |

The following parameter names are supported for `paramName`:

| Parameter name | Description | Possible values |
| :--- | :--- | :--- |
| `cipher` | The cipher to be used for encrypting the database. | `cipherName`<br />(see&nbsp;table&nbsp;below) |
| `hmac_check` | Boolean flag whether the HMAC should be validated on read operations for encryption schemes using HMACs | `0` <br/> `1` |

The following table lists the supported cipher identifiers:

| Cipher ID | Cipher name | Cipher |
| :---: | :--- | :--- |
| 1 | `aes128cbc` | [wxSQLite3: AES 128 Bit]({% link docs/ciphers/cipher_aes128cbc.md %}) |
| 2 | `aes256cbc` | [wxSQLite3: AES 256 Bit]({% link docs/ciphers/cipher_aes256cbc.md %}) |
| 3 | `chacha20`  | [sqleet: ChaCha20]({% link docs/ciphers/cipher_chacha20.md %}) |
| 4 | `sqlcipher` | [SQLCipher: AES 256 Bit]({% link docs/ciphers/cipher_sqlcipher.md %}) |
| 5 | `rc4` | [System.Data.SQLite: RC4]({% link docs/ciphers/cipher_sds_rc4.md %}) |

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- Checking the HMAC on read operations is active by default. With the parameter `hmac_check` the HMAC check can be disabled in case of trying to recover a corrupted database. It is not recommended to deactivate the HMAC check for regular database operation. Therefore the default can not be changed.

<span class="label label-green">Examples</span>

```sql
-- Get cipher used for the next key or rekey operation
SELECT sqlite3mc_config('cipher');
```

```sql
-- Set cipher used by default for all key and rekey operations
SELECT sqlite3mc_config('default:cipher', 'sqlcipher');
```

---

## Function sqlite3mc\_config for cipher parameters

This version of the function `sqlite3mc_config` gets or sets cipher configuration parameters which are relevant for the selected cipher scheme. `cipherName` is the name of the cipher scheme, of which `paramName` is the name of the requested parameter. To set a parameter, the new parameter value is passed into the function as parameter `newValue`. To get the current parameter value, the parameter `newValue` is simply omitted.

| SQL function | Description |
| :--- | :--- |
| `sqlite3mc_config(cipherName TEXT, paramName TEXT)` | Get value of cipher `cipherName` encryption parameter `paramName` |
| `sqlite3mc_config(cipherName TEXT, paramName TEXT, newValue)` | Set value of cipher `cipherName` encryption parameter `paramName` to `newValue` |

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- See the related [cipher descriptions]({% link docs/ciphers/cipher_overview.md %}) for the parameter names supported for `paramName`.

<span class="label label-green">Examples</span>

```sql
-- Get number of KDF iterations for the AES-256 cipher
SELECT sqlite3mc_config('aes256cbc', 'kdf_iter');
```

```sql
-- Set number of KDF iterations for the AES-256 cipher to 54321
SELECT sqlite3mc_config('aes256cbc', 'kdf_iter', 54321);
```

```sql
-- Select legacy SQLCipher version 1 encryption scheme
SELECT sqlite3mc_config('cipher', 'sqlcipher');
SELECT sqlite3mc_config('sqlcipher', 'legacy', 1);
-- Activate cipher scheme
PRAGMA key='<passphrase>';
```

```sql
-- Select legacy SQLCipher version 1 encryption scheme
SELECT sqlite3mc_config('cipher', 'sqlcipher');
SELECT sqlite3mc_config('sqlcipher', 'legacy', 1);
-- Overwrite default settings for some or all cipher parameters
SELECT sqlite3mc_config('sqlcipher', 'legacy_page_size', 1024);
SELECT sqlite3mc_config('sqlcipher', 'kdf_iter', 4000);
SELECT sqlite3mc_config('sqlcipher', 'fast_kdf_iter', 2);
SELECT sqlite3mc_config('sqlcipher', 'hmac_use', 0);
-- Activate cipher scheme
PRAGMA key='<passphrase>';
```

---

## Function sqlite3mc\_codec\_data

The function `sqlite3mc_codec_data` retrieves the value of encryption parameters after an encrypted database has been opened. The parameter `schemaName` optionally specifies the schema name of an attached database; for the main database the parameter `schemaName` can be omitted. The parameter `paramName` specifies the parameter to be queried.

| SQL function | Description |
| :--- | :--- |
| `sqlite3mc_codec_data(paramName TEXT)` | Get value of parameter `paramName` |
| `sqlite3mc_codec_data(paramName TEXT, schemaName TEXT)` | Get value of parameter `paramName` from schema `schemaName` |

The following parameter names are currently supported for `paramName`:

| Cipher name | Description |
| :--- | :--- |
| `cipher_salt` | The random cipher salt used for key derivation and stored in the database header (as a hexadecimal encoded string, 32 bytes) |
| `raw:cipher_salt` | The random cipher salt used for key derivation and stored in the database header (as a raw binary string, 16 bytes) |

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- A NULL value is returned if the database is not encrypted or if the encryption scheme doesn't use a cipher salt.
- Some cipher schemes use a random cipher salt on database creation. If the database header gets corrupted for some reason, it is almost impossible to recover the database without knowing the cipher salt. For critical applications it is therefore recommended to retrieve the cipher salt after the initial creation of a database and keep it in a safe place.

<span class="label label-green">Example</span>

```sql
-- Get the random key salt as a hexadecimal encoded string (if database is encrypted and uses key salt)
SELECT sqlite3mc_codec_data('salt');
```
