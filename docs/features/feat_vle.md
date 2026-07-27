---
layout: default
title: Value Level Encryption
parent: Features
nav_order: 2
---
# Value Level Encryption (VLE)
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Although _SQLite3 Multiple Ciphers_ is primarily intended for the complete, transparent encryption of _SQLite_ databases, there are occasionally situations in which full encryption is unnecessary and it is sufficient to encrypt individual values holding confidential information. The feature _Value Level Encryption_ (VLE) was introduced in version 2.4.0 to allow partial encryption of data in such situations, where only a subset of the data needs to be kept confidential.

The VLE feature uses the same cryptographic functions as used by _SQLite3 Multiple Ciphers_ for full database encryption. VLE provides a clean API via a small set of SQL functions. The VLE functions serve the following purposes:

- Set up a main encryption key
- Encrypt a single table column in a non-encrypted database on inserting or updating a table row
- Decrypt a single table column in a non-encrypted database on selecting a table row

Encrypted payloads have the type _BLOB_ which consists of a small header (specifying the algorithm used), nonce, ciphertext, and verifiable tag. This incurs an overhead of 36 bytes per encrypted value.

Currently, the VLE feature supports only stream cipher algorithms, namely `chacha20` and `ascon128`, since block cipher algorithms would significantly increase the overhead because blocks would have to be added or padded on a regular basis.

## Value Level Encryption API

All VLE functions take and return standard _SQLite_ values. An application can pass into or bind arbitrary values as appropriate.

### sqlite3mc\_vle\_key()

This function is used to establish a key for use within a SQLite connection. It must be called before any of the other VLE functions can be used.

```sql
sqlite3mc_vle_key(password [, salt [, algorithm [, options] ] ]);
```
Parameters:

| Parameter | Description | Required/Optional |
| :--- | :--- | :--- |
| `password` | Passphrase to be used for deriving a key | required |
| `salt`     | Key salt as _TEXT_ or _BLOB_, can be `NULL` | optional |
| `algoritm` | Name of the algorithm to be used | optional <br/> default: `chacha20` |
| `options`  | String with a list of algorithm-specific options  | optional |


After the key has been derived it is stored in the function context for future use via the VLE functions. The function returns a string beginning with `Ok` followed by the used option set, or an error message if something went wrong.

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- `sqlite3mc_vle_key()` does not enable full database encryption. The key derived by this function is completely separate from the key used for full database encryption.
- If no `salt` is specified a default `salt` value will be used. The given `salt` will always be passed through a hash function to generate a final salt with a fixed length as required by the used `algorithm` (typically 16 bytes).
- Currently, the only algorithms supported are `chacha20` and `ascon128`.

<span class="label label-green">Examples</span>

```sql
-- Specify just a passphrase for the key
SELECT sqlite3mc_vle_key('passphrase');
```

```sql
-- Specify a passphrase and a salt for the key
SELECT sqlite3mc_vle_key('passphrase', 'This is my own salt');
```

```sql
-- Select a non-default algorithm (using default salt)
SELECT sqlite3mc_vle_key('passphrase', NULL, 'ascon128');
```

```sql
-- Change the default key derivation option
SELECT sqlite3mc_vle_key('passphrase', NULL, 'ascon128', 'kdf_iter=12345');
```

---

### sqlite3mc\_vle\_encrypt()

This function is used to encrypt an input value and returns the encrypted ciphertext as a _BLOB_ result.

```sql
sqlite3mc_vle_encrypt(input [, scope]);
```

Parameters:

| Parameter | Description | Required/Optional |
| :--- | :--- | :--- |
| `input`   | Input to be encrypted | required |
| `scope`   | Scope identifier      | optional |

The encrypted value is returned as a _BLOB_. SQLite type information is preserved through the encryption and decryption process.

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- The _SQLite_ type of the `input` value is preserved.
- The `scope` value must have the _SQLite_ type _TEXT_ or _BLOB_.
- If no `scope` is specified a default `scope` value will be used. The given `scope` will always be passed through a hash function to generate a final scope value with a fixed length as required by the used algorithm.

### sqlite3mc\_vle\_decrypt()

This function is used to decrypt an input value and returns the decrypted value as the original _SQLite_ type.

```sql
sqlite3mc_vle_decrypt(input [, scope]);
```

Parameters:

| Parameter | Description | Required/Optional |
| :--- | :--- | :--- |
| `input`   | Input to be decrypted | required |
| `scope`   | Scope identifier      | optional |

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- The input value must be of type _BLOB_.
- The `scope` value must have the _SQLite_ type _TEXT_ or _BLOB_.
- If no `scope` is specified a default `scope` value will be used. The given `scope` will always be passed through a hash function to generate a final scope value with a fixed length as required by the used algorithm.

### Example Usage

Following is a simple example demonstrating the use of the VLE functions to derive and establish a key, encrypting and then decrypting a table column value.

```sql
SELECT sqlite3mc_vle_key('passphrase');
CREATE TABLE user_tokens(id, name, token);
INSERT INTO user_tokens(id, name, token) values (1, 'anton', sqlite3mc_vle_encrypt('Token of Anton'));
-- show the raw storage
SELECT id, name, hex(token) FROM user_tokens;
-- decrypt the value
SELECT id, name, sqlite3mc_vle_decrypt(token) AS token FROM user_tokens;
```

The above SQL statements will produce the following output:

| sqlite3mc_vle_key...      |
| :---          |
| Ok. Options(kdf_iter=64007) |

| id   | name  | token          |
| :--- | :---  | :---           |
|  1   | anton | EC010300B1BEE87C54F35E9E73B94E986399ED62B138F629<br/>FFF1CDD583D2A6C59F891D48F08B11DBE856E6F5FD738D9228A1D0 |

| id   | name  | token          |
| :--- | :---  | :---           |
|  1   | anton | Token of Anton |
