---
layout: default
title: SQL Pragmas
parent: SQL Interface
grand_parent: Cipher configuration
nav_order: 1
---
# SQL PRAGMA statements
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Usage of PRAGMA statements

The general syntax of `PRAGMA` statements is:

```sql
PRAGMA [schemaName.]pragmaName [ = newValue];
```

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- If the parameter `schemaName` is omitted or given as `main`, the `PRAGMA` statement affects the main database connection.
- If the equal sign and the parameter `newValue` are omitted, the current value of the parameter will be returned.
- The following notes are valid only in the context of configuring a cipher encryption scheme:
  - If the parameter `schemaName` is omitted or given as `main`, the `PRAGMA` statement affects the **_default_** values of the encryption parameters.
  - If the parameter `schemaName` is given as `temp` (or the schema name of any attached database), the `PRAGMA` statement affects the **_transient_** values of the encryption parameters.
  - Using other schema names than `main` or `temp` has currently no effect on the encryption of attached databases.

Important
{: .label .label-purple .ml-0 .mb-1 .mt-2 }
It is strongly recommended to **avoid executing** `PRAGMA` statements for the configuration of the encryption extension **_within_ a transaction**. The effect of these `PRAGMA` statements can't be rolled back. In some cases execution will even fail (for example, `PRAGMA rekey` can't be executed within a transaction, if the number of reserved bytes per database page changes).

---

## Key handling

Creating a new, encrypted database or accessing an already encrypted database is based on the use of an _encryption key_. Such a _key_ is usually a password or passphrase or is derived from a password or passphrase. 

Most ciphers supported by **SQLite3 Multiple Ciphers** derive the key from a passphrase. The key and any cipher configuration option have to be set, before any SQL statements (e.g. `SELECT`, `INSERT`,`UPDATE`,`DELETE`,`CREATE TABLE`, etc.) are executed on the database. If the key is omitted or is an empty string no encryption is performed.

If the encryption scheme is configured via `PRAGMA` statements, the order of the `PRAGMA` statements matters. The configuration process consists of up to 3 steps:

1. _Optionally_ select the cipher scheme using [PRAGMA cipher](#pragma-cipher)
2. _Optionally_ set configuration parameters for the selected encryption scheme using [PRAGMA statements for cipher configuration](#pragma-statements-for-cipher-configuration)
3. Apply the encryption key using [PRAGMA key](#pragma-key)

Step 1 is only required, if a non-default encryption scheme should be used. Step 2 is only required, if the selected encryption scheme should be used with non-default configuration parameters. Step 3 is always required.

---

### PRAGMA *key* / *hexkey*

For creating a new, encrypted database or accessing an already encrypted database it is necessary to specify at least the _encryption key_. This can be done with the `PRAGMA key` resp `PRAGMA hexkey` statement, which has the following syntax:

```sql
PRAGMA key = { passphrase | 'passphrase' };
PRAGMA hexkey = { hex-passphrase | 'hex-passphrase' };
```
Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
The unquoted variant for the _passphrase_ is only valid, if the passphrase does not contain any whitespace characters. The _key_ pragma only works with string keys. The encoding of the passphrase should be UTF-8, unless a wrapper is used that implicitly performs conversion to UTF-8 internally. If you use a binary key, use the _hexkey_ pragma instead.

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- These pragmas return `ok` even if the provided key isn't correct. This is because the key isn't actually used until a subsequent attempt to read or write the database is made. To check whether the provided key was actually correct, you must execute a simple query like e.g. `SELECT * FROM sqlite_master;` and check whether that succeeds.
- When setting a new key on an empty database (that is, a database with zero bytes length), you have to make a subsequent write access so that the database will actually be encrypted. You'd usually want to write to a new database anyway, but if not, you can execute the [VACUUM](https://www.sqlite.org/lang_vacuum.html) statement instead to force SQLite to write to the empty database.

<span class="label label-green">Example 1:</span> _Passphrase with key derivation_

Typically the key value is a passphrase, from which the actual encryption key is derived.

```sql
PRAGMA key = 'My very secret passphrase';
PRAGMA hexkey='796f75722d7365637265742d6b6579';
```
<span class="label label-green">Example 2:</span> _Raw key data (without key derivation)_

Alternatively, it is possible to specify an exact byte sequence for the encryption key using a blob literal or a specially formatted string literal. In this case it is the responsibility of the application to ensure that the provided literal corresponds to a 64 character hex string, which will be converted directly to 32 bytes (256 bits) of key data.

```sql
-- Example of a raw key for the SQLCipher scheme
PRAGMA key = "x'54686973206973206D792076657279207365637265742070617373776F72642E'";
-- Example of a raw key for the sqleet scheme
PRAGMA key = 'raw:54686973206973206D792076657279207365637265742070617373776F72642E';
```

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
Currently only the cipher schemes [sqleet: ChaCha20]({{ site.baseurl }}{% link docs/ciphers/cipher_chacha20.md %}) and [SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %}) support this method, requiring the literal syntax as given in the example.
Starting with version [2.2.0](https://github.com/utelle/SQLite3MultipleCiphers/releases/tag/v2.2.0) the ciphers [Ascon128]({{ site.baseurl }}{% link docs/ciphers/cipher_ascon128.md %}) and [AEGIS]({{ site.baseurl }}{% link docs/ciphers/cipher_aegis.md %}) support this option, too.
All named ciphers accept the raw key material in both forms shown in the example.

<span class="label label-green">Example 3:</span> _Raw key data including salt (without key derivation)_

In addition to specifying an exact byte sequence for the encryption key it is possible to provide a specific key salt to use. Normally, for certain cipher schemes a key salt value is generated randomly and stored in the first 16 bytes of the database header. In this case an application would provide 96 characters as a blob literal or a specially formatted string literal. The first 64 characters (32 bytes) will be used as the raw encryption key, and the remaining 32 characters (16 bytes) will be used as the key salt.

```sql
-- Example of a raw key for the SQLCipher scheme
PRAGMA key = "x'54686973206973206D792076657279207365637265742070617373776F72642E2E73616C7479206B65792073616C742E'";
-- Example of a raw key for the sqleet scheme
PRAGMA key = 'raw:54686973206973206D792076657279207365637265742070617373776F72642E2E73616C7479206B65792073616C742E';
```

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
Currently only the cipher schemes [sqleet: ChaCha20]({{ site.baseurl }}{% link docs/ciphers/cipher_chacha20.md %}) and [SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %}) support this method, requiring the literal syntax as given in the example.
Starting with version [2.2.0](https://github.com/utelle/SQLite3MultipleCiphers/releases/tag/v2.2.0) the ciphers [Ascon128]({{ site.baseurl }}{% link docs/ciphers/cipher_ascon128.md %}) and [AEGIS]({{ site.baseurl }}{% link docs/ciphers/cipher_aegis.md %}) support this option, too.
All named ciphers accept the raw key material in both forms shown in the example.

---

### PRAGMA *rekey* / *hexrekey*

The `PRAGMA rekey` resp `PRAGMA hexrekey` statement has 3 use cases:

1. Encrypt an existing unencrypted database
2. Change the encryption key of an existing encrypted database
3. Remove encryption from an existing encrypted database

The `PRAGMA rekey` resp `PRAGMA hexrekey` statement has the following syntax:

```sql
PRAGMA rekey = { passphrase | 'passphrase' };
PRAGMA hexrekey = { hex-passphrase | 'hex-passphrase' };
```
Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
The unquoted variant for the _passphrase_ is only valid, if the passphrase does not contain any whitespace characters. The _rekey_ pragma only works with string keys. The encoding of the passphrase should be UTF-8, unless a wrapper is used that implicitly performs conversion to UTF-8 internally. If you use a binary key, use the _hexrekey_ pragma instead.

<span class="label label-green">Example 1:</span> _Change passphrase_

To change the passphrase of an encrypted database the `PRAGMA rekey` statement is executed with a non-empty passphrase.

```sql
PRAGMA rekey = 'My changed secret passphrase';
PRAGMA hexrekey='796f75722d7365637265742d6b6579';
```

<span class="label label-green">Example 2:</span> _Remove encryption_

To remove the encryption from a database the `PRAGMA rekey` statement is executed with an empty passphrase.

```sql
PRAGMA rekey = '';
```

---

## General PRAGMA statements

General `PRAGMA` statements are used to specify the general behaviour of the encryption extension:

- which cipher should be used, or
- whether the HMAC of database pages should be verified or not.

---

### PRAGMA *cipher*

The `PRAGMA cipher` allows to select the cipher to be used for encrypting the database, and has the following syntax:

```sql
PRAGMA cipher = { ciphername | 'ciphername' | "ciphername" };
```
where `ciphername` is one of the following strings:
- **_aes128cbc_** = [wxSQLite3: AES 128 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes128cbc.md %}), 
- **_aes256cbc_** = [wxSQLite3: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes256cbc.md %}), 
- **_chacha20_** = [sqleet: ChaCha20]({{ site.baseurl }}{% link docs/ciphers/cipher_chacha20.md %}), 
- **_sqlcipher_** = [SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %}), 
- **_rc4_** = [System.Data.SQLite: RC4]({{ site.baseurl }}{% link docs/ciphers/cipher_sds_rc4.md %})
- **_ascon128_** = [Ascon: Ascon-128 v1.2]({{ site.baseurl }}{% link docs/ciphers/cipher_ascon.md %})

<span class="label label-green">Example:</span> _Select cipher wxSQLite3: AES 256 Bit_

To remove the encryption from a database the `PRAGMA rekey` statement is executed with an empty passphrase.

```sql
PRAGMA cipher = 'aes256cbc';
```

---

### PRAGMA *cipher_salt*

The `PRAGMA cipher_salt` allows to set or retrieve the _cipher salt_ used by the cipher scheme, and has the following syntax:

```sql
PRAGMA cipher_salt = { ciphersalt | 'ciphersalt' | "ciphersalt" };
```

where the value for `ciphersalt` has to be given as a string consisting of 32 hex digits representing the 16 bytes cipher salt.

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- **Setting** the cipher salt is only possible, _before_ `PRAGMA key` is executed.
- **Retrieving** the cipher salt is only possible, _after_ `PRAGMA key` was executed.

---

### PRAGMA *hmac_check*

The `PRAGMA hmac_check` sets a boolean flag whether the HMAC should be validated on read operations for encryption schemes using HMACs. It has the following syntax:

```sql
PRAGMA hmac_check = { 0 | 1 };
```
where the value `0` stands for `false` or `disabled`, and the value `1` stands for `true` or `enabled`.

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- Checking the HMAC on read operations is active by default. With the parameter `hmac_check` the HMAC check can be disabled in case of trying to recover a corrupted database. It is not recommended to deactivate the HMAC check for regular database operation. Therefore the default can not be changed.

---

### PRAGMA *mc_legacy_wal*

The `PRAGMA mc_legacy_wal` sets a boolean flag whether the legacy mode for the WAL journal encryption should be used. It has the following syntax:

```sql
PRAGMA mc_legacy_wal = { 0 | 1 };
```
where the value `0` stands for `false` or `disabled`, and the value `1` stands for `true` or `enabled`.

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- The _legacy_ mode for WAL journal encryption is off by default. The encryption mode used by all versions up to 1.2.5 is called _legacy_ mode, version 1.3.0 introduced a new encryption mode that provides  compatibility with legacy encryption implementations and is less vulnerable to changes in SQLite. It should only be enabled to recover WAL journal files left behind by applications using versions up to 1.2.5.

---

### PRAGMA *memory_security*

The `PRAGMA memory_security` enables additional security measures by clearing memory allocations, before they are freed. This prevents leaking possibly sensitive information via unallocated memory.

```sql
PRAGMA memory_security = { 0 | NONE | 1 | FILL };
```
where the value `0` or `NONE` stands for `false` or `disabled`, and the value `1` or `FILL` stands for `true` or `enabled`.

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- If this feature was not compiled in, this pragma will be simply a no-op.
- Depending on the compile time option `SQLITE3MC_USE_RANDOM_FILL_MEMORY` the memory is cleared with zeros or random data.
- Other SQLite libraries like the **SQLCipher** library additionally lock memory allocations, so that they are not swapped from main memory to disk by the operating system. The idea is to prevent leaking possibly sensitive information via swap files. **SQLite3 Multiple Ciphers** does not offer this feature, because it would feign security that is actually not there. Typically an operating system does not track locking for memory chunks smaller than a page, but SQLite's memory allocations are often significantly smaller than a page. Therefore it is not guaranteed that several memory allocations within a page are really locked. Even locked memory is tpically written to disk if the operating system switches to hibernate state. This can't be prevented, unless hibernate state is disabled.

---

## PRAGMA statements for cipher configuration

Each cipher scheme has certain parameters which can be configured. Usually, just selecting a cipher scheme for database encryption should be enough, but if compatibility with other applications matters, it may be necessary to adjust some or all of the cipher parameters.

For each `PRAGMA` in the following sections it is noted to which cipher schemes it is applicable.

---

### PRAGMA *legacy*

**Applicable to:** [wxSQLite3: AES 128 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes128cbc.md %}), 
[wxSQLite3: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes256cbc.md %}), 
[sqleet: ChaCha20]({{ site.baseurl }}{% link docs/ciphers/cipher_chacha20.md %}), 
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %}), 
[System.Data.SQLite: RC4]({{ site.baseurl }}{% link docs/ciphers/cipher_sds_rc4.md %})

The `PRAGMA legacy` defines the [_legacy_ mode]({{ site.baseurl }}{% link docs/ciphers/cipher_legacy_mode.md %}) for a cipher scheme. It has the following syntax:

```sql
PRAGMA legacy = { 0 | 1 ... };
```

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- The value range of parameter `legacy` depends on the cipher scheme, although it is typically just a 0 / 1 decision.
- This `PRAGMA` usually changes the default parameters according to the selected `legacy` version. If deviating parameter settings are required, they must be set **after** setting the `legacy` value.

---

### PRAGMA *legacy\_page\_size*

**Applicable to:** 
[wxSQLite3: AES 128 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes128cbc.md %}), 
[wxSQLite3: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes256cbc.md %}), 
[sqleet: ChaCha20]({{ site.baseurl }}{% link docs/ciphers/cipher_chacha20.md %}), 
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %}), 
[System.Data.SQLite: RC4]({{ site.baseurl }}{% link docs/ciphers/cipher_sds_rc4.md %})

The `PRAGMA legacy_page_size` specifies the database page size to be used in [_legacy_ mode]({{ site.baseurl }}{% link docs/ciphers/cipher_legacy_mode.md %}) for a cipher scheme. It has the following syntax:

```sql
PRAGMA legacy_page_size = { 0 | 512 | 1024 | ... 65536 };
```

In non-legacy mode the page size is detected automatically, but in _legacy_ mode it is necessary to specify the page size, if it deviates from the default page size. The default page size is 4096 bytes, but it can be desirable for some applications to use a larger page size for increased performance.

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- To adjust the page size, the pragma has to be executed before setting the encryption key.
- The value for `legacy_page_size` must be a power of two between 512 and 65536 inclusive.
- The value 0 corresponds to the default SQLite page size.

---

### PRAGMA *kdf\_iter*

**Applicable to:** 
[wxSQLite3: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes256cbc.md %}), 
[sqleet: ChaCha20]({{ site.baseurl }}{% link docs/ciphers/cipher_chacha20.md %}), 
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %})
[Ascon: Ascon-128 v1.2]({{ site.baseurl }}{% link docs/ciphers/cipher_ascon.md %})

Most key derivation functions perform a certain number of iterations to strengthen the key and make it resistent to brute force and dictionary attacks. The `PRAGMA kdf_iter` statement can be used to increase or decrease the number of iterations used. It has the following syntax:

```sql
PRAGMA kdf_iter = { number-of-iterations };
```

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- If a non-default value is used on creating a database, the value must be set every time the database is opened.
- Reducing the number of iterations is strongly discouraged.

---

### PRAGMA *fast\_kdf\_iter*

**Applicable to:** 
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %})

The cipher scheme **SQLCipher** also performs a certain number of iterations for HMAC key derivation. The `PRAGMA fast_kdf_iter` statement can be used to increase or decrease the number of iterations used. It has the following syntax:

```sql
PRAGMA fast_kdf_iter = { number-of-iterations };
```

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- It is not recommended to modify this value.

---

### PRAGMA *hmac\_use*

**Applicable to:** 
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %})

The cipher scheme **SQLCipher** allows to enable or disable the use of per-page HMACs. The `PRAGMA hmac_use` statement can be used to enable or disable the use of HMACs. It has the following syntax:

```sql
PRAGMA hmac_use = { 0 | 1 };
```

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- It is not recommended to modify this value.

---

### PRAGMA *hmac\_pgno*

**Applicable to:** 
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %})

The cipher scheme **SQLCipher** uses the number of the current page to calculate the HMAC of that page. The `PRAGMA hmac_pgno` statement allows to modify in which endianess the page number should be used. It has the following syntax:

```sql
PRAGMA hmac_pgno = { 0 | 1 | 2 };
```
where the storage type is defined as
- 0 = native
- 1 = little endian
- 2 = big endian

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- It is not recommended to modify this value.

---

### PRAGMA *hmac\_salt\_mask*

**Applicable to:** 
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %})

The cipher scheme **SQLCipher** uses a certain mask byte in calculating the HMAC salt. The `PRAGMA hmac_salt_mask` statement allows to modify the mask byte. It has the following syntax:

```sql
PRAGMA hmac_salt_mask = { 0 .. 255 };
```

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- The mask byte can be specified as a hex value, e.g. `0x3a`).
- It is not recommended to modify this value.

---

### PRAGMA *kdf\_algorithm*

**Applicable to:** 
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %})

The `PRAGMA kdf_algorithm` statement allows to modify hash algorithm used for key derivation. It has the following syntax:

```sql
PRAGMA kdf_algorithm = { 0 | 1 | 2 };
```
where the value corresponds to the hash algoritm for key derivation function:
- 0 = SHA1
- 1 = SHA256
- 2 = SHA512

---

### PRAGMA *hmac\_algorithm*

**Applicable to:** 
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %})

The `PRAGMA hmac_algorithm` statement allows to modify hash algorithm used for HMAC calculation. It has the following syntax:

```sql
PRAGMA hmac_algorithm = { 0 | 1 | 2 };
```
where the value corresponds to the hash algoritm for HMAC calculation:
- 0 = SHA1
- 1 = SHA256
- 2 = SHA512

---

### PRAGMA *plaintext\_header\_size*

**Applicable to:**
[SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %})

The cipher scheme **SQLCipher** introduced a `PRAGMA` statement to keep the database header partially unencrypted in version 4. In the first place, it allows to overcome an issue with shared encrypted databases under iOS, when a database is operated in WAL mode. Such a database will be stored in a [shared container](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html). In this special case iOS actually examines a database file to determine whether it is an SQLite database in WAL mode. If the database is in WAL mode, then iOS extends [special privileges](https://developer.apple.com/library/content/technotes/tn2408/_index.html), allowing the application to maintain a file lock on the main database while it is in the background. However, if iOS can’t determine the file type from the database header, then iOS will kill the application process when it attempts to background with a file lock.

The `PRAGMA plaintext_header_size` allows to configure the cipher scheme to keep the database header partially unencrypted. It has the following syntax:

```sql
PRAGMA plaintext_header_size = { offset };
```
where the offset (where encryption starts) must be multiple of 16, i.e. 32.

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- The offset recommended by **SQLCipher** is currently 32. This value ensures that the important [SQLite header](https://www.sqlite.org/fileformat.html) segments are readable by iOS, i.e. the magic string "SQLite Format 3\0" and the database read/write version numbers indicating a database is operating in WAL journal mode (bytes at offsets 18 and 19). This will allow iOS to identify the file and will permit an application to background correctly without being killed.
- The drawback of this approach is that the cipher salt used for the key derivation can't be stored in the database header any longer. Therefore it is necessary to retrieve the cipher salt on creating a new database, and to specify the salt on opening an existing database. The cipher salt can be retrieved with the function wxsqlite3_codec_data using parameter cipher_salt, and has to be supplied on opening a database via the database URI parameter `cipher_salt`.

---

### PRAGMA *tcost*

**Applicable to:** 
[AEGIS]({{ site.baseurl }}{% link docs/ciphers/cipher_aegis.md %})

The `PRAGMA tcost` statement allows to specify the _number of iterations_ used to derive the key material with the _Argon2id_ function. It has the following syntax:

```sql
PRAGMA tcost = { 1 | 2 ... };
```

---

### PRAGMA *mcost*

**Applicable to:** 
[AEGIS]({{ site.baseurl }}{% link docs/ciphers/cipher_aegis.md %})

The `PRAGMA mcost` statement allows to specify the _amount of memory_ used to derive the key material with the _Argon2id_ function. The amount is specified as the _number of **kB** memory blocks_. It has the following syntax:

```sql
PRAGMA mcost = { 1 | 2 ... };
```
For example, specifying a value of `1024x1024` = `1048576` requests _1 GB_ of memory to be used for deriving the key material.

---

### PRAGMA *pcost*

**Applicable to:** 
[AEGIS]({{ site.baseurl }}{% link docs/ciphers/cipher_aegis.md %})

The `PRAGMA pcost` statement allows to modify the _parallelism_ aka _the number of threads_ used to derive the key material with the _Argon2id_ function. It has the following syntax:

```sql
PRAGMA pcost = { 1 | 2 ... };
```

---

### PRAGMA *algorithm*

**Applicable to:** 
[AEGIS]({{ site.baseurl }}{% link docs/ciphers/cipher_aegis.md %})

The `PRAGMA algorithm` statement allows to modify the _AEGIS_ algorithm variant used for encryption. It has the following syntax:

```sql
PRAGMA algorithm = { 1 | `aegis-128l` | 2 | `aegis-128x2` | 3 | `aegis-128x4`|
                     4 | `aegis-256`  | 5 | `aegis-256x2` | 6 | `aegis-256x4` };
```
where the value corresponds to the _AEGIS_ algorithm:
- 1 = `aegis-128l`
- 2 = `aegis-128x2`
- 3 = `aegis-128x4`
- 4 = `aegis-256`
- 5 = `aegis-256x2`
- 6 = `aegis-256x4`
