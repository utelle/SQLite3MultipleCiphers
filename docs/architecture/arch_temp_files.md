---
layout: default
title: Temporary Files
parent: Architecture
nav_order: 3
---
## Temporary Files

SQLite uses temporary files for various purposes; these files are deleted at the latest when a database connection is closed. These include temporary databases, temporary journals, and temporary data generated during sorting operations. For more details, see the [SQLite documentation](https://sqlite.org/tempfiles.html).

### Overview

Starting with version **2.6.0** of **SQLite3 Multiple Ciphers**, temporary data is stored in memory by default. This was already the case for precompiled binaries in prior versions, but for user-built binaries, it only applied if the corresponding compile option was explicitly set.

However, for each database connection, you can configure separately how temporary data should be handled using [`PRAGMA temp_store`](https://sqlite.org/pragma.html#pragma_temp_store). This means that in environments with limited main memory, temporary data can be stored in files instead of in memory.

However, in the context of encrypted databases, the storage of temporary data has been a problem in the past with regard to data security, since temporary files were not encrypted and data could therefore end up on the hard drive in unencrypted form.

Alternative encryption extensions such as [SQLite Encryption Extension (SEE)](https://sqlite.org/see/) or [SQLCipher](https://www.zetetic.net/sqlcipher/) are also affected by this limitation.

For **SQLite3 Multiple Ciphers**, however, this restriction no longer applies as of version **2.6.0**. Temporary files are now also encrypted to ensure data confidentiality.

### Encryption

Since SQLite manages temporary files largely independently of the main database, there is no direct connection to the main database's encryption scheme. We have therefore decided to avoid administrative overhead on the user's part and instead to use always the default `chacha20` scheme with random keys.

If the main database is encrypted or if any of the attached databases (if used) in the database connection are encrypted, temporary files are also encrypted.

When creating a temporary file, a random key is generated as needed and stored in the file handle. Each write operation also uses a nonce, which is changed every time the same data block is overwritten. From our perspective, it is not necessary to further secure the authenticity of short-lived, only locally used data using _Poly1305_ tags. Mainly for performance reasons, we have therefore chosen not to generate _Poly1305_ tags.

### Technical Implementation

Since SQLite's temporary files have very different structures, they are stored in fixed-length blocks regardless of their structure. Each block has an 8-byte prefix containing its current nonce. For temporary and transient databases, however, care is taken to ensure that the block size is chosen according to the size of the database pages in order to make access as efficient as possible.
