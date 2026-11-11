---
layout: default
title: Database Encryption
parent: Features
nav_order: 2
---
# Database Encryption
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

The most significant feature of _SQLite3MC_ is that databases can be encrypted to ensure confidentiality. Modern methods like `chacha20`, `ascon128`, `aegis`, and `sqlcipher` all follow a uniform scheme:

1. To derive the encryption key, a random 16-byte salt is used in addition to the passphrase; this salt is stored in the first 16 bytes of the database header. Alternatively, the application itself can perform the key derivation, and the key and salt can be specified as raw values.
2. The database is encrypted page by page, with a random nonce used for each page, which is generated anew each time the page is written. To secure the page content, a tag is assigned that can be used to detect any tampering with the page content. The nonce and tag are stored in a reserved area on each page.

## Key derivation and salt

Unless the standard cipher scheme is to be used, the cipher scheme (and, if necessary, parameter values that differ from the standard) must first be configured. Encryption is then initiated using a `PRAGMA key=<passphrase>;` command.

For new databases, a random 16-byte salt is generated. Typically, the salt is stored in the database header. An exception occurs when the `plaintext_header` feature is used, since in this case the salt cannot be stored in the database itself. In this case, it is the user’s responsibility to retrieve the salt that was used and to provide it when opening the database in the future. The `cipher_salt` pragma is available for this purpose.

Not only for the use case mentioned above, but in general, it is recommended to retrieve the salt and store it in a secure location, since any intentional or unintentional change to the first 16 bytes of the database header will prevent the database from being opened.

## Changing the encryption key

In general, a database's encryption can be changed using the `rekey` pragma. In the past, the salt was also reset during re-encryption. However, since this can lead to problems when reopening the database in the event of an error — particularly when using WAL journaling mode — the old salt will be retained since version 2.7.0, regardless of the journaling mode.

From a security standpoint, retaining the old salt is generally not a serious problem. However, if a new salt is to be generated during re-encryption, this can be done by taking the appropriate precautions.

```sql
PRAGMA rekey_salt [= { 0 | 1 | on | off | true | false| yes | no } ];
```

Before executing the `rekey` pragma, the new salt can be regenerated (value `1`, `on`, `true`, or `yes`) or cleared (value `0`, `off`, `false`, or `no`) using the `rekey_salt` pragma with a value assignment. The resulting salt value is returned. The current salt value can be retrieved at any time using the pragma without a value assignment.

It is essential to store the generated salt value in a secure location. In particular, when using WAL journal mode, the database can otherwise only be opened by explicitly specifying the salt (using the `cipher_salt` pragma or URI parameter) as long as no WAL checkpoint has yet been performed. This also applies if the rekey operation aborts for any reason and the hot journal is to be used for a rollback.

If the salt remains unchanged, an interruption of the rekey operation due to an error is generally not a problem, since the salt can be retrieved from the database file when processing the hot journal.

The only critical cases are those in which a new salt must be used (_encrypting an unencrypted database_) or in which the salt is removed (_decrypting an encrypted database_). In the first case, however, errors during the rekey operation do not pose a serious problem, since the hot journal can be used for rollback without a key. In the second case, however, the hot journal can only be used for rollback if the previous passphrase and salt are specified when opening the database.
