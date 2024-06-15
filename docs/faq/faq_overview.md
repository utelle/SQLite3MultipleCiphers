---
layout: default
title: Frequently asked questions
nav_order: 6
has_children: false
---
# Frequently Asked Questions
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## How can I enable encryption for a non-default SQLite VFS?

On initialization of the SQLite library encryption is automatically enabled for the default VFS by registering a new VFS combining the _SQLite3 Multiple Ciphers_ VFS shim with SQLite's default VFS for the current platform (for example, on _Windows_ this would result in the (new) VFS `multipleciphers-win32`) and making it the new default VFS.

On most platforms SQLite offers additional VFS implementations. For example, on _Windows_ there is the VFS `win32-longpath` which supports very long file path specifications for database files, while the default VFS `win32` supports only file paths of at most 1040 characters.

A non-default VFS is chosen for a SQLite database connection by specifying the name of the requested VFS on opening the database connection. Encryption support can be enabled for such a non-default VFS by simply prefixing the VFS name with the string `multipleciphers-`. For example, for using the VFS `win32-longpath` with encryption support specify the VFS name `multipleciphers-win32-longpath`. _SQLite3 Multiple Ciphers_ will create and register this new VFS automatically. However, the new VFS will not be made the default.

## How can I change the page size of an encrypted database?

Usually SQLite allows to change the page size of a database by requesting the new page size via a `PRAGMA page_size` SQL statement and actually changing the page size when a `VACUUM` statement is executed.

Unfortunately, this method does not work for encrypted databases. If you need to change the page size of an encrypted database, apply the following procedure:

```SQL
-- Decrypt database
PRAGMA rekey='';
-- Set requested page size
PRAGMA page_size=32768;
-- Vacuun database
VACUUM;
-- Encrypt database again
PRAGMA rekey='passphrase';
```

An alternative would be to create a copy of the database with the new page size:

```SQL
PRAGMA page_size=32768;
VACUUM INTO 'file:databasefile?key=passphrase'
```

> [!IMPORTANT]
> The database must not be in WAL journal mode.

<!--
<details>

<summary></summary>

</details>

<details>

<summary></summary>

</details>

<details>

<summary></summary>

</details>

-->
