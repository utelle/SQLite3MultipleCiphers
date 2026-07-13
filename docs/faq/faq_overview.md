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

```sql
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

```sql
PRAGMA page_size=32768;
VACUUM INTO 'file:databasefile?key=passphrase'
```

Important
{: .label .label-purple .ml-0 .mb-1 .mt-2 }
The database must not be in WAL journal mode.

## Why do I get an error on executing schema-independent selects or dynamically loading extensions?

The reason is that starting with [SQLite 3.48.0](https://sqlite.org/releaselog/3_48_0.html) executing a `SELECT` statement will now always access the underlying database file. For encrypted databases this will fail, as long as the cipher scheme has not yet been set up, that is, the `PRAGMA key` statement was not yet executed.

Therefore the SQL configuration functions can't be used any longer for configuring the cipher scheme before issuing the `PRAGMA key` statement. Please use `PRAGMA` statements or URI parameters for configuring the cipher scheme.

Dynamically loading certain SQLite extensions may also fail, if done before`PRAGMA key` was executed. Namely FTS5 extensions (like [sqlite-better-trigram](https://github.com/streetwriters/sqlite-better-trigram) or [sqlite3-fts5-html](https://github.com/streetwriters/sqlite3-fts5-html)) are affected, because they retrieve the FTS5 API pointer via a `SELECT` statement (see [issue #208](https://github.com/utelle/SQLite3MultipleCiphers/issues/208)). Postpone dynamically loading affected extensions until `PRAGMA key` was executed.

[Automatically loading statically linked extensions](https://sqlite.org/c3ref/auto_extension.html) will not work at all for extensions that depend on using `SELECT` statements while initializing the extension, because SQLite initializes extensions registered for automatic loading, before the cipher scheme is activated for the connection. For example, in case of extending the FTS5 extension, it would be necessary that the FTS5 extension provides access to the API pointer by other means than a `SELECT` statement.

## Why my app is killed under **iOS** on suspension, when the _SQLite_ database is stored in a shared container for app groups?

_iOS_ apps can't share an **encrypted** database with app extensions (e.g. share extensions) without being terminated every time they enter the background. _iOS_ won't let suspended apps retain a file lock on apps in the _"shared data container"_ used to share files between _iOS_ apps and their app extensions. This seems to affect all versions of iOS and all device models.

To overcome this issue version 4 of _SQLCipher_ introduced a new parameter `plain_text_header_size`. If this parameter is set to a non-zero value (like 16 or 32), the corresponding number of bytes at the beginning of the database header are not encrypted allowing _iOS_ to identify the file as a _SQLite_ database file. The drawback of this approach is that the cipher salt used for the key derivation can't be stored in the database header any longer. Therefore it is necessary to retrieve the cipher salt on creating a new database, and to specify the salt on opening an existing database.

While _SQLite3 Multiple Ciphers_ supported the parameter `plain_text_header_size` right from the beginning, it did not for other cipher schemes. Starting with version [2.2.0](https://github.com/utelle/SQLite3MultipleCiphers/releases/tag/v2.2.0) the cipher schemes _chacha20_, _ascon128_, and _aegis_ support this parameter as well.

In _SQLite3 Multiple Ciphers_ the cipher salt can be retrieved with the function [`sqlite3mc_codec_data`]({{ site.baseurl }}{% link docs/configuration/config_sql_functions.md %}#function-sqlite3mc_codec_data) using parameter `cipher_salt`. Alternatively, it can be retrieved with `PRAGMA cipher_salt`. On opening a database the _cipher salt_ has to be supplied either via the database URI parameter `cipher_salt`, or via `PRAGMA cipher_salt='<hex bytes of cipher salt>'`, before `PRAGMA key` is executed.

## What should I keep in mind when using _SQLite3 Multiple Ciphers_ together with other _SQLite_ libraries?

_SQLite3 Multiple Ciphers_ is designed as a **drop-in replacement for the original SQLite library**. Therefore, it intentionally exports the standard `sqlite3_*` API and is intended to provide the SQLite implementation used by the application.

The SQLite documentation recommends that only **one SQLite implementation** should exist within a process (see section [Multiple copies of _SQLite_ linked into the same application](https://sqlite.org/howtocorrupt.html#multiple_copies_of_sqlite_linked_into_the_same_application) of the SQLite documentation about [How to corrupt an SQLite database file](https://sqlite.org/howtocorrupt.html)). SQLite maintains process-wide global state (such as memory management, mutex configuration, VFS registrations, extension handling, and initialization state) that is not designed to be duplicated across multiple independent SQLite builds.

For this reason, using _SQLite3 Multiple Ciphers_ together with other SQLite implementations in the same process can lead to unpredictable behavior. Examples include:

- libraries that embed their own SQLite build for internal use,
- libraries that export the standard `sqlite3_*` symbols,
- applications that intentionally load multiple SQLite variants,
- components that link against a system-provided SQLite implementation while the application uses _SQLite3 Multiple Ciphers_ as a replacement.

A native component may embed SQLite without intending to expose SQLite as part of its public API. However, if the embedded SQLite symbols are not hidden or renamed during the build process, they can become visible to the entire process and conflict with other SQLite implementations.

The presence of multiple SQLite implementations can cause problems even if they use the same SQLite version. Different compile-time options, enabled extensions, patches, or build configurations can result in incompatible behavior. For example, one SQLite build may include extensions such as FTS5, JSON support, ICU integration, or encryption-related functionality, while another build does not.

When multiple SQLite implementations are present, symbol resolution depends on the platform, linker, loader, and application configuration. As a result, it may not be predictable which implementation is actually used at runtime. Typical symptoms include:

- encryption-related PRAGMAs such as `PRAGMA key` or `PRAGMA cipher` having no effect,
- encrypted databases failing to open with errors such as *"file is not a database"*,
- missing SQLite extensions or compile-time features,
- subtle runtime failures caused by different SQLite versions or build configurations.

Platform-specific linker options (such as `ForceLoad` on iOS) may influence which SQLite implementation is selected in a particular application. However, such settings only affect symbol availability or resolution in a specific build scenario. They do not solve the underlying problem of multiple competing SQLite implementations within the same process and may have unintended effects on other components.

It is therefore the responsibility of the application developer to ensure that the application uses a consistent SQLite configuration and to avoid combining components that provide incompatible SQLite implementations.

If a component uses SQLite only as an internal implementation detail, it should ideally hide or rename its SQLite symbols so that they do not conflict with the SQLite implementation chosen by the application.

The likelihood of symbol conflicts depends on the native platform and on how the involved libraries are built.

On some platforms, such as Windows, symbols in dynamic libraries (DLLs) are usually exported only when they are explicitly marked for export. This reduces the chance that internal implementation symbols accidentally become globally visible.

However, similar conflicts can still occur when static libraries are linked into the same application. If multiple static libraries contain identical global symbols, the final result depends on linker behavior, library order, and build settings.

On platforms where native symbols are more commonly visible by default, accidentally exporting internal SQLite symbols is easier and can lead to conflicts with other SQLite implementations in the same process.
