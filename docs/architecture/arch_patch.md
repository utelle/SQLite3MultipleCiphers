---
layout: default
title: SQLite Patches
parent: Architecture
nav_order: 2
---
## SQLite Patches

Of course, it would be the preferred solution to avoid patching the SQLite3 amalgamation code. However, there are a few aspects that can't be handled conveniently without patching. These aspects are described in the following sections.

### Initializing and shutting down SQLite

SQLite3 supports 2 C preprocessor macros to specify functions for initializing and shutting down the library. The macro `SQLITE_EXTRA_INIT` can be used to specify a function that will be called on initializing the library; the macro `SQLITE_EXTRA_SHUTDOWN` can be used to specify a function that will be called on shutting down the library.

**SQLite3 Multiple Ciphers** makes use of this _undocumented_ feature to register and unregister its VFS shim. This is just for convenience. In case, this feature will be removed from SQLite3 in the future, applications will have to call these functions manually before and after using the SQLite3 library.

### Handling for attached databases

The previous `SQLITE_HAS_CODEC` based implementation had support for specifying the passphrase for an attached database through a special _undocumented_ `KEY` parameter of SQLite's `ATTACH` statement. In the public SQLite version 3.32.x and later this parameter is no longer passed forward anywhere, but silently ignored.

Without patching SQLite3 applications could no longer make use of this `KEY` parameter. As a workaround the `key` URI parameter could be used, but this would require to modify the application accordingly.

Therefore, **SQLite3 Multiple Ciphers** modifies the SQLite's function for handling the `ATTACH` statement by adding a function call. The called function processes the `KEY` parameter and URI parameters, if they were specified.

Handling of the URI parameters could be postponed until the first database file access. That is, this patch could be avoided, if dropping support for the `KEY` parameter of the `ATTACH` statement is acceptable.

### Handling for main databases

It is convenient to be able to handle URI parameters at an early stage. Therefore, **SQLite3 Multiple Ciphers** modifies the SQLite's function for opening a database file by adding a function call. The called function processes URI parameters, if they were specified.

However, handling of the URI parameters could be postponed until the first database file access. That is, this patch could be avoided.

### Handling for WAL journal files

Beginning with version 1.3.0 the page content of a WAL frame is encrypted **before** SQLite calculates any checksums. In prior versions SQLite calculated the checksums based on the **unencrypted** page content. However, that could lead to problems. Therefore 2 patches are applied to SQLite's WAL implementation.

### Pragma handling

**SQLite3 Multiple Ciphers** keeps certain configuration parameters in a data structure which is bound to each database connection. Access to this data structure is implemented by a user-defined SQL function. The parameters held in this data structure can be queried or modified by `PRAGMA` statements or by calling user-defined functions.

In principle, `PRAGMA` statements could be handled in the VFS shim implementation. However, this works only for file based main databases. That is, if the main database is a memory based database, it would be impossible to handle dedicated `PRAGMA` statements, because unknown `PRAGMA` statements are silently ignored by SQLite.

Therefore, **SQLite3 Multiple Ciphers** intercepts the call to SQLite's `PRAGMA` handling function, checks for dedicated `PRAGMA` statements, and handles them, before invoking SQLite's own `PRAGMA` handling function.

This patch could be avoided, if the encryption related data structure would be bound to a database file instead of the database connection.
