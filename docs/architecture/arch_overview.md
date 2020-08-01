---
layout: default
title: Architecture
nav_order: 3
has_children: true
---
# Architecture

In the course of time several developers had asked for a stand-alone version of the [wxSQLite3 encryption extension](https://github.com/utelle/wxsqlite3/tree/master/sqlite3secure). Originally it was planned to undertake the separation process already in 2019, but due to personal matters it had to be postponed for several months. However, maybe that wasn't that bad after all, because there were changes to the public SQLite code on Feb 7, 2020: [“Simplify the code by removing the unsupported and undocumented SQLITE_HAS_CODEC compile-time option”](https://www.sqlite.org/src/timeline?c=5a877221ce90e752). These changes took effect with the release of SQLite version 3.32.0 on May 22, 2020. As a consequence, all SQLite encryption extensions out there will not be able to easily support SQLite version 3.32.0 and later, _wxSQLite3_ being no exception.

After some analysis it became clear that forking SQLite and maintaining a fork by somehow applying upstream changes would get increasingly difficult over time. Therefore the decision was made to develop a new implementation of the encryption extension based on [SQLite's Virtual File System](https://www.sqlite.org/vfs.html) (VFS), because a VFS shim is now the only available option to intercept read and write operations for database files.

Unfortunately, the VFS layer is rather dumb and "knows" (almost) nothing about internal SQLite3 structures. Therefore the "hard work" in implementing a VFS shim is to analyze how SQLite accesses the database files and how essential information (like the page number) can be deduced.

To be fully compatible with the previous implementation of the encryption extension **SQLite3 Multiple Ciphers** has to apply a few patches to the SQLite3 amalgamation. All of the patches are very small. Nevertheless, a solution without them would be preferrable, of course.

The following sections describe the overall approach and the patches in more detail.
