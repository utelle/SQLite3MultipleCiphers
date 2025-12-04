---
layout: default
title: External Links
nav_order: 7
has_children: false
---
# External Links

Several tools, wrappers, and applications are using **SQLite3 Multiple Ciphers** under the hood to support SQLite database encryption. The following sections provide links to such projects.

## SQLite Database Management Tools

- [SQLiteStudio](https://sqlitestudio.pl), ([GitHub](https://github.com/pawelsalawa/sqlitestudio))
- [sqlite-gui](https://github.com/little-brother/sqlite-gui)
- [SQLMaestro](https://www.sqlmaestro.com), (commercial)
- [HeidiSQL](https://www.heidisql.com), ([GitHub](https://github.com/HeidiSQL/HeidiSQL)); starting with version 12.8 support for SQLite encryption is  officially available (see release of [HeidiSQL version 12.8](https://github.com/HeidiSQL/HeidiSQL/releases/tag/12.8)).

## SQLite Wrapper

- _Node.js._ wrapper [better-sqlite3-multiple-ciphers](https://www.npmjs.com/package/better-sqlite3-multiple-ciphers), ([GitHub](https://github.com/m4heshd/better-sqlite3-multiple-ciphers))
- [SQLite JDBC Driver](https://github.com/Willena/sqlite-jdbc-crypt)
- [SQLDelight driver](https://github.com/toxicity-io/sqlite-mc)
- _.NET NuGet_ package [SQLite3MC.PCLRaw.bundle](https://www.nuget.org/packages/SQLite3MC.PCLRaw.bundle) ([GitHub](https://github.com/utelle/SQLite3MultipleCiphers-NuGet)) (since November 2025).  
  The prior package [SQLitePCLRaw.bundle_e_sqlite3mc](https://www.nuget.org/packages/SQLitePCLRaw.bundle_e_sqlite3mc) is deprecated, because the maintainer doesn't provide up-to-date binaries for the package any longer for free - however, commercial [build service and support](https://sqlite.sourcegear.com/doc/trunk/www/sqlite_build_service.md) is [available](https://sqlite.sourcegear.com/doc/trunk/www/sqlite_build_service.md).
- _Python3_ package [apsw-sqlite3mc](https://pypi.org/project/apsw-sqlite3mc), ([GitHub](https://github.com/utelle/apsw-sqlite3mc))
- Qt plugin for SQLite [QtCipherSqlitePlugin](https://github.com/devbean/QtCipherSqlitePlugin) or [QSQLite3MultipleCiphers](https://github.com/FalsinSoft/QSQLite3MultipleCiphers)

## Package manager

- Recipe for the _CONAN C/C++ Package Manager_: [![Conan Center](https://img.shields.io/conan/v/sqlite3mc)](https://conan.io/center/recipes/sqlite3mc)

## Applications

- [Goupile](https://goupile.org/en/), an open-source electronic data capture application
- [LazLiteDB](https://sourceforge.net/projects/lazlitedb/), a SQLite DB editor and reporter application
