---
layout: default
title: Supported Ciphers
nav_order: 4
has_children: true
---
# Supported Ciphers

**SQLite3 Multiple Ciphers** currently supports the cipher schemes of 4 _Open Source_ projects that provide SQLite database encryption:

- [wxSQLite3](https://github.com/utelle/wxsqlite3)
- [sqleet](https://github.com/resilar/sqleet)
- [SQLCipher](https://www.zetetic.net/sqlcipher/)
- [System.Data.SQLite](http://system.data.sqlite.org)

The implementation of the cipher schemes of **wxSQLite3**, **SQLCipher**, and **System.Data.SQLite** is based on code from project [wxSQLite3](https://github.com/utelle/wxsqlite3); the implementation of the cipher scheme **sqleet** uses (slightly modified) code from the project [sqleet](https://github.com/resilar/sqleet). There is no direct dependency on external projects. The project [wxSQLite3](https://github.com/utelle/wxsqlite3) will use the **SQLite3 Multiple Ciphers** implementation in future versions (starting with version 5).

The following sections describe the supported cipher schemes in a bit more detail. 

Special attention should be payed to the section about _legacy_ modes. While _legacy_ encryption modes from the above mentioned projects is supported, the default of **SQLite3 Multiple Ciphers** is to use _non-legacy_ modes, which increase compatibility with SQLite itself.
