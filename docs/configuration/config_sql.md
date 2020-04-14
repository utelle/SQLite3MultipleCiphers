---
layout: default
title: SQL Interface
parent: Cipher configuration
nav_order: 2
has_children: true
---
# SQL Interface

In the previous implementation of the SQLite encryption extension bundled with **wxSQLite3** the only way to configure cipher schemes was to use SQL functions (for example in SQL `SELECT` statements). The main reason was to avoid any modifications of the original SQLite amalgamation code. However, starting with SQLite version 3.32.0 the prior mechanism for implementing an encryption extension is no longer available. For providing full compatibility with prior versions **SQLite3 Multiple Ciphers** now has to modify the SQLite amalgamation code anyway, and therefore it was decided to provide `PRAGMA` statements for configuring cipher schemes in addition to SQL functions.

Using `PRAGMA` statements is now the preferred way for configuring cupher schemes, but the SQL functions are kept for compatibility with prior versions.
