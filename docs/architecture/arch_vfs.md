---
layout: default
title: Virtual File System
parent: Architecture
nav_order: 1
---
## Virtual File System

In this section only those aspects of _SQLite's Virtual File System_ will be discussed which are relevant for the implementation of the new encryption extension. A full description of _SQLite's Virtual File System_ can be found [here](https://www.sqlite.org/vfs.html).

_SQLite's Virtual File System_ is used to access various types of database files:

  - **Main database files** (Open flag `SQLITE_OPEN_MAIN_DB`)
  - Temporary database files (Open flag `SQLITE_OPEN_TEMP_DB`)
  - Transient database files (Open flag `SQLITE_OPEN_TRANSIENT_DB`)
  - **Main rollback journal files** (Open flag `) SQLITE_OPEN_MAIN_JOURNAL`)
  - Temporary rollback journal files (Open flag `SQLITE_OPEN_TEMP_JOURNAL`)
  - **Subjournal files** (Open flag `SQLITE_OPEN_SUBJOURNAL`)
  - Master journal files (Open flag `SQLITE_OPEN_MASTER_JOURNAL`)
  - **WAL journal files** (Open flag `SQLITE_OPEN_WAL`)

In accordance with the previous implementation of the encryption extension only main database files and journal files (rollback as well as WAL) will be handled (marked in **bold** in the above list). Maybe support for handling encryption for temporary files will be added in the future, if there is a demand. However, based on _SQLite's Virtual File System_ encryption can be supported only for ordinary file based databases, not for memory based databases.

Only the content of database pages will be encrypted. Just as in the previous implementation data structures used for housekeeping of journals will not be encrypted. Details of SQLite's file formats can be found [here](https://sqlite.org/fileformat.html).

An important information item for the encryption is the page number of a database page. Unfortunately the page number is not passed into the VFS methods, but has to be deduced from the given information, offset and size of the file chunk to be read or written.

### Main database files

A main database file consists of database pages of fixed size. Therefore the page number can be deduced from the offset of the file chunk.

On writing only full database pages are written. On reading there are a few special cases where a database page is read only partially. This affects only the first database page, which contains the database header.

### Rollback journal files

Rollback journal files mainly consist of a file header and page records. A page record consists of the page number, the page content, and a checksum. Page number, page content, and checksum are read and written separately in the given order. Therefore the page number can be deduced from the read or write operation preceeding the read or write operation for the page content.

### WAL journal files

WAL journal files consist of a file header and  WAL frames. Each frame consists of a frame header and the page content. The frame header contains the page number and various checksums.

Unfortunately, the frame header and the page content are not read or written in a particular order. Therefore on reading or writing the content of a page an additional read operation is required to read the page number from the frame header.

### Checksums

In the previous implementation SQLite calculated checksums **after** the page content was encrypted. In the new implementation SQLite uses the **unencrypted** page content to calculate checksums. In the transition from the previous to the new implementation this could possibly cause problems, if journal files written by the previous implementation have to be processed by the new implementation. Therefore it is strongly recommended to do the transition for intact databases without active journal files.
