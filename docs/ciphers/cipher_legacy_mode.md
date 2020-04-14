---
layout: default
title: Legacy cipher modes
parent: Supported Ciphers
nav_order: 6
---
## <a name="legacy" /> Legacy cipher modes

On opening an existing database file SQLite reads the [database header](https://www.sqlite.org/fileformat.html#the_database_header), before the database connection is actually established and any encryption extension gets a chance to decrypt the database header. The main purpose of reading the database header is to detect the page size and the number of reserved bytes per page. This information is stored in bytes 16 through 23 of the database header. Therefore the official [SQLite Encryption Extension (SEE)](https://www.sqlite.org/see) leaves these header bytes unencrypted. 

Ciphers that encrypt these header bytes as well are called _legacy ciphers_ in the context of this documentation. If the page size or the number of reserved bytes does not correspond to default values, the use of legacy ciphers may prevent SQLite from successfully opening a database file.

All cipher implementations supported by **SQLite3 Multiple Ciphers** started their life as _legacy_ ciphers. However, in the course of time some of them offered options to leave the database header unencrypted, partially or in full:

1. The ciphers **AES 128-bit** and **AES 256 bit** of [wxSQLite3](https://github.com/utelle/wxsqlite3) were _legacy_ ciphers until the release of wxSQLite3 version 3.1.0 in May 2014. Thereafter those ciphers kept bytes 16 to 23 of the database header unencrypted. Databases encrypted in legacy format are transparently converted to non-legacy format unless the `legacy` parameter is explicitly set.
2. The cipher used by [sqleet](https://github.com/resilar/sqleet) (ChaCha20) introduced in version 0.22.0 (released in February 2018) a compile time option to leave the database header partially unencrypted.
3. The cipher used by [SQLCipher (Zetetic LLC)](https://www.zetetic.net/sqlcipher) introduced in version 4.0.0 (released in November 2018) a runtime option (`PRAGMA cipher_plaintext_header_size`) to leave the database header unencrypted partially or in full. This option was introduced to overcome a problems with database files using SQLite's WAL mode on iOS.
4. The cipher used by [System.Data.SQLite](https://system.data.sqlite.org) is a _legacy_ cipher up to now.

Database files created with **SQLite3 Multiple Ciphers** (or **wxSQLite3** version 4.0.0 and higher) will usually not be compatible with the original ciphers provided by [sqleet](https://github.com/resilar/sqleet) or [SQLCipher (Zetetic LLC)](https://www.zetetic.net/sqlcipher) unless the `legacy` parameter is explicitly set.

**Notes**
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- If a database is encrypted in legacy mode, then the `legacy` parameter *must* be set to **_true_** and the `legacy_page_size` parameter *should* be set to the correct page size. If this isn't done, **SQLite3 Multiple Ciphers** might fail to access the database.
- It's strongly recommended to use the non-legacy encryption schemes, since it provides better compatibility with SQLite. The unencrypted header bytes don't reveal any sensitive information. Note, however, that it will actually be possible to recognize encrypted SQLite database files as such. This isn't usually a problem since the purpose of a specific file can almost always be deduced from context anyway.
- If compatibility with certain legacy modes is essential, it is possible to activate the legacy modes at compile time.
