# SQLite3MultipleCiphers

The project **SQLite3 Multiple Ciphers** implements an encryption extension for [SQLite](https://www.sqlite.org) with support for multiple ciphers. In the past the encryption extension was bundled with the project [wxSQLite3](https://github.com/utelle/wxsqlite3), which provides a thin SQLite3 database wrapper for [wxWidgets](https://www.wxwidgets.org/).

In the course of time several developers had asked for a stand-alone version of the _wxSQLite3 encryption extension_. Originally it was planned to undertake the separation process already in 2019, but due to personal matters it had to be postponed for several months. However, maybe that wasn't that bad after all, because there were changes to the public SQLite code on Feb 7, 2020: [“Simplify the code by removing the unsupported and undocumented SQLITE_HAS_CODEC compile-time option”](https://www.sqlite.org/src/timeline?c=5a877221ce90e752). These changes took effect with the release of SQLite version 3.32.0 on May 22, 2020. As a consequence, all SQLite encryption extensions out there will not be able to easily support SQLite version 3.32.0 and later.

In late February 2020 work started on a new implementation of a SQLite encryption extension that will be able to support SQLite 3.32.0 and later. The new approach is based on [SQLite's VFS feature](https://www.sqlite.org/vfs.html). This approach has its pros and cons. On the one hand, the code is less closely coupled with SQLite itself; on the other hand, access to SQLite's internal data structures is more complex.

The code was mainly developed under Windows, but was tested under Linux as well. At the moment no major issues are known.

## Version history

* 1.5.0 - *September 2022*
  - Based on SQLite version 3.39.3
  - Added option to register cipher schemes dynamically
  - Eliminated a few compile time warnings
* 1.4.8 - *July 2022*
  - Based on SQLite version 3.39.2
  - Fix issue in `PRAGMA rekey` that could lead to a crash
* 1.4.7 - *July 2022*
  - Based on SQLite version 3.39.2
* 1.4.6 - *July 2022*
  - Based on SQLite version 3.39.1
* 1.4.5 - *July 2022*
  - Based on SQLite version 3.39.0
  - Enabled preupdate hooks in build files
* 1.4.4 - *May 2022*
  - Based on SQLite version 3.38.5
  - Added optional extensions COMPRESS, SQLAR, and ZIPFILE
  - Added optional TCL support (source code only)
* 1.4.3 - *May 2022*
  - Based on SQLite version 3.38.5
* 1.4.2 - *April 2022*
  - Based on SQLite version 3.38.3
* 1.4.1 - *April 2022*
  - Based on SQLite version 3.38.2
  - Fix issue #74 (only debug builds are affected)
* 1.4.0 - *April 2022*
  - Based on SQLite version 3.38.2
  - Removed global VFS structure to resolve issue #73
* 1.3.10 - *March 2022*
  - Based on SQLite version 3.38.2
* 1.3.9 - *March 2022*
  - Based on SQLite version 3.38.1
* 1.3.8 - *February 2022*
  - Based on SQLite version 3.38.0
  - Updated build files (JSON extension is now integral part of SQLite)
  - Eliminated compile time warning (issue #66)
* 1.3.7 - *January 2022*
  - Based on SQLite version 3.37.2
* 1.3.6 - *January 2022*
  - Based on SQLite version 3.37.1
* 1.3.5 - *November 2021*
  - Based on SQLite version 3.37.0
  - Added build support for Visual C++ 2022
  - Fix issue #55: Set pager error state on reporting decrypt error condition to avoid assertion when SQLITE_DEBUG is defined
  - Fix issue #54: Check definition of symbol `__QNX__` to support compilation for QNX
  - Apply minor adjustments to ChaCha20 implementation (taken from upstream resilar/sqleet)
  - Fix issue #50 and #51: Numeric cipher ids are now handled correctly, if some of the cipher schemes are excluded from compilation
  - The SQLite3 Multiple Ciphers version information is now exposed in the amalgamation header
  - The compile-time configuration options have been moved to a separate header file
* 1.3.4 - *July 2021*
  - Allow empty passphrase for `PRAGMA key`
  - Allow to fully disable including of user authentication by defining `SQLITE_USER_AUTHENTICATION=0`
* 1.3.3 - *June 2021*
  - Based on SQLite version 3.36.0
* 1.3.2 - *May 2021*
  - Added configuration parameter `mc_legacy_wal` (issue #40)
  - Fix issue #39: Corrupted WAL journal due to referencing the wrong codec pointer
* 1.3.1 - *April 2021*
  - Prevent rekey in WAL journal mode
  - Fix issue in user authentication extension that prevented VACUUMing or rekeying
* 1.3.0 - *April 2021*
  - Based on SQLite version 3.35.5
  - Fix issue #37: Allow concurrent access from legacy applications by establishing WAL journal mode compatibility
  - Fix issue #36: Clear pager cache after setting a new passphrase to force a reread of the database header
  - Adjusted build files for MinGW
* 1.2.5 - *April 2021*
  - Based on SQLite version 3.35.5
* 1.2.4 - *April 2021*
  - Based on SQLite version 3.35.4
* 1.2.3 - *March 2021*
  - Based on SQLite version 3.35.3
* 1.2.2 - *March 2021*
  - Based on SQLite version 3.35.2
* 1.2.1 - *March 2021*
  - Based on SQLite version 3.35.1
* 1.2.0 - *March 2021*
  - Based on SQLite version 3.35.0
  - Enabled new SQLite Math Extension (Note: _log_ function now computes _log10_, not _ln_.)
  - Fixed a bug in cipher selection via URI, if cipher schemes were excluded from build (issue #26)
  - Cleaned up precompiler instructions to exclude cipher schemes from build
* 1.1.4 - *January 2021*
  - Based on SQLite version 3.34.1
* 1.1.3 - *December 2020*
  - Added code for AES hardware support on ARM platforms
  - Added GitHub Actions for CI
* 1.1.2 - *December 2020*
  - Fixed a bug on cipher configuration via PRAGMA commands or URI parameters
  - Added SQLite3 Multple Ciphers version info to shell application
* 1.1.1 - *December 2020*
  - Fixed a bug on removing encryption from an encrypted database
* 1.1.0 - *December 2020*
  - Based on SQLite version 3.34.0
  - Added code for AES hardware support on x86 platforms
  - Fixed issues with sqlite3_key / sqlite3_rekey
* 1.0.1 - *October 2020*
  - Added VSV extension (_V_ariably _S_eparated _V_alues)
* 1.0.0 - *August 2020*
  - First public release, based on SQLite version 3.33.0

## How to participate

**Help in testing and discussing further development will be _highly_ appreciated**. Please use the [issue tracker](https://github.com/utelle/SQLite3MultipleCiphers/issues) to give feedback, report problems, or to discuss ideas.

## Documentation

Documentation of the currently supported cipher schemes and the C and SQL interfaces is provided already on the [SQLite3MultipleCiphers website](https://utelle.github.io/SQLite3MultipleCiphers/).

Documentation on how to build the extension can be found on the page [SQLite3 Multiple Ciphers Installation](https://utelle.github.io/SQLite3MultipleCiphers/docs/installation/install_overview/).
