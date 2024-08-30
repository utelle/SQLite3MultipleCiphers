---
layout: default
title: Installation
nav_order: 2
has_children: false
---
# Installation
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

- TOC
{:toc}

## Overview

Build files for the supported platforms - Windows, Linux, and OSX - are provided.

The build files for Windows platforms are generated with [Premake 5](https://premake.github.io/).
For regenerating the build files it is recommended to use **_Premake 5.0 alpha 15_** or later.

For Linux and OSX build files based on the _autoconf/automake_ toolchain are provided.

### Releases and Binaries

[Releases](https://github.com/utelle/SQLite3MultipleCiphers/releases) of _SQLite3 Multiple Ciphers_ are typically made available shortly after releases of [SQLite](https://sqlite.org). Usually, an archive with the _amalgamated source code_, pre-built binaries for Windows and Android (see [SQLite Android Bindings](https://www.sqlite.org/android/)) are provided with every [release](https://github.com/utelle/SQLite3MultipleCiphers/releases).

### Language Bindings

Several language bindings for _SQLite3 Multiple Ciphers_ exist in separate projects:

- _Node.js._ wrapper [better-sqlite3-multiple-ciphers](https://www.npmjs.com/package/better-sqlite3-multiple-ciphers), ([GitHub](https://github.com/m4heshd/better-sqlite3-multiple-ciphers))
- [SQLite JDBC Driver](https://github.com/Willena/sqlite-jdbc-crypt) for _Java_
- [SQLDelight driver](https://github.com/toxicity-io/sqlite-mc) for _Kotlin_
- _.NET NuGet_ package [SQLitePCLRaw.bundle_e_sqlite3mc](https://www.nuget.org/packages/SQLitePCLRaw.bundle_e_sqlite3mc) via [Eric Sink's](https://github.com/ericsink) project [SQLitePCL.raw](https://github.com/ericsink/SQLitePCL.raw)
- _Python3_ package [apsw-sqlite3mc](https://pypi.org/project/apsw-sqlite3mc), ([GitHub](https://github.com/utelle/apsw-sqlite3mc)) based on [Roger Binns'](https://github.com/rogerbinns) project [apsw](https://github.com/rogerbinns/apsw)
- [Jonathan Giannuzzi's](https://github.com/jgiannuzzi) fork of [go-sqlite3](https://github.com/jgiannuzzi/go-sqlite3/tree/sqlite3mc) for the _Go_ language. Integration into [mattn/go-sqlite3](https://github.com/mattn/go-sqlite3) is discussed in [PR 1109](https://github.com/mattn/go-sqlite3/pull/1109), but it is unclear, if and when this will happen.

Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }

If you know about further language bindings, please drop a note (for example, via a [GitHub discussion](https://github.com/utelle/SQLite3MultipleCiphers/discussions)).

### Drop-in replacement for SQLite

In principle, the _SQLite3 Multiple Ciphers_ source code or binaries can be used as a drop-in replacement for _SQLite_.

If your project uses the _SQLite_ amalgamation source file `sqlite3.c`, this file could be replaced by the _SQLite3 Multiple Ciphers_ amalgamation source file `sqlite3mc_amalgamation.c` (as distributed with the releases).

If your project references _SQLite's_ shared library (for example, `sqlite3.dll` on Windows), _SQLite3 Multiple Ciphers'_ shared library could be referenced instead by renaming the shared library and making it available on the library search path.

## Windows builds

Ready to use project files are provided for Visual C++ 2010, 2012, 2013,
2015, 2017, 2019, and 2022. Additionally, GNU Makefiles are provided supporting GCC
(for example, [Mingw-w64](http://mingw-w64.org) or recent versions of
[tdm-gcc](https://jmeubank.github.io/tdm-gcc/)).

For Visual Studio 2010+ solutions it is possible to customize the build
by creating a `wx_local.props` file in the build directory which is used
by the projects, if it exists. The settings in that file override the
default values for the properties. The typical way to make the file is
to copy `wx_setup.props` to `wx_local.props` and then edit locally.

For GNU Makefiles the file `config.gcc` serves the same purpose as the
file `wx_setup.props` for Visual C++ projects.

The customization files `wx_setup.props` resp. `config.gcc` allow to
customize certain settings like for example the default cipher scheme.

For adjusting the build configuration edit file `premake5.lua` in the root directory,
and then run

```
premake5 [action]
```
where `action` is one of the following:
`vs2010`, `vs2012`, `vs2013`, `vs2015`, `vs2017`, `vs2019`, or `gmake2`.

When building on _Win32_ or _Win64_, you can use the makefiles or one of the
Microsoft Visual Studio solution files in the `build` folder.

For Visual C++ the debugging properties are set up in such a way that
debugging the sample applications should work right out of the box.

## Linux / OSX builds

When building on Linux or OSX, the first setup is to recreate the configure script doing:

```
  autoreconf
```

Thereafter you should create a build directory

```
  mkdir build-gtk [or any other suitable name]
  cd build-gtk
  ../configure
  make
```
 
Type `../configure --help` for more info.

The autoconf-based system also supports a `make install` target which
builds the library and then copies the headers of the component to
`/usr/local/include` and the lib to `/usr/local/lib`.

## WebAssembly

Starting with version 3.40 the [SQLite project](https://sqlite.org) provides [WebAssembly- and JavaScript-related APIs](https://sqlite.org/wasm/), which enable the use of _SQLite3_ in modern WASM-capable browsers.

**SQLite3 Multiple Ciphers** can add encryption support to WASM-based applications. In principle, [building JS/WASM support](https://sqlite.org/wasm/doc/trunk/building.md) for _SQLite3 Multiple Ciphers_ follows closely the [documentation given on the SQLite website](https://sqlite.org/wasm/doc/trunk/building.md).

The build process is very similar to the description of [Building for SQLite Encryption Extension (SEE)](https://sqlite.org/wasm/doc/trunk/building.md#see), the official (commercial) [SQLite Encryption Extension](https://sqlite.org/see/).

The following steps describe the preliminary actions:

1. Generate or download the amalgamation source code of _SQLite3 Multiple Ciphers_, matching the SQLite version, you want to build WASM support for,
2. Copy the file `sqlite3mc_amalgamation.c` to the top-most directory of the SQLite source tree,
3. Rename `sqlite3mc_amalgamation.c` to `sqlite3-see.c`, or pass `sqlite3.c=/path/to/sqlite3mc_amalgamation.c` when running make or gmake from the `ext/wasm` directory,
4. Adjust the file `ext/wasm/GNUmakefile` by adding the compile time flag `-D__WASM__` (2 places),
5. (Optional) Add support for the _SQLite3 Multiple Ciphers_ C API:
  - Add the _SQLite3 Multiple Ciphers_ API function names to file `ext/wasm/api/EXPORTED_FUNCTIONS.sqlite3-see`, prefixing them with an underscore character,
  - Add the signatures of the _SQLite3 Multiple Ciphers_ API functions to `ext/wasm/api/sqlite3-api-glue.js` (search for `sqlite3_activate_see`).

Thereafter WASM support can be built according to the [SQLite documentation](https://sqlite.org/wasm/doc/trunk/building.md).

## Support for ICU (_**I**nternational **C**omponents for **U**nicode_)

On **Windows** the **SQLite3 Multiple Ciphers** library can be built _with_ or _without_
[ICU support](https://github.com/unicode-org/icu). ICU support for SQLite3 is
currently based on pre-built ICU Libraries, which were compiled with Visual Studio 2019.
The required ICU DLLs are not included in the repository, but can be downloaded from the
[latest ICU release](https://github.com/unicode-org/icu/releases/latest).
However, the pre-built binary packages for Windows include the required ICU DLLs.

Using the build files coming with _SQLite3 Multiple Ciphers_ for building the library with ICU support,
requires to define the environment variable `LIBICU_PATH` that must point to the directory
to which the archive with the pre-built ICU libraries was extracted. 

In addition, the Visual C++ 2019 runtime is required to be installed,
because the ICU DLLs depend on it.

In principle, the ICU DLLs should be compatible with Visual C++ 2015 and Visual C++ 2017 as well.

## Default settings

Currently the cipher scheme [sqleet: ChaCha20]({{ site.baseurl }}{% link docs/ciphers/cipher_chacha20.md %}) is set as the default.
However, this can be changed by setting the preprocessor symbol `CODEC_TYPE` to one of the values listed in
the following table:

| Preprocessor Symbol | Cipher |
| :--- | :--- |
| `CODEC_TYPE_AES128` | [wxSQLite3: AES 128 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes128cbc.md %}) |
| `CODEC_TYPE_AES256` | [wxSQLite3: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_aes256cbc.md %}) |
| `CODEC_TYPE_CHACHA20`  | [sqleet: ChaCha20]({{ site.baseurl }}{% link docs/ciphers/cipher_chacha20.md %}) |
| `CODEC_TYPE_SQLCIPHER` | [SQLCipher: AES 256 Bit]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %}) |
| `CODEC_TYPE_RC4` | [System.Data.SQLite: RC4]({{ site.baseurl }}{% link docs/ciphers/cipher_sds_rc4.md %}) |
| `CODEC_TYPE_ASCON128` | [Ascon: Ascon-128 v1.2]({{ site.baseurl }}{% link docs/ciphers/cipher_ascon.md %}) |

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- If compatibility with _legacy_ [sqleet](https://github.com/resilar/sqleet) is required, it is necessary to explicitly define the preprocessor symbol `SQLITE3MC_USE_SQLEET_LEGACY`.
- If compatibility with _legacy_ [SQLCipher](https://www.zetetic.net/sqlcipher/) is required, it is necessary to explicitly define the preprocessor symbol `SQLITE3MC_USE_SQLCIPHER_LEGACY`. If not the latest SQLCipher version, but a specific older one, should be selected, then the preprocessor symbol `SQLCIPHER_VERSION_DEFAULT=version` needs to be defined, where _version_ can have one of the values 1, 2, 3, or 4.

## Optional features

SQLite has many optional features and offers a vast number of optional extensions.
The below table lists the features that are enabled for **SQLite3 Multiple Ciphers** as default.
For details, please see [SQLite Compile Time Options](https://www.sqlite.org/compile.html).

| Symbol | Description|
| :--- | :--- |
| SQLITE_DQS=0 | Disable double quoted string literals |
| SQLITE_ENABLE_COLUMN_METADATA=1 | Access to meta-data about tables and queries |
| SQLITE_ENABLE_DEBUG=0 | Enable additional debug features (default: off) |
| SQLITE_ENABLE_DESERIALIZE=1 | Enable the deserialization interface |
| SQLITE_ENABLE_EXPLAIN_COMMENTS=1 | Enable additional comments in EXPLAIN output |
| SQLITE_ENABLE_CARRAY=1 | C array extension |
| SQLITE_ENABLE_CSV=1 | CSV extension |
| SQLITE_ENABLE_FTS3=1 | Version 3 of the full-text search engine |
| SQLITE_ENABLE_FTS3_PARENTHESIS=1 | Additional operators for query pattern parser |
| SQLITE_ENABLE_FTS4=1 | Version 4 of the full-text search engine |
| SQLITE_ENABLE_FTS5=1 | Version 5 of the full-text search engine |
| SQLITE_ENABLE_GEOPOLY=1 | GeoPoly extension |
| SQLITE_ENABLE_JSON1=1 | JSON SQL functions |
| SQLITE_ENABLE_RTREE=1 | R*Tree index extension |
| SQLITE_ENABLE_EXTFUNC=1 | Extension with mathematical and string functions |
| SQLITE_ENABLE_FILEIO=1 | Extension with file I/O SQL functions |
| SQLITE_ENABLE_REGEXP=1 | Regular expression extension |
| SQLITE_ENABLE_SERIES=1 | Series extension |
| SQLITE_ENABLE_SHA3=1 | SHA3 extension |
| SQLITE_ENABLE_UUID=1 | UUID extension |
| SQLITE_MAX_ATTACHED=10 | Maximum Number Of Attached Databases (max. 125) |
| SQLITE_SECURE_DELETE=1 | Overwrite deleted content with zeros |
| SQLITE_SOUNDEX=1 | Enable soundex SQL function |
| SQLITE_USE_URI=1 | Enable URI file names |
| SQLITE_USER_AUTHENTICATION=1 | User authentication extension |
 
Note
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- In case of memory constraints it is of course possible to disable unneeded features.
However, this will require to modify the build files.

The source code of 3 extensions that require ZLIB support is also included, but is not
enabled by default:
 
- [COMPRESS](https://sqlite.org/src/file/ext/misc/compress.c)
- [SQLAR](https://sqlite.org/src/file/ext/misc/sqlar.c)
- [ZIPFILE](https://sqlite.org/src/file/ext/misc/zipfile.c)

To enable one or more of those extensions, it is required to specify the corresponding
preprocessor symbol:

| Symbol | Description|
| :--- | :--- |
| SQLITE_ENABLE_COMPRESS=1 | Enable extension COMPRESS |
| SQLITE_ENABLE_SQLAR=1 | Enable extension SQLAR |
| SQLITE_ENABLE_ZIPFILE=1 | Enable extension ZIPFILE |

To successfully compile these extensions it is required to specify for the compiler,
where the ZLIB header can be found, and for the linker, the name and location of the
ZLIB library. Alternatively, it is possible to use the included MINIZ library,
a subset of ZLIB, by  specifying the preprocessor symbol `SQLITE3MC_USE_MINIZ=1`.
This allows to remove the external dependency on the ZLIB library.

## TCL Interface

SQLite offers an implementation of a TCL interface and a TCL command shell. The source
code of this interface is included with _SQLite3 Multiple Ciphers_. 

| Symbol | Description|
| :--- | :--- |
| SQLITE_ENABLE_TCL=1 | Enable the TCL interface |

Please consult the original SQLite documentation
[Compiling the TCL interface](https://www.sqlite.org/howtocompile.html#compiling_the_tcl_interface)
for further information, how to build the TCL interface and TCL command shell, since 
_SQLite3 Multiple Ciphers_ does not contain build support for this feature.
