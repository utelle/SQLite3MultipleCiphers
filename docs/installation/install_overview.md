---
layout: default
title: Installation
nav_order: 2
has_children: false
---
# Installation

Build files for the supported platforms - Windows, Linux, and OSX - are provided.

The build files for Windows platforms are generated with [Premake 5](https://premake.github.io/).
For regenerating the build files it is recommended to use **_Premake 5.0 alpha 15_** or later.

For Linux and OSX build files based on the _autoconf/automake_ toolchain are provided.

## Windows

Ready to use project files are provided for Visual C++ 2010, 2012, 2013,
2015, 2017, and 2019. Additionally, GNU Makefiles are provided supporting GCC
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



## Linux / OSX

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
