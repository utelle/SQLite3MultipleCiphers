# Release notes

Release date: {BUILD_DATE}
ICU support:  ICU {ICU_SUPPORT}

The SQLite3 shell applications are compatible with the official
SQLite3 shell in respect to the compile time options
`SQLITE_ENABLE_DBSTAT_VTAB`, `SQLITE_ENABLE_STMTVTAB`, and
`SQLITE_ENABLE_UNKNOWN_SQL_FUNCTION`.

Separate archives are provided _with_ resp. _without_ enabled ICU support
for 32-bit and 64-bit Windows.

ICU support for SQLite3 is currently based on the pre-built ICU
Libraries {ICU_VERSION}, which were compiled with Visual Studio 2022.
The required ICU DLLs are included in the archives in folder `bin`.
They were downloaded from

https://github.com/unicode-org/icu/releases/tag/release-{ICU_VERSION}

In addition, the Visual C++ 2022 runtime is required to be installed,
because the ICU DLLs depend on it.

## Archive content

Archive names:

1) `sqlite3mc-u.v.w-sqlite-x.y.z-win32.zip` - 32-bit Windows without ICU support
2) `sqlite3mc-u.v.w-sqlite-x.y.z-win64.zip` - 64-bit Windows without ICU support
3) `sqlite3mc-u.v.w-sqlite-x.y.z-icu-win32.zip` - 32-bit Windows with ICU support
4) `sqlite3mc-u.v.w-sqlite-x.y.z-icu-win64.zip` - 64-bit Windows with ICU support

where `u.v.w` designates the version of _SQLite3 Multiple Ciphers_ and
`x.y.z` designates the version of the _SQLite3_ library.

32 Bit   | 64 Bit       | Description
:------- | :----------- | :--------
*.a      | *_x64.a      | Import libraries for GCC
*.lib    | *_x64.lib    | Import libraries for MSVC
*.pdb    | *_x64.pdb    | Program Database files for MSVC
*.dll    | *_x64.dll    | Shared release DLLs
*.exe    | *_x64.exe    | SQLite3 shell tool
*icu.a   | *icu_x64.a   | Import libraries for GCC, with ICU support
*icu.lib | *icu_x64.lib | Import libraries for MSVC, with ICU support
*icu.dll | *icu_x64.dll | Shared release DLLs, with ICU support
*icu.exe | *icu_x64.exe | SQLite3 shell tool, with ICU support

## Support

If you have any comments or problems open an issue on the _SQLite3 Multiple Ciphers_ github page:
https://github.com/utelle/SQLite3MultipleCiphers/issues
