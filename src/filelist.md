# Source files of the SQLite3MultipleCiphers encryption extension

The following document gives a short overview of all source files of which the **SQLite3 Multiple Ciphers** encryption extension consists.

## Kernel of the SQLite3MultipleCiphers encryption extension

The following files constitute the kernel of the **SQLite3 Multiple Ciphers** encryption extension:

| Filename | Description |
| :--- | :--- |
| aegis/*.*          | Adapted files from the _libaegis_ project |
| argon2/*.*         | Adapted files from the _argon2_ project |
| ascon/*.*          | Adapted files from the _ascon-c_ project |
| chacha20/*.*       | Adapted files from the _libsodium_ project |
| aes_hardware.c     | Implementation of AES algorithms with hardware support |
| btreecopyfile.c    | Adjusted sqlite3BtreeCopyFile function for use on rekeying a database file |
| cipher_common.c    | Implementation of the common cipher functions |
| cipher_common.h    | Header for the common cipher functions |
| cipher_config.c    | Common cipher configuration functions |
| cipher_aegis.c     | Implementation of the **AEGIS** encryption extension |
| cipher_aes256gcm.c | Implementation of the **AES-256-GCM** encryption extension (AES-256-GCM-SIV, XAES-256-GCM) |
| cipher_ascon.c     | Implementation of the **Ascon128** encryption extension |
| cipher_chacha20.c  | Implementation of the **ChaCha20-Poly1305** encryption extension |
| cipher_wxaes128.c  | Implementation of the **wxSQLite3 AES 128-bit** encryption extension |
| cipher_wxaes256.c  | Implementation of the **wxSQLite3 AES 256-bit** encryption extension |
| cipher_sqlcipher.c | Implementation of the **SQLCipher** encryption extension |
| cipher_sds_rc4.c   | Implementation of the **System.Data.SQLite RC4** encryption extension |
| codec_algos.c      | Implementation of the encryption algorithms |
| codecext.c         | Implementation of the **SQLite3** codec API |
| rekeyvacuum.c      | Adjusted VACUUM function for use on rekeying a database file |
| sqlite3mc.c        | _Amalgamation_ of the complete **SQLite3 Multiple Ciphers** encryption extension |
| sqlite3mc.h        | Header for the additional API functions of the **SQLite3 Multiple Ciphers** encryption extension |
| sqlite3mc_vfs.c    | Implementation of the Multiple Ciphers VFS |
| sqlite3mc_vfs.h    | Header for the additional API functions of the Multiple Ciphers VFS |

Files in `argon2` directory are under the `Apache 2.0`license.
Files in `chacha20` directory are under the `ISC` license.
All other files, except `rekeyvacuum.c`, are licensed under the `MIT` license.

`rekeyvacuum.c` contains a slightly modified implementation of the function `sqlite3RunVacuum` from the **SQLite3** and stays in the public domain.

## Cryptograhic algorithms

The following files contain the implementations of cryptographic algorithms used by the **SQLite3MultipleCiphers** encryption extension:

| Filename | Description |
| :--- | :--- |
| chacha20poly1305.c | Implementation of ChaCha20 cipher and Poly1305 message authentication |
| fastpbkdf2.c       | Implementation of PBKDF2 functions |
| fastpbkdf2.h       | Header for PBKDF2 functions |
| md5.c              | Implementation of MD5 hash functions |
| rijndael.c         | Implementation of AES block cipher |
| rijndael.h         | Header for AES block cipher |
| sha1.c             | Implementation of SHA1 hash functions |
| sha1.h             | Header for SHA1 hash functions |
| sha2.c             | Implementation of SHA2 hash functions |
| sha2.h             | Header for SHA2 hash functions |

The files `chacha20poly1305.c`, `fastpbkdf2.*`, `md5.c`, and `sha1.*` are in the public domain.

The files `rijndael.*` contain the original Rijndael implementation by Szymon Stefanek, which is in the public domain, together with adaptations made for SQLite3MultipleCiphers. These adaptations are licensed under the `MIT` License.

The files `sha2.*` are licensed under `BSD-3-Clause`.

## Windows-specific files

The following files are only used under Windows platforms for creating binaries:

| Filename | Description |
| :--- | :--- |
| sqlite3mc.def      | Module definition specifying exported functions |
| sqlite3mc.rc       | Resource file specifying version information for the SQLite3MultipleCiphers library |
| sqlite3mc_shell.rc | Resource file specifying version information for the SQLite3MultipleCiphers shell |

All files are licensed under the `MIT` license.

## SQLite3 core

The following files belong to the **SQLite3** core:

| Filename | Description |
| :--- | :--- |
| shell.c          | SQLite3 shell application  |
| sqlite3.c        | SQLite3 source amalgamation  |
| sqlite3.h        | SQLite3 header  |
| sqlite3ext.h     | SQLite3 header for extensions  |
| tclsqlite.c      | SQLite TCL extension |
| windirent.h      | Header for directory access under Windows used by `fileio` extension |

All files are in the public domain.

## SQLite3 extensions

The following files belong to **SQLite3** extensions contained in the official **SQLite3** distribution:

| Filename | Description |
| :--- | :--- |
| carray.c          | Table-valued function that returns the values in a C-language array |
| compress.c        | SQL compression functions compress() and uncompress() using ZLIB |
| csv.c             | Virtual table for reading CSV files |
| fileio.c          | Functions `readfile` and `writefile`, and eponymous virtual table `fsdir` |
| regexp.c          | Regular expressions |
| series.c          | Table-valued-function implementing the function `generate_series` |
| shathree.c        | Functions computing SHA3 hashes |
| sqlar.c           | Utility functions sqlar_compress() and sqlar_uncompress() |
| sqlite3userauth.h | Header for user-authentication extension feature |
| uuid.c            | Functions handling RFC-4122 UUIDs |
| zipfile.c         | virtual table for reading and writing ZIP archive files. |

All files are in the public domain.

## External SQLite3 extensions

The following file was posted to the SQLite mailing list:

| Filename | Description |
| :--- | :--- |
| extensionfunctions.c | The extension provides common mathematical and string functions |

The file `extensionfunctions.c` does not contain any specific license information. Since it was posted to the SQLite mailing list, it is assumed that the file is in the public domain like SQLite3 itself.
