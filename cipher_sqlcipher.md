## <a name="cipher_sqlcipher"/> SQLCipher: AES 256 Bit CBC - SHA1/SHA256/SHA512 HMAC

SQLCipher was developed by [Zetetic LLC](https://www.zetetic.net/sqlcipher) and initially released in 2008. It is a 256 bit AES encryption in CBC mode.

The encryption key is derived from the passphrase using a random salt (stored in the first 16 bytes of the database file) and the standardized PBKDF2 algorithm with an SHA1, SHA256, or SHA512 hash function.

A random 16 bytes initial vector (nonce) for the encryption of each database page is used for the AES algorithm. Additionally, an authentication tag per database page is calculated. SQLCipher version 1 used no tag; SQLCipher version 2 to 3 used a 20 bytes **SHA1** tag; SQLCipher version 4 uses a 64 bytes **SHA512** tag, allowing to optionally choose a 32 bytes **SHA256** tag instead. Therefore this cipher requires 16, 48 or 80 reserved bytes per database page (since the number of reserved bytes is rounded to the next multiple of the AES block size of 16 bytes).

The following table lists all parameters related to this cipher that can be set before activating database encryption. The columns labelled **v4**, **v3**, **v2**, and **v1** show the parameter values used in legacy SQLCipher versions **3**, **2**, and **1** respectively. To access databases encrypted with the respective SQLCipher version the listed parameters have to be set explicitly.

| Parameter               | Default | v4     | v3    | v2    | v1     | Min   | Max   | Description |
| :---                    | :---:   | :---:  | :---: | :---: | :---:  | :---: | :---: | :--- |
| `kdf_iter`              | 256000  | 256000 | 64000 | 4000  | 4000   | 1     |       | Number of iterations for key derivation |
| `fast_kdf_iter`         | 2       | 2      | 2     | 2     | 2      | 1     |       | Number of iterations for HMAC key derivation |
| `hmac_use`              | 1       | 1      | 1     | 1     | 0      | 0     | 1     | Flag whether a HMAC should be used |
| `hmac_pgno`             | 1       | 1      | 1     | 1     | n/a    | 0     | 2     | Storage type for page number in HMAC:<br/>0 = native, 1 = little endian, 2 = big endian|
| `hmac_salt_mask`        | 0x3a    | 0x3a   | 0x3a  | 0x3a  | n/a    | 0     | 255   | Mask byte for HMAC salt |
| `legacy`                | 0       | 4      | 3     | 2     | 1      | 0     | 4     | SQLCipher version to be used in legacy mode |
| `legacy_page_size`      | 4096    | 4096   | 1024  | 1024  | 1024   | 0     | 65536 | Page size to use in legacy mode, 0 = default SQLite page size |
| `kdf_algorithm`         | 2       | 2      | 0     | 0     | 0      | 0     | 2     | Hash algoritm for key derivation function<br/>0 = SHA1, 1 = SHA256, 2 = SHA512 |
| `hmac_algorithm`        | 2       | 2      | 0     | 0     | 0      | 0     | 2     | Hash algoritm for HMAC calculation<br/>0 = SHA1, 1 = SHA256, 2 = SHA512 |
| `plaintext_header_size` | 0       | 0      | n/a   | n/a   | n/a    | 0     | 100   | Size of plaintext database header<br/>must be multiple of 16, i.e. 32 |

**Note**: It is not recommended to use _legacy_ mode for encrypting new databases. It is supported for compatibility reasons only, so that databases that were encrypted in _legacy_ mode can be accessed. However, the default _legacy_ mode for the various SQLCipher versions can be easily set using just the parameter `legacy` set to the requested version number. That is, all other parameters have to be specified only, if their requested value deviates from the default value.

**Note**: Version 4 of SQLCipher introduces a new parameter `plain_text_header_size` to overcome an issue with shared encrypted databases under **iOS**. If this parameter is set to a non-zero value (like 16 or 32), the corresponding number of bytes at the beginning of the database header are not encrypted allowing **iOS** to identify the file as a SQLite database file. The drawback of this approach is that the cipher salt used for the key derivation can't be stored in the database header any longer. Therefore it is necessary to retrieve the cipher salt on creating a new database, and to specify the salt on opening an existing database. The cipher salt can be retrieved with the function `wxsqlite3_codec_data` using parameter `cipher_salt`, and has to be supplied on opening a database via the database URI parameter `cipher_salt`.
