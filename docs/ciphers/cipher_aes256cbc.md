---
layout: default
title: "wxSQLite3: AES 256 Bit"
parent: Supported Ciphers
nav_order: 2
---
## <a name="cipher_aes256cbc"/>wxSQLite3: AES 256 Bit

This cipher was added to [wxSQLite3](https://github.com/utelle/wxsqlite3) in 2010. It is a 256 bit AES encryption in CBC mode.

The encryption key is derived from the passphrase using an SHA256 hash function.

The initial vector for the encryption of each database page is derived from the page number.

The cipher does not use a _Hash Message Authentication Code_ (HMAC), and requires therefore no reserved bytes per database page.

The following table lists all parameters related to this cipher that can be set before activating database encryption.

| Parameter | Default | Min | Max | Description |
| :--- | :---: | :---: | :---: | :--- |
| `kdf_iter` | 4001 | 1 | | Number of iterations for the key derivation function
| `legacy` | 0 | 0 | 1 | Boolean flag whether the legacy mode should be used |
| `legacy_page_size` | 0 | 0 | 65536 | Page size to use in legacy mode, 0 = default SQLite page size |

**Note**
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- It is not recommended to use [_legacy_ mode](/ciphers/cipher_legacy_mode.md) for encrypting new databases. It is supported for compatibility reasons only, so that databases that were encrypted in _legacy_ mode can be accessed.
