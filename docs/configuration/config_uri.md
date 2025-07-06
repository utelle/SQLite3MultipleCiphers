---
layout: default
title: URI Parameters
parent: Cipher configuration
nav_order: 3
---
## URI Parameters

SQLite3 allows to specify database file names as [SQLite Uniform Resource Identifiers](https://www.sqlite.org/uri.html) on opening or attaching databases. The advantage of using a URI file name is that query parameters on the URI can be used to control details of the newly created database connection. **SQLite3 Multiple Ciphers** allows to configure the encryption cipher via URI query parameters.

| URI Parameter | Description |
| :--- | :--- |
| `cipher`=_cipher name_ | The `cipher` query parameter specifies which cipher should be used. It has to be the identifier name of one of the supported ciphers. |
| `key`=_passphrase_ | The `key` query parameter allows to specify the passphrase used to initialize the encryption extension for the database connection. If the query string does not contain a `cipher` parameter, the default cipher selected at compile time is used. |
| `hexkey`=_hex-passphrase_ | The `hexkey` query parameter allows to specify a hexadecimal encoded passphrase used to initialize the encryption extension for the database connection. If the query string does not contain a `cipher` parameter, the default cipher selected at compile time is used. |

Depending on the cipher selected via the `cipher` parameter, additional query parameters can be used to configure the encryption extension. All parameters as described for each supported cipher (like `legacy`, `kdf_iter`, and so on) can be used to modify the cipher configuration; the order of parameters does not matter. Default values are used for all cipher parameters which are not explicitly added to the URI query string. Misspelled or unknown parameters are silently ignored.

Notes
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- The URI query parameters `key` and `hexkey` were detected and applied by the SQLite3 library itself up to and including version 3.31.1; since version 3.32.0 these parameters are handled by the encryption extension.
- If either the URI query parameter `key` or `hexkey` is used and if it is not intended to use the default cipher, then the `cipher` query parameter and optionally further cipher configuration parameters have to be given in the URI query string as well. 
- For security reasons it is not recommended to use the URI query parameter `key` or `hexkey`, because the passphrase is visible in memory for the whole duration of the database connection.
- The URI query parameters `key` or `hexkey` are respected on **opening** a database, and on **attaching** a database. However, if the keyword `KEY` of the SQL command `ATTACH` is used on attaching a database, the value after the keyword `KEY` will take precedence over the URI parameters.
- If query parameters are used to configure the encryption extension, the `cipher` query parameter is mandatory for _all_ **non-default** ciphers; it is optional for the default cipher, but it is recommended to always specify the cipher. If this parameter specifies an unknown cipher, all other cipher configuration parameters are silently ignored, and the default cipher as selected at compile time will be used.
- On **opening** a database all cipher configuration parameters given in the URI query string are used to set the **default** cipher configuration of the database connection. On **attaching** a database the cipher configuration parameters given in the URI query string will be used for the attached database, but will not change the defaults of the main database connection.

<span class="label label-green">Example:</span> URI query string to select the _legacy_ SQLCipher Version 2 encryption scheme

```
file:databasefile?cipher=sqlcipher&legacy=1&kdf_iter=4000
```
