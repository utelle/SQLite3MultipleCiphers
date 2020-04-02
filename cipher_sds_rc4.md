## <a name="cipher_rc4"/> System.Data.SQLite: RC4 - No HMAC

This cipher is included with [System.Data.SQLite](https://system.data.sqlite.org), an ADO.NET provider for SQLite. It provides a 128 bit RC4 encryption. This encryption scheme had been added to **wxSQLite3** in early 2020 to allow cross-platform access to databases created with _System.Data.SQLite_ based applications. **SQLite3MultipleCiphers** continues to support this cipher for compatibility reasons only.

The encryption key is derived from the passphrase using an SHA1 hash function.

The cipher does not use a _Hash Message Authentication Code_ (HMAC), and requires therefore no reserved bytes per database page.

The following table lists all parameters related to this cipher that can be set before activating database encryption.

| Parameter | Default | Min | Max | Description |
| :--- | :---: | :---: | :---: | :--- |
| `legacy` | 1 | 1 | 1 | Boolean flag whether the legacy mode should be used |
| `legacy_page_size` | 0 | 0 | 65536 | Page size to use in legacy mode, 0 = default SQLite page size |

**Note**: Currently no non-legacy mode is implemented and it is not intended to implement one in the future, because RC4 encryption has known weaknesses (for example, the use of RC4 in TLS was prohibited by RFC 7465 published in February 2015). **The use of this cipher scheme for new applications is strongly discouraged.**
