## <a name="cipher_chacha20"/>sqleet: ChaCha20 - Poly1305 HMAC

This cipher was introduced for SQLite database encryption by the project [sqleet](https://github.com/resilar/sqleet) in 2017.

The Internet Engineering Task Force (IETF) officially standardized the cipher algorithm **ChaCha20** and the message authentication code **Poly1305** in [RFC 7905](https://tools.ietf.org/html/rfc7905) for Transport Layer Security (TLS).

The new default **wxSQLite3** cipher is **ChaCha20 - Poly1305**.

The encryption key is derived from the passphrase using a random salt (stored in the first 16 bytes of the database file) and the standardized PBKDF2 algorithm with an SHA256 hash function.

One-time keys per database page are derived from the encryption key, the page number, and a 16 bytes nonce. Additionally, a 16 bytes **Poly1305** authentication tag per database page is calculated. Therefore this cipher requires 32 reserved bytes per database page.

The following table lists all parameters related to this cipher that can be set before activating database encryption.

| Parameter | Default | sqleet | Min | Max | Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `kdf_iter` | 64007 | 12345 | 1 | | Number of iterations for the key derivation function |
| `legacy` | 0 | 1 | 0 | 1 | Boolean flag whether the legacy mode should be used |
| `legacy_page_size` | 4096 | 4096 | 0 | 65536 | Page size to use in legacy mode, 0 = default SQLite page size |

**Note**: It is not recommended to use _legacy_ mode for encrypting new databases. It is supported for compatibility reasons only, so that databases that were encrypted in _legacy_ mode can be accessed.
