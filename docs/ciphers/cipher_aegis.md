---
layout: default
title: "AEGIS: AEGIS Family"
parent: Supported Ciphers
nav_order: 7
---
## <a name="cipher_aegis"/>AEGIS: Family of Authenticated Encryption Algorithms

[**AEGIS**](https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/draft-irtf-cfrg-aegis-aead.html) is a family of [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) and [hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function) algorithms designed for high-performance applications. It was chosen in the [CAESAR](https://en.wikipedia.org/wiki/CAESAR_Competition) (Competition for Authenticated Encryption: Security, Applicability, and Robustness) competition. A detailed description of the algorithms can be found [here](https://eprint.iacr.org/2013/695.pdf).

The _AEGIS_ implementation used in _SQLite3 Multiple Ciphers_ is based on the [Portable C implementation](https://github.com/aegis-aead/libaegis) by [Frank Denis](https://github.com/jedisct1/). The source code was adjusted to be useable in the _SQLite3 Multiple Ciphers_ amalgamation.

The _AEGIS_ cipher scheme supports the selection of all available _AEGIS_ variants: _AEGIS-128L_, _AEGIS-128X2_, _AEGIS-128X4_, _AEGIS-256_, _AEGIS-256X2_, and _AEGIS-256X4_, the default being _AEGIS-256_.

The encryption key is derived from the passphrase using a random salt (stored in the first 16 bytes of the database file) and the _key derivation_ algorithm [Argon2id](https://en.wikipedia.org/wiki/Argon2). The _Argon2_ implementation used in _SQLite3 Multiple Ciphers_ is based on the [reference C implementation of Argon2](https://github.com/p-h-c/phc-winner-argon2), that won the [Password Hashing Competition (PHC)](https://password-hashing.net/).

One-time keys per database page are derived from the encryption key, the page number, and a 16 or 32 bytes nonce - depending on the _AEGIS_ variant. Additionally, the _AEGIS_ cipher provides a 32 bytes authentication tag per database page. Therefore this cipher requires 48 or 64 reserved bytes per database page.

The following table lists all parameters related to this cipher that can be set before activating database encryption.

| Parameter   | Default | Min   | Max   | Description |
| :---        | :---:   | :---: | :---: | :---:       |
| `tcost`     | 2       | 1     |       | Number of iterations for the key derivation with Argon2id |
| `mcost`     | 19456   | 1     |       | Amount of memory in kB for key derivation with Argon2id |
| `pcost`     | 1       | 1     |       | Parallelism, number of threads for key derivation with Argon2 |
| `algorithm` | 4       | 1     | 6     | AEGIS variant to be used for page encryption |
| `plaintext_header_size` | 0 | 0 | 100 | Size of plaintext database header<br/>must be a multiple of 16, i.e. 32 |

**Notes**
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- The default values were chosen based on the [OWASP](https://owasp.ord)(Open Web Application Security Project) recommendations as listed on the [Argon2](https://en.wikipedia.org/wiki/Argon2) WikiPedia web page under the heading _Recommended minimum parameters_.
- Each combination of parameter values leads to different encryption and authentication tag values. If databases need to be compatible across different platforms and devices, the parameter values should be chosen with care. For example, _iOS_ restricts memory use to about 47 MB, so that choosing a value greater than `47 x 1024` (= `48128`) for `mcost` can cause errors.
- Any of the available algorithms can be chosen on any platform. If hardware support is available, it will be used to accelerate the encryption process, but a software implementation will be used where hardware support is lacking.

**Note**
{: .label .label-red .ml-0 .mb-1 .mt-2 }

When specifying the `algorithm` via `PRAGMA` or as an URI parameter, the value can be specified as a _number_ or as a _string_ according to the following table:

| Index | Name          | Description |
| :---: | :---          | :--- |
| 1     | `aegis-128l`  | 128-bit key, a 128-bit nonce, 128-bit register |
| 2     | `aegis-128x2` | 128-bit key, a 128-bit nonce, 256-bit register |
| 3     | `aegis-128x4` | 128-bit key, a 128-bit nonce, 512-bit register |
| 4     | `aegis-256`   | 256-bit key, a 256-bit nonce, 128-bit register (default) |
| 5     | `aegis-256x2` | 256-bit key, a 256-bit nonce, 256-bit register |
| 6     | `aegis-256x4` | 256-bit key, a 256-bit nonce, 512-bit register |

<span class="label label-green">Example:</span> Setup for _AEGIS_ cipher scheme

```sql
PRAGMA cipher = 'aegis';
PRAGMA algorithm = 'aegis-256x2';
PRAGMA key='<passphrase>';
```
