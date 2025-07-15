---
layout: default
title: "Ascon: Ascon-128 v1.2"
parent: Supported Ciphers
nav_order: 6
---
## <a name="cipher_ascon128"/>Ascon: Ascon-128 v1.2

[**Ascon**](https://ascon.iaik.tugraz.at/) is a family of [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) and [hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function) algorithms designed to be lightweight and easy to implement, even with added countermeasures against side-channel attacks. _Ascon_ has been [selected as new standard](https://csrc.nist.gov/News/2023/lightweight-cryptography-nist-selects-ascon) for [lightweight cryptography](https://csrc.nist.gov/projects/lightweight-cryptography) in the [NIST Lightweight Cryptography competition (2019–2023)](https://csrc.nist.gov/projects/lightweight-cryptography/finalists).

The _Ascon-128_ implementation used in _SQLite3 Multiple Ciphers_ is based on the [Ascon reference implementation](https://github.com/ascon/ascon-c) and its variants optimized for 32- resp. 64-bit architectures - with minor modifications of the API for the use in this project.

The encryption key is derived from the passphrase using a random salt (stored in the first 16 bytes of the database file) and the (not yet) standardized PBKDF2 algorithm with an Ascon-derived hash function. The implementation of this PBKDF2 function is based on the information contained in the paper [_Additional Modes for Ascon, Version 1.1_](https://eprint.iacr.org/2023/391) by _Rhys Weatherley_.

One-time keys per database page are derived from the encryption key, the page number, and a 16 bytes nonce. Additionally, the _Ascon_ cipher provides a 16 bytes authentication tag per database page. Therefore this cipher requires 32 reserved bytes per database page.

The following table lists all parameters related to this cipher that can be set before activating database encryption.

| Parameter | Default | Min   | Max   | Description |
| :---      | :---:   | :---: | :---: | :---        |
| `kdf_iter` | 64007 | 1 | | Number of iterations for the key derivation function |
| `plaintext_header_size` | 0 | 0 | 100 | Size of plaintext database header<br/>(see note) |

**Note**
{: .label .label-red .ml-0 .mb-1 .mt-2 }
- If the _plaintext_header_size_ is > 0, then values between 1 and 23 will be interpreted as 24.
