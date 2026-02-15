---
layout: default
title: Plaintext header
parent: Supported Ciphers
nav_order: 9
---
## <a name="plaintext_header" /> Plaintext database header

On **iOS** there exists an issue with encrypted databases, if they are stored in a shared container. **iOS** identifies SQLite database files by inspecting certain bytes in the database header. However, several cipher schemes, namely [ChaCha20]({{ site.baseurl }}{% link docs/ciphers/cipher_chacha20.md %}), [SQLCipher]({{ site.baseurl }}{% link docs/ciphers/cipher_sqlcipher.md %}), [Ascon]({{ site.baseurl }}{% link docs/ciphers/cipher_ascon.md %}), and [AEGIS]({{ site.baseurl }}{% link docs/ciphers/cipher_aegis.md %}), save a cipher salt value used in the key derivation process in the first 16 bytes of the database header, and usually encrypt the database header, too. This prevents **iOS** from identifying, and therefore **iOS** will kill the application process when it tries to maintain a file lock on the database  while it is in the background.

To avoid problems on **iOS** it is necessary to leave the database header unencrypted - at least partially. For this purpose the parameter `plaintext_header_size` was introduced to exclude a specified number of bytes of the database header unencrypted.

The drawback of this approach is that the cipher salt used for the key derivation can't be stored in the database header any longer. Therefore it is necessary to retrieve the cipher salt on creating a new database, and to specify the salt on opening an existing database. In **SQLite3 Multiple Ciphers** the cipher salt can be retrieved with the function `sqlite3mc_codec_data` using parameter `cipher_salt`, and has to be supplied on opening a database via the database URI parameter `cipher_salt`. Alternatively, the SQL command `PRAGMA cipher_salt` can be used for that purpose.

**Note**
{: .label .label-red .ml-0 .mb-1 .mt-2 }
Some developers prefer to use raw key and salt material under **iOS**. In this case, an application would provide the key and salt material via a specially formatted key value via `PRAGMA key`.
While specifying raw key **and** salt material is required for the cipher scheme _SQLCipher_, it is sufficient to specify just the key material for the cipher schemes _ChaCha20_, _Ascon_, and _AEGIS_, because they use the salt only for the key derivation process (which doesn't take place, when raw key material is provided). Thus, for the latter cipher schemes retrieving and specifying the cipher salt isn't required at all, when using raw key material. 
