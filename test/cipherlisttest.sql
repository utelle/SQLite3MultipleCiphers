-- Test of the PRAGMA cipher with parameter list: PRAGMA cipher='name{param=value,...}'
-- Run with: sqlite3mc_shell :memory: < test/cipherlisttest.sql
-- The expected result is given in the comments. Lines with "Result: Error" are expected to fail,
-- nothing is changed by such a statement.

-- Result: sqlcipher, 123456, 4096, 2
-- (the preset 'legacy' is applied first, so that the individual value 'kdf_iter' wins)
PRAGMA cipher='sqlcipher{kdf_iter=123456, legacy=4}';
PRAGMA kdf_iter;
PRAGMA legacy_page_size;
PRAGMA hmac_algorithm;

-- Result: sqlcipher, 777, 1024
PRAGMA cipher='sqlcipher{legacy=2, kdf_iter=777}';
PRAGMA kdf_iter;
PRAGMA legacy_page_size;

-- Blanks are ignored, the list can be empty
-- Result: chacha20, 1000, chacha20
PRAGMA cipher=' chacha20 { kdf_iter = 1000 } ';
PRAGMA kdf_iter;
PRAGMA cipher='chacha20{}';

-- Aliases can be used as values
-- Result: aegis, aegis-256x2
PRAGMA cipher='aegis{algorithm=aegis-256x2}';
PRAGMA algorithm;

-- Values in single quotes
-- Result: sqlcipher, 5
PRAGMA cipher='sqlcipher{kdf_iter=''5''}';
PRAGMA kdf_iter;

-- Invalid values are errors; nothing is changed, not even the valid entries before the invalid one
-- Result: Error (not an alias)
PRAGMA cipher='aegis{algorithm=bogus}';
-- Result: Error (out of range)
PRAGMA cipher='sqlcipher{kdf_iter=0}';
PRAGMA cipher='sqlcipher{legacy=9}';
-- Result: Error (malformed number, unknown alias)
PRAGMA cipher='sqlcipher{kdf_iter=abc}';
PRAGMA cipher='sqlcipher{kdf_iter=99,hmac_algorithm=sha999}';
-- Result: Error (constraint)
PRAGMA cipher='sqlcipher{plaintext_header_size=7}';

-- Only parameters of the specified cipher scheme are accepted
-- Result: Error (common parameters, cipher, parameter of another cipher scheme, unknown parameter)
PRAGMA cipher='sqlcipher{hmac_check=0}';
PRAGMA cipher='sqlcipher{encrypt_temp_db=1}';
PRAGMA cipher='sqlcipher{cipher=aegis}';
PRAGMA cipher='sqlcipher{algorithm=aegis-256}';
PRAGMA cipher='sqlcipher{nonexistent=5}';

-- Structure of the list
-- Result: Error (missing closing brace, missing '=', missing value, missing parameter name,
-- comma at the end, characters behind the closing brace, missing cipher name, unknown cipher)
PRAGMA cipher='sqlcipher{kdf_iter=5';
PRAGMA cipher='sqlcipher{kdf_iter}';
PRAGMA cipher='sqlcipher{kdf_iter=}';
PRAGMA cipher='sqlcipher{=5}';
PRAGMA cipher='sqlcipher{kdf_iter=5,}';
PRAGMA cipher='sqlcipher{kdf_iter=5}x';
PRAGMA cipher='{kdf_iter=5}';
PRAGMA cipher='nonexistent{kdf_iter=5}';

-- After all failed statements nothing has changed
-- Result: sqlcipher, 5
PRAGMA cipher;
PRAGMA kdf_iter;

-- Other schemas: only the current value is changed, the default value remains
-- Result: chacha20, 2222, 1000 (the main database now resolves 'kdf_iter' via the current cipher chacha20,
-- whose default kdf_iter was set to 1000 above)
PRAGMA temp.cipher='chacha20{kdf_iter=2222}';
PRAGMA temp.kdf_iter;
PRAGMA main.kdf_iter;

-- The parameter list is only accepted for the PRAGMA cipher
-- Result: 1 (a PRAGMA of another parameter treats the value as usual, the invalid value is logged)
PRAGMA hmac_check='x{1}';
