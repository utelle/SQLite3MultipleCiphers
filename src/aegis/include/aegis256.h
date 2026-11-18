/*
** Name:        aegis256.h
** Purpose:     Header for AEGIS-256 API
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

#ifndef AEGIS256_H
#define AEGIS256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The length of an AEGIS key, in bytes */
#define aegis256_KEYBYTES 32

/* The length of an AEGIS nonce, in bytes */
#define aegis256_NPUBBYTES 32

/* The minimum length of an AEGIS authentication tag, in bytes */
#define aegis256_ABYTES_MIN 16

/* The maximum length of an AEGIS authentication tag, in bytes */
#define aegis256_ABYTES_MAX 32

/*
 * Maximum number of leftover bytes at finalization (always 0).
 * This constant is kept for backwards compatibility but is no longer needed
 * since update functions now output data immediately without buffering.
 */
#define aegis256_TAILBYTES_MAX 15

/* An AEGIS state, for incremental updates */
typedef struct aegis256_state {
    uint8_t opaque[192];
} aegis256_state;

/* An AEGIS state, only for MAC updates */
typedef struct aegis256_mac_state {
    uint8_t opaque[288];
} aegis256_mac_state;

/* The length of an AEGIS key, in bytes */
AEGIS_API
size_t aegis256_keybytes(void);

/* The length of an AEGIS nonce, in bytes */
AEGIS_API
size_t aegis256_npubbytes(void);

/* The minimum length of an AEGIS authentication tag, in bytes */
AEGIS_API
size_t aegis256_abytes_min(void);

/* The maximum length of an AEGIS authentication tag, in bytes */
AEGIS_API
size_t aegis256_abytes_max(void);

/*
 * Maximum number of leftover bytes at finalization (always 0).
 * This function is kept for backwards compatibility but always returns 15.
 * Update functions now output data immediately without buffering.
 */
AEGIS_API
size_t aegis256_tailbytes_max(void);

/*
 * Encrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext separately.
 *
 * c: ciphertext output buffer
 * mac: authentication tag output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
AEGIS_API
int aegis256_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                              size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                              const uint8_t *k);

/*
 * Decrypt a message with AEGIS in one shot mode with a detached tag.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * mac: authentication tag input buffer
 * maclen: length of the authentication tag (16 or 32)
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 *
 * Returns 0 if the ciphertext is authentic, -1 otherwise.
 */
AEGIS_API
AEGIS_WARN_UNUSED_RESULT
int aegis256_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                              size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                              const uint8_t *k);

/*
 * Encrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext together.
 *
 * c: ciphertext output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
AEGIS_API
int aegis256_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                     size_t adlen, const uint8_t *npub, const uint8_t *k);

/*
 * Decrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext together.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * maclen: length of the authentication tag (16 or 32)
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 *
 * Returns 0 if the ciphertext is authentic, -1 otherwise.
 */
AEGIS_API
AEGIS_WARN_UNUSED_RESULT
int aegis256_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                     size_t adlen, const uint8_t *npub, const uint8_t *k);

#ifndef AEGIS_OMIT_INCREMENTAL

/*
 * Initialize a state for incremental encryption or decryption.
 *
 * st_: state to initialize
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
AEGIS_API
void aegis256_state_init(aegis256_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                         const uint8_t *k);

/*
 * Encrypt a message chunk.
 * The same function can be used regardless of whether the tag will be attached or not.
 *
 * st_: state to update
 * c: ciphertext output buffer (must be at least mlen bytes)
 * m: plaintext input buffer
 * mlen: length of the plaintext
 *
 * Return 0 on success, -1 on failure.
 */
AEGIS_API
int aegis256_state_encrypt_update(aegis256_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);

/*
 * Finalize the incremental encryption and generate the authentication tag.
 *
 * st_: state to finalize
 * mac: output buffer for the authentication tag
 * maclen: length of the authentication tag to generate (16 or 32)
 *
 * Return 0 on success, -1 on failure.
 */
AEGIS_API
int aegis256_state_encrypt_final(aegis256_state *st_, uint8_t *mac, size_t maclen);

/*
 * Decrypt a message chunk.
 *
 * The decrypted message must not be used until state_decrypt_final() has been
 * called and returns successfully.
 *
 * st_: state to update
 * m: plaintext output buffer (must be at least clen bytes)
 * c: ciphertext chunk input buffer
 * clen: length of the ciphertext chunk
 *
 * Return 0 on success, -1 on failure.
 */
AEGIS_API
AEGIS_WARN_UNUSED_RESULT
int aegis256_state_decrypt_update(aegis256_state *st_, uint8_t *m, const uint8_t *c, size_t clen);

/*
 * Finalize the incremental decryption and verify the authentication tag.
 *
 * This function verifies the authentication tag. It must be called after all
 * decryption updates, and the decrypted message must not be used until this
 * function returns successfully.
 *
 * st_: state to finalize
 * mac: authentication tag input buffer
 * maclen: length of the authentication tag (16 or 32)
 *
 * Return 0 if the tag is valid, -1 otherwise.
 */
AEGIS_API
AEGIS_WARN_UNUSED_RESULT
int aegis256_state_decrypt_final(aegis256_state *st_, const uint8_t *mac, size_t maclen);

#endif /* AEGIS_OMIT_INCREMENTAL */

/*
 * Return a deterministic pseudo-random byte sequence.
 *
 * out: output buffer
 * len: number of bytes to generate
 * npub: nonce input buffer (32 bytes) - Can be set to `NULL` if only one sequence has to be
 * generated from a given key.
 * k: key input buffer (32 bytes)
 */
AEGIS_API
void aegis256_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);

/*
 * Encrypt or decrypt a message WITHOUT AUTHENTICATION, by XORing it with the output of
 * aegis256_stream().
 *
 * Only use this if your protocol authenticates the data some other way. Never reuse a nonce with
 * the same key. Don't share a key and nonce with other functions in this library either.
 *
 * out: output buffer (can be the same as `in`)
 * in: input buffer
 * len: length of the input
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
AEGIS_API
void aegis256_stream_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t *npub,
                         const uint8_t *k);

/*
 * Encrypt a message WITHOUT AUTHENTICATION, similar to AES-CTR.
 *
 * DEPRECATED: use aegis256_stream_xor() in new code. Its output is different, so only keep this for
 * existing data.
 *
 * WARNING: this is an insecure mode of operation, provided for compatibility with specific
 * protocols that bring their own authentication scheme.
 *
 * c: ciphertext output buffer
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
AEGIS_API
AEGIS_DEPRECATED("use aegis256_stream_xor() in new code; its output is different")
void aegis256_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen,
                                      const uint8_t *npub, const uint8_t *k);

/*
 * Decrypt a message WITHOUT AUTHENTICATION, similar to AES-CTR.
 *
 * DEPRECATED: use aegis256_stream_xor() in new code. Only keep this to decrypt data from
 * aegis256_encrypt_unauthenticated().
 *
 * WARNING: this is an insecure mode of operation, provided for compatibility with specific
 * protocols that bring their own authentication scheme.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * npub: nonce input buffer (32 bytes)
 * k: key input buffer (32 bytes)
 */
AEGIS_API
AEGIS_DEPRECATED("use aegis256_stream_xor() in new code; its output is different")
void aegis256_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen,
                                      const uint8_t *npub, const uint8_t *k);

#ifndef AEGIS_OMIT_MAC_API

/*
 * Initialize a state for generating a MAC.
 *
 * st_: state to initialize
 * k: key input buffer (32 bytes)
 * npub: nonce input buffer (32 bytes) - Can be set to `NULL` to use an all-zero nonce
 *
 * - The same key MUST NOT be used both for MAC and encryption.
 * - If the key is secret, the MAC is secure against forgery.
 * - However, if the key is known, arbitrary inputs matching a tag can be efficiently computed.
 *
 * The recommended way to use the MAC mode is to generate a random key and keep it secret.
 *
 * After initialization, the state can be reused to generate multiple MACs by cloning it
 * with `aegis256_mac_state_clone()`. It is only safe to copy a state directly without using
 * the clone function if the state is guaranteed to be properly aligned.
 *
 * A state can also be reset for reuse without cloning with `aegis256_mac_reset()`.
 */
AEGIS_API
void aegis256_mac_init(aegis256_mac_state *st_, const uint8_t *k, const uint8_t *npub);

/*
 * Update the MAC state with input data.
 *
 * st_: state to update
 * m: input data
 * mlen: length of the input data
 *
 * This function can be called multiple times.
 *
 * Once the full input has been absorbed, call either `_mac_final` or `_mac_verify`.
 */
AEGIS_API
int aegis256_mac_update(aegis256_mac_state *st_, const uint8_t *m, size_t mlen);

/*
 * Finalize the MAC and generate the authentication tag.
 *
 * st_: state to finalize
 * mac: authentication tag output buffer
 * maclen: length of the authentication tag to generate (16 or 32. 32 is recommended).
 */
AEGIS_API
int aegis256_mac_final(aegis256_mac_state *st_, uint8_t *mac, size_t maclen);

/*
 * Verify a MAC in constant time.
 *
 * st_: state to verify
 * mac: authentication tag to verify
 * maclen: length of the authentication tag (16 or 32)
 *
 * Returns 0 if the tag is authentic, -1 otherwise.
 */
AEGIS_API
int aegis256_mac_verify(aegis256_mac_state *st_, const uint8_t *mac, size_t maclen);

/*
 * Reset an AEGIS-MAC state.
 */
AEGIS_API
void aegis256_mac_reset(aegis256_mac_state *st_);

/*
 * Clone an AEGIS-MAC state.
 *
 * dst: destination state
 * src: source state
 *
 * This function MUST be used in order to clone states.
 */
AEGIS_API
void aegis256_mac_state_clone(aegis256_mac_state *dst, const aegis256_mac_state *src);

#endif /* AEGIS_OMIT_MAC_API */

#ifdef __cplusplus
}
#endif

#endif /* AEGIS256_H */
