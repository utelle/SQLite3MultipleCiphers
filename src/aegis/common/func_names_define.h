/*
** Name:        func_names_define.h
** Purpose:     Defines for AEGIS function names
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

/*
** NOTE:
** Do NOT use include guards, because including this header
** multiple times is intended behaviour.
*/

#define AEGIS_AES_BLOCK_XOR                 AEGIS_FUNC(aes_block_xor)
#define AEGIS_AES_BLOCK_AND                 AEGIS_FUNC(aes_block_and)
#define AEGIS_AES_BLOCK_LOAD                AEGIS_FUNC(aes_block_load)
#define AEGIS_AES_BLOCK_LOAD_64x2           AEGIS_FUNC(aes_block_load_64x2)
#define AEGIS_AES_BLOCK_STORE               AEGIS_FUNC(aes_block_store)
#define AEGIS_AES_ENC                       AEGIS_FUNC(aes_enc)
#define AEGIS_AES_BLOCK_XOR3                AEGIS_FUNC(aes_block_xor3)
#define AEGIS_AES_BLOCK_BROADCAST128        AEGIS_FUNC(aes_block_broadcast128)
#define AEGIS_AES_ENC0                      AEGIS_FUNC(aes_enc0)
#define AEGIS_update_nodata                 AEGIS_FUNC(update_nodata)
#define AEGIS_update                        AEGIS_FUNC(update)
#define AEGIS_encrypt_detached              AEGIS_FUNC(encrypt_detached)
#define AEGIS_decrypt_detached              AEGIS_FUNC(decrypt_detached)
#define AEGIS_encrypt_unauthenticated       AEGIS_FUNC(encrypt_unauthenticated)
#define AEGIS_decrypt_unauthenticated       AEGIS_FUNC(decrypt_unauthenticated)
#define AEGIS_stream                        AEGIS_FUNC(stream)
#define AEGIS_stream_xor                    AEGIS_FUNC(stream_xor)
#define AEGIS_state_init                    AEGIS_FUNC(state_init)
#define AEGIS_state_encrypt_update          AEGIS_FUNC(state_encrypt_update)
#define AEGIS_state_encrypt_final           AEGIS_FUNC(state_encrypt_final)
#define AEGIS_state_decrypt_update          AEGIS_FUNC(state_decrypt_update)
#define AEGIS_state_decrypt_final           AEGIS_FUNC(state_decrypt_final)
#define AEGIS_state_mac_init                AEGIS_FUNC(state_mac_init)
#define AEGIS_state_mac_update              AEGIS_FUNC(state_mac_update)
#define AEGIS_state_mac_final               AEGIS_FUNC(state_mac_final)
#define AEGIS_state_mac_reset               AEGIS_FUNC(state_mac_reset)
#define AEGIS_state_mac_clone               AEGIS_FUNC(state_mac_clone)
#define AEGIS_state_mac_verify              AEGIS_FUNC(state_mac_verify)
