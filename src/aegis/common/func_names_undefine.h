/*
** Name:        func_names_undefine.h
** Purpose:     Undefines for AEGIS function names
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

/*
** NOTE:
** Do NOT use include guards, because including this header
** multiple times is intended behaviour.
*/

/* Undefine function name prefix */
#undef AEGIS_FUNC_PREFIX

/* Undefine all function names */
#undef AEGIS_AES_BLOCK_XOR
#undef AEGIS_AES_BLOCK_AND
#undef AEGIS_AES_BLOCK_LOAD
#undef AEGIS_AES_BLOCK_LOAD_64x2
#undef AEGIS_AES_BLOCK_STORE
#undef AEGIS_AES_ENC
#undef AEGIS_AES_BLOCK_XOR3
#undef AEGIS_AES_BLOCK_BROADCAST128
#undef AEGIS_AES_ENC0
#undef AEGIS_update_nodata
#undef AEGIS_update
#undef AEGIS_encrypt_detached
#undef AEGIS_decrypt_detached
#undef AEGIS_encrypt_unauthenticated
#undef AEGIS_decrypt_unauthenticated
#undef AEGIS_stream
#undef AEGIS_stream_xor
#undef AEGIS_state_init
#undef AEGIS_state_encrypt_update
#undef AEGIS_state_encrypt_final
#undef AEGIS_state_decrypt_update
#undef AEGIS_state_decrypt_final
#undef AEGIS_state_mac_init
#undef AEGIS_state_mac_update
#undef AEGIS_state_mac_final
#undef AEGIS_state_mac_reset
#undef AEGIS_state_mac_clone
#undef AEGIS_state_mac_verify
