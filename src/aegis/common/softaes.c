/*
** Name:        softaes.c
** Purpose:     Implementation of AES via software
** Copyright:   (c) 2023-2024 Frank Denis
** SPDX-License-Identifier: MIT
*/

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "softaes.h"

#ifdef SOFTAES_SIMD128

/* Keep these tables mutable and visible so LLVM preserves the faster loads. */
CRYPTO_ALIGN(64)
uint8_t libaegis_softaes_simd_tables[SOFTAES_TBL_COUNT][16] = {
    [SOFTAES_TBL_IPT_LO] = { 0x00, 0x70, 0x2a, 0x5a, 0x98, 0xe8, 0xb2, 0xc2, 0x08, 0x78, 0x22, 0x52,
                             0x90, 0xe0, 0xba, 0xca },
    [SOFTAES_TBL_IPT_HI] = { 0x00, 0x4d, 0x7c, 0x31, 0x7d, 0x30, 0x01, 0x4c, 0x81, 0xcc, 0xfd, 0xb0,
                             0xfc, 0xb1, 0x80, 0xcd },
    [SOFTAES_TBL_INV]    = { 0x80, 0x01, 0x08, 0x0d, 0x0f, 0x06, 0x05, 0x0e, 0x02, 0x0c, 0x0b, 0x0a,
                             0x09, 0x03, 0x07, 0x04 },
    [SOFTAES_TBL_INVA]   = { 0x80, 0x07, 0x0b, 0x0f, 0x06, 0x0a, 0x04, 0x01, 0x09, 0x08, 0x05, 0x02,
                             0x0c, 0x0e, 0x0d, 0x03 },
    [SOFTAES_TBL_SBO_U]  = { 0x00, 0xc7, 0xbd, 0x6f, 0x17, 0x6d, 0xd2, 0xd0, 0x78, 0xa8, 0x02, 0xc5,
                             0x7a, 0xbf, 0xaa, 0x15 },
    [SOFTAES_TBL_SBO_T]  = { 0x00, 0x6a, 0xbb, 0x5f, 0xa5, 0x74, 0xe4, 0xcf, 0xfa, 0x35, 0x2b, 0x41,
                             0xd1, 0x90, 0x1e, 0x8e },
    /* Precompute doubled S-box outputs for MixColumns. */
    [SOFTAES_TBL_SBO2_U] = { 0x00, 0x95, 0x61, 0xde, 0x2e, 0xda, 0xbf, 0xbb, 0xf0, 0x4b, 0x04, 0x91,
                             0xf4, 0x65, 0x4f, 0x2a },
    [SOFTAES_TBL_SBO2_T] = { 0x00, 0xd4, 0x6d, 0xbe, 0x51, 0xe8, 0xd3, 0x85, 0xef, 0x6a, 0x56, 0x82,
                             0xb9, 0x3b, 0x3c, 0x07 },
    /* Combine ShiftRows with each MixColumns rotation. */
    [SOFTAES_TBL_MC0] = { 0x00, 0x05, 0x0a, 0x0f, 0x04, 0x09, 0x0e, 0x03, 0x08, 0x0d, 0x02, 0x07,
                          0x0c, 0x01, 0x06, 0x0b },
    [SOFTAES_TBL_MC1] = { 0x05, 0x0a, 0x0f, 0x00, 0x09, 0x0e, 0x03, 0x04, 0x0d, 0x02, 0x07, 0x08,
                          0x01, 0x06, 0x0b, 0x0c },
    [SOFTAES_TBL_MC2] = { 0x0a, 0x0f, 0x00, 0x05, 0x0e, 0x03, 0x04, 0x09, 0x02, 0x07, 0x08, 0x0d,
                          0x06, 0x0b, 0x0c, 0x01 },
    [SOFTAES_TBL_MC3] = { 0x0f, 0x00, 0x05, 0x0a, 0x03, 0x04, 0x09, 0x0e, 0x07, 0x08, 0x0d, 0x02,
                          0x0b, 0x0c, 0x01, 0x06 },
    [SOFTAES_TBL_S0F] = { 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
                          0x0f, 0x0f, 0x0f, 0x0f },
    [SOFTAES_TBL_C63] = { 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
                          0x63, 0x63, 0x63, 0x63 },
};

#else

#    if defined(__wasm__) && !defined(FAVOR_PERFORMANCE)
#        define FAVOR_PERFORMANCE
#    endif

#    ifdef FAVOR_PERFORMANCE
static const uint32_t _aes_lut[1024] = {
    0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591,
    0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec,
    0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa, 0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb,
    0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b,
    0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
    0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9, 0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
    0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f,
    0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df, 0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea,
    0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
    0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d, 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
    0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6,
    0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
    0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed, 0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511,
    0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe, 0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b,
    0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
    0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf,
    0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3, 0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e,
    0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a, 0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
    0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b,
    0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428, 0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
    0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, 0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8,
    0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2,
    0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda, 0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949,
    0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
    0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c, 0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
    0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e, 0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f,
    0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c,
    0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969, 0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27,
    0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122, 0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433,
    0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
    0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0,
    0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e, 0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c,
    0x6363c6a5, 0x7c7cf884, 0x7777ee99, 0x7b7bf68d, 0xf2f2ff0d, 0x6b6bd6bd, 0x6f6fdeb1, 0xc5c59154,
    0x30306050, 0x01010203, 0x6767cea9, 0x2b2b567d, 0xfefee719, 0xd7d7b562, 0xabab4de6, 0x7676ec9a,
    0xcaca8f45, 0x82821f9d, 0xc9c98940, 0x7d7dfa87, 0xfafaef15, 0x5959b2eb, 0x47478ec9, 0xf0f0fb0b,
    0xadad41ec, 0xd4d4b367, 0xa2a25ffd, 0xafaf45ea, 0x9c9c23bf, 0xa4a453f7, 0x7272e496, 0xc0c09b5b,
    0xb7b775c2, 0xfdfde11c, 0x93933dae, 0x26264c6a, 0x36366c5a, 0x3f3f7e41, 0xf7f7f502, 0xcccc834f,
    0x3434685c, 0xa5a551f4, 0xe5e5d134, 0xf1f1f908, 0x7171e293, 0xd8d8ab73, 0x31316253, 0x15152a3f,
    0x0404080c, 0xc7c79552, 0x23234665, 0xc3c39d5e, 0x18183028, 0x969637a1, 0x05050a0f, 0x9a9a2fb5,
    0x07070e09, 0x12122436, 0x80801b9b, 0xe2e2df3d, 0xebebcd26, 0x27274e69, 0xb2b27fcd, 0x7575ea9f,
    0x0909121b, 0x83831d9e, 0x2c2c5874, 0x1a1a342e, 0x1b1b362d, 0x6e6edcb2, 0x5a5ab4ee, 0xa0a05bfb,
    0x5252a4f6, 0x3b3b764d, 0xd6d6b761, 0xb3b37dce, 0x2929527b, 0xe3e3dd3e, 0x2f2f5e71, 0x84841397,
    0x5353a6f5, 0xd1d1b968, 0x00000000, 0xededc12c, 0x20204060, 0xfcfce31f, 0xb1b179c8, 0x5b5bb6ed,
    0x6a6ad4be, 0xcbcb8d46, 0xbebe67d9, 0x3939724b, 0x4a4a94de, 0x4c4c98d4, 0x5858b0e8, 0xcfcf854a,
    0xd0d0bb6b, 0xefefc52a, 0xaaaa4fe5, 0xfbfbed16, 0x434386c5, 0x4d4d9ad7, 0x33336655, 0x85851194,
    0x45458acf, 0xf9f9e910, 0x02020406, 0x7f7ffe81, 0x5050a0f0, 0x3c3c7844, 0x9f9f25ba, 0xa8a84be3,
    0x5151a2f3, 0xa3a35dfe, 0x404080c0, 0x8f8f058a, 0x92923fad, 0x9d9d21bc, 0x38387048, 0xf5f5f104,
    0xbcbc63df, 0xb6b677c1, 0xdadaaf75, 0x21214263, 0x10102030, 0xffffe51a, 0xf3f3fd0e, 0xd2d2bf6d,
    0xcdcd814c, 0x0c0c1814, 0x13132635, 0xececc32f, 0x5f5fbee1, 0x979735a2, 0x444488cc, 0x17172e39,
    0xc4c49357, 0xa7a755f2, 0x7e7efc82, 0x3d3d7a47, 0x6464c8ac, 0x5d5dbae7, 0x1919322b, 0x7373e695,
    0x6060c0a0, 0x81811998, 0x4f4f9ed1, 0xdcdca37f, 0x22224466, 0x2a2a547e, 0x90903bab, 0x88880b83,
    0x46468cca, 0xeeeec729, 0xb8b86bd3, 0x1414283c, 0xdedea779, 0x5e5ebce2, 0x0b0b161d, 0xdbdbad76,
    0xe0e0db3b, 0x32326456, 0x3a3a744e, 0x0a0a141e, 0x494992db, 0x06060c0a, 0x2424486c, 0x5c5cb8e4,
    0xc2c29f5d, 0xd3d3bd6e, 0xacac43ef, 0x6262c4a6, 0x919139a8, 0x959531a4, 0xe4e4d337, 0x7979f28b,
    0xe7e7d532, 0xc8c88b43, 0x37376e59, 0x6d6ddab7, 0x8d8d018c, 0xd5d5b164, 0x4e4e9cd2, 0xa9a949e0,
    0x6c6cd8b4, 0x5656acfa, 0xf4f4f307, 0xeaeacf25, 0x6565caaf, 0x7a7af48e, 0xaeae47e9, 0x08081018,
    0xbaba6fd5, 0x7878f088, 0x25254a6f, 0x2e2e5c72, 0x1c1c3824, 0xa6a657f1, 0xb4b473c7, 0xc6c69751,
    0xe8e8cb23, 0xdddda17c, 0x7474e89c, 0x1f1f3e21, 0x4b4b96dd, 0xbdbd61dc, 0x8b8b0d86, 0x8a8a0f85,
    0x7070e090, 0x3e3e7c42, 0xb5b571c4, 0x6666ccaa, 0x484890d8, 0x03030605, 0xf6f6f701, 0x0e0e1c12,
    0x6161c2a3, 0x35356a5f, 0x5757aef9, 0xb9b969d0, 0x86861791, 0xc1c19958, 0x1d1d3a27, 0x9e9e27b9,
    0xe1e1d938, 0xf8f8eb13, 0x98982bb3, 0x11112233, 0x6969d2bb, 0xd9d9a970, 0x8e8e0789, 0x949433a7,
    0x9b9b2db6, 0x1e1e3c22, 0x87871592, 0xe9e9c920, 0xcece8749, 0x5555aaff, 0x28285078, 0xdfdfa57a,
    0x8c8c038f, 0xa1a159f8, 0x89890980, 0x0d0d1a17, 0xbfbf65da, 0xe6e6d731, 0x424284c6, 0x6868d0b8,
    0x414182c3, 0x999929b0, 0x2d2d5a77, 0x0f0f1e11, 0xb0b07bcb, 0x5454a8fc, 0xbbbb6dd6, 0x16162c3a,
    0x63c6a563, 0x7cf8847c, 0x77ee9977, 0x7bf68d7b, 0xf2ff0df2, 0x6bd6bd6b, 0x6fdeb16f, 0xc59154c5,
    0x30605030, 0x01020301, 0x67cea967, 0x2b567d2b, 0xfee719fe, 0xd7b562d7, 0xab4de6ab, 0x76ec9a76,
    0xca8f45ca, 0x821f9d82, 0xc98940c9, 0x7dfa877d, 0xfaef15fa, 0x59b2eb59, 0x478ec947, 0xf0fb0bf0,
    0xad41ecad, 0xd4b367d4, 0xa25ffda2, 0xaf45eaaf, 0x9c23bf9c, 0xa453f7a4, 0x72e49672, 0xc09b5bc0,
    0xb775c2b7, 0xfde11cfd, 0x933dae93, 0x264c6a26, 0x366c5a36, 0x3f7e413f, 0xf7f502f7, 0xcc834fcc,
    0x34685c34, 0xa551f4a5, 0xe5d134e5, 0xf1f908f1, 0x71e29371, 0xd8ab73d8, 0x31625331, 0x152a3f15,
    0x04080c04, 0xc79552c7, 0x23466523, 0xc39d5ec3, 0x18302818, 0x9637a196, 0x050a0f05, 0x9a2fb59a,
    0x070e0907, 0x12243612, 0x801b9b80, 0xe2df3de2, 0xebcd26eb, 0x274e6927, 0xb27fcdb2, 0x75ea9f75,
    0x09121b09, 0x831d9e83, 0x2c58742c, 0x1a342e1a, 0x1b362d1b, 0x6edcb26e, 0x5ab4ee5a, 0xa05bfba0,
    0x52a4f652, 0x3b764d3b, 0xd6b761d6, 0xb37dceb3, 0x29527b29, 0xe3dd3ee3, 0x2f5e712f, 0x84139784,
    0x53a6f553, 0xd1b968d1, 0x00000000, 0xedc12ced, 0x20406020, 0xfce31ffc, 0xb179c8b1, 0x5bb6ed5b,
    0x6ad4be6a, 0xcb8d46cb, 0xbe67d9be, 0x39724b39, 0x4a94de4a, 0x4c98d44c, 0x58b0e858, 0xcf854acf,
    0xd0bb6bd0, 0xefc52aef, 0xaa4fe5aa, 0xfbed16fb, 0x4386c543, 0x4d9ad74d, 0x33665533, 0x85119485,
    0x458acf45, 0xf9e910f9, 0x02040602, 0x7ffe817f, 0x50a0f050, 0x3c78443c, 0x9f25ba9f, 0xa84be3a8,
    0x51a2f351, 0xa35dfea3, 0x4080c040, 0x8f058a8f, 0x923fad92, 0x9d21bc9d, 0x38704838, 0xf5f104f5,
    0xbc63dfbc, 0xb677c1b6, 0xdaaf75da, 0x21426321, 0x10203010, 0xffe51aff, 0xf3fd0ef3, 0xd2bf6dd2,
    0xcd814ccd, 0x0c18140c, 0x13263513, 0xecc32fec, 0x5fbee15f, 0x9735a297, 0x4488cc44, 0x172e3917,
    0xc49357c4, 0xa755f2a7, 0x7efc827e, 0x3d7a473d, 0x64c8ac64, 0x5dbae75d, 0x19322b19, 0x73e69573,
    0x60c0a060, 0x81199881, 0x4f9ed14f, 0xdca37fdc, 0x22446622, 0x2a547e2a, 0x903bab90, 0x880b8388,
    0x468cca46, 0xeec729ee, 0xb86bd3b8, 0x14283c14, 0xdea779de, 0x5ebce25e, 0x0b161d0b, 0xdbad76db,
    0xe0db3be0, 0x32645632, 0x3a744e3a, 0x0a141e0a, 0x4992db49, 0x060c0a06, 0x24486c24, 0x5cb8e45c,
    0xc29f5dc2, 0xd3bd6ed3, 0xac43efac, 0x62c4a662, 0x9139a891, 0x9531a495, 0xe4d337e4, 0x79f28b79,
    0xe7d532e7, 0xc88b43c8, 0x376e5937, 0x6ddab76d, 0x8d018c8d, 0xd5b164d5, 0x4e9cd24e, 0xa949e0a9,
    0x6cd8b46c, 0x56acfa56, 0xf4f307f4, 0xeacf25ea, 0x65caaf65, 0x7af48e7a, 0xae47e9ae, 0x08101808,
    0xba6fd5ba, 0x78f08878, 0x254a6f25, 0x2e5c722e, 0x1c38241c, 0xa657f1a6, 0xb473c7b4, 0xc69751c6,
    0xe8cb23e8, 0xdda17cdd, 0x74e89c74, 0x1f3e211f, 0x4b96dd4b, 0xbd61dcbd, 0x8b0d868b, 0x8a0f858a,
    0x70e09070, 0x3e7c423e, 0xb571c4b5, 0x66ccaa66, 0x4890d848, 0x03060503, 0xf6f701f6, 0x0e1c120e,
    0x61c2a361, 0x356a5f35, 0x57aef957, 0xb969d0b9, 0x86179186, 0xc19958c1, 0x1d3a271d, 0x9e27b99e,
    0xe1d938e1, 0xf8eb13f8, 0x982bb398, 0x11223311, 0x69d2bb69, 0xd9a970d9, 0x8e07898e, 0x9433a794,
    0x9b2db69b, 0x1e3c221e, 0x87159287, 0xe9c920e9, 0xce8749ce, 0x55aaff55, 0x28507828, 0xdfa57adf,
    0x8c038f8c, 0xa159f8a1, 0x89098089, 0x0d1a170d, 0xbf65dabf, 0xe6d731e6, 0x4284c642, 0x68d0b868,
    0x4182c341, 0x9929b099, 0x2d5a772d, 0x0f1e110f, 0xb07bcbb0, 0x54a8fc54, 0xbb6dd6bb, 0x162c3a16,
    0xc6a56363, 0xf8847c7c, 0xee997777, 0xf68d7b7b, 0xff0df2f2, 0xd6bd6b6b, 0xdeb16f6f, 0x9154c5c5,
    0x60503030, 0x02030101, 0xcea96767, 0x567d2b2b, 0xe719fefe, 0xb562d7d7, 0x4de6abab, 0xec9a7676,
    0x8f45caca, 0x1f9d8282, 0x8940c9c9, 0xfa877d7d, 0xef15fafa, 0xb2eb5959, 0x8ec94747, 0xfb0bf0f0,
    0x41ecadad, 0xb367d4d4, 0x5ffda2a2, 0x45eaafaf, 0x23bf9c9c, 0x53f7a4a4, 0xe4967272, 0x9b5bc0c0,
    0x75c2b7b7, 0xe11cfdfd, 0x3dae9393, 0x4c6a2626, 0x6c5a3636, 0x7e413f3f, 0xf502f7f7, 0x834fcccc,
    0x685c3434, 0x51f4a5a5, 0xd134e5e5, 0xf908f1f1, 0xe2937171, 0xab73d8d8, 0x62533131, 0x2a3f1515,
    0x080c0404, 0x9552c7c7, 0x46652323, 0x9d5ec3c3, 0x30281818, 0x37a19696, 0x0a0f0505, 0x2fb59a9a,
    0x0e090707, 0x24361212, 0x1b9b8080, 0xdf3de2e2, 0xcd26ebeb, 0x4e692727, 0x7fcdb2b2, 0xea9f7575,
    0x121b0909, 0x1d9e8383, 0x58742c2c, 0x342e1a1a, 0x362d1b1b, 0xdcb26e6e, 0xb4ee5a5a, 0x5bfba0a0,
    0xa4f65252, 0x764d3b3b, 0xb761d6d6, 0x7dceb3b3, 0x527b2929, 0xdd3ee3e3, 0x5e712f2f, 0x13978484,
    0xa6f55353, 0xb968d1d1, 0x00000000, 0xc12ceded, 0x40602020, 0xe31ffcfc, 0x79c8b1b1, 0xb6ed5b5b,
    0xd4be6a6a, 0x8d46cbcb, 0x67d9bebe, 0x724b3939, 0x94de4a4a, 0x98d44c4c, 0xb0e85858, 0x854acfcf,
    0xbb6bd0d0, 0xc52aefef, 0x4fe5aaaa, 0xed16fbfb, 0x86c54343, 0x9ad74d4d, 0x66553333, 0x11948585,
    0x8acf4545, 0xe910f9f9, 0x04060202, 0xfe817f7f, 0xa0f05050, 0x78443c3c, 0x25ba9f9f, 0x4be3a8a8,
    0xa2f35151, 0x5dfea3a3, 0x80c04040, 0x058a8f8f, 0x3fad9292, 0x21bc9d9d, 0x70483838, 0xf104f5f5,
    0x63dfbcbc, 0x77c1b6b6, 0xaf75dada, 0x42632121, 0x20301010, 0xe51affff, 0xfd0ef3f3, 0xbf6dd2d2,
    0x814ccdcd, 0x18140c0c, 0x26351313, 0xc32fecec, 0xbee15f5f, 0x35a29797, 0x88cc4444, 0x2e391717,
    0x9357c4c4, 0x55f2a7a7, 0xfc827e7e, 0x7a473d3d, 0xc8ac6464, 0xbae75d5d, 0x322b1919, 0xe6957373,
    0xc0a06060, 0x19988181, 0x9ed14f4f, 0xa37fdcdc, 0x44662222, 0x547e2a2a, 0x3bab9090, 0x0b838888,
    0x8cca4646, 0xc729eeee, 0x6bd3b8b8, 0x283c1414, 0xa779dede, 0xbce25e5e, 0x161d0b0b, 0xad76dbdb,
    0xdb3be0e0, 0x64563232, 0x744e3a3a, 0x141e0a0a, 0x92db4949, 0x0c0a0606, 0x486c2424, 0xb8e45c5c,
    0x9f5dc2c2, 0xbd6ed3d3, 0x43efacac, 0xc4a66262, 0x39a89191, 0x31a49595, 0xd337e4e4, 0xf28b7979,
    0xd532e7e7, 0x8b43c8c8, 0x6e593737, 0xdab76d6d, 0x018c8d8d, 0xb164d5d5, 0x9cd24e4e, 0x49e0a9a9,
    0xd8b46c6c, 0xacfa5656, 0xf307f4f4, 0xcf25eaea, 0xcaaf6565, 0xf48e7a7a, 0x47e9aeae, 0x10180808,
    0x6fd5baba, 0xf0887878, 0x4a6f2525, 0x5c722e2e, 0x38241c1c, 0x57f1a6a6, 0x73c7b4b4, 0x9751c6c6,
    0xcb23e8e8, 0xa17cdddd, 0xe89c7474, 0x3e211f1f, 0x96dd4b4b, 0x61dcbdbd, 0x0d868b8b, 0x0f858a8a,
    0xe0907070, 0x7c423e3e, 0x71c4b5b5, 0xccaa6666, 0x90d84848, 0x06050303, 0xf701f6f6, 0x1c120e0e,
    0xc2a36161, 0x6a5f3535, 0xaef95757, 0x69d0b9b9, 0x17918686, 0x9958c1c1, 0x3a271d1d, 0x27b99e9e,
    0xd938e1e1, 0xeb13f8f8, 0x2bb39898, 0x22331111, 0xd2bb6969, 0xa970d9d9, 0x07898e8e, 0x33a79494,
    0x2db69b9b, 0x3c221e1e, 0x15928787, 0xc920e9e9, 0x8749cece, 0xaaff5555, 0x50782828, 0xa57adfdf,
    0x038f8c8c, 0x59f8a1a1, 0x09808989, 0x1a170d0d, 0x65dabfbf, 0xd731e6e6, 0x84c64242, 0xd0b86868,
    0x82c34141, 0x29b09999, 0x5a772d2d, 0x1e110f0f, 0x7bcbb0b0, 0xa8fc5454, 0x6dd6bbbb, 0x2c3a1616
};

static const uint32_t *const LUT0 = _aes_lut + 0 * 256;
static const uint32_t *const LUT1 = _aes_lut + 1 * 256;
static const uint32_t *const LUT2 = _aes_lut + 2 * 256;
static const uint32_t *const LUT3 = _aes_lut + 3 * 256;

static SoftAesBlock
softaes_block_encrypt(const SoftAesBlock block, const SoftAesBlock rk)
{
    SoftAesBlock   out;
    uint8_t        ix0[4], ix1[4], ix2[4], ix3[4];
    const uint32_t s0 = block.w0;
    const uint32_t s1 = block.w1;
    const uint32_t s2 = block.w2;
    const uint32_t s3 = block.w3;

    ix0[0] = (uint8_t) s0;
    ix0[1] = (uint8_t) s1;
    ix0[2] = (uint8_t) s2;
    ix0[3] = (uint8_t) s3;

    ix1[0] = (uint8_t) (s1 >> 8);
    ix1[1] = (uint8_t) (s2 >> 8);
    ix1[2] = (uint8_t) (s3 >> 8);
    ix1[3] = (uint8_t) (s0 >> 8);

    ix2[0] = (uint8_t) (s2 >> 16);
    ix2[1] = (uint8_t) (s3 >> 16);
    ix2[2] = (uint8_t) (s0 >> 16);
    ix2[3] = (uint8_t) (s1 >> 16);

    ix3[0] = (uint8_t) (s3 >> 24);
    ix3[1] = (uint8_t) (s0 >> 24);
    ix3[2] = (uint8_t) (s1 >> 24);
    ix3[3] = (uint8_t) (s2 >> 24);

    out.w0 = LUT0[ix0[0]];
    out.w1 = LUT0[ix0[1]];
    out.w2 = LUT0[ix0[2]];
    out.w3 = LUT0[ix0[3]];

    out.w0 ^= LUT1[ix1[0]];
    out.w1 ^= LUT1[ix1[1]];
    out.w2 ^= LUT1[ix1[2]];
    out.w3 ^= LUT1[ix1[3]];

    out.w0 ^= LUT2[ix2[0]];
    out.w1 ^= LUT2[ix2[1]];
    out.w2 ^= LUT2[ix2[2]];
    out.w3 ^= LUT2[ix2[3]];

    out.w0 ^= LUT3[ix3[0]];
    out.w1 ^= LUT3[ix3[1]];
    out.w2 ^= LUT3[ix3[2]];
    out.w3 ^= LUT3[ix3[3]];

    out.w0 ^= rk.w0;
    out.w1 ^= rk.w1;
    out.w2 ^= rk.w2;
    out.w3 ^= rk.w3;

    return out;
}

static void
softaes_blocks_encrypt_x8(SoftAesBlock out[8], const SoftAesBlock in[8], const SoftAesBlock rk[8])
{
    size_t i;

    for (i = 0; i < 8; i++) {
        out[i] = softaes_block_encrypt(in[i], rk[i]);
    }
}

static void
softaes_blocks_encrypt_x6(SoftAesBlock out[6], const SoftAesBlock in[6], const SoftAesBlock rk[6])
{
    size_t i;

    for (i = 0; i < 6; i++) {
        out[i] = softaes_block_encrypt(in[i], rk[i]);
    }
}
#    else

/*
 * Without FAVOR_PERFORMANCE, the AES rounds of a whole AEGIS state update are
 * computed at once on a bitsliced representation: up to eight independent
 * blocks are spread across 32 words of 32 bits, grouped as four pairs of
 * blocks going through identical, independent circuits. SubBytes is a
 * gate-only Boolean S-box, ShiftRows is a word rotation and MixColumns a
 * fixed sequence of XORs, so no step indexes memory with secret data and the
 * rounds are constant-time on every platform.
 *
 * In the bitsliced layout, bit-plane k of group g lives in word 4k+g: each
 * bit-plane's four group lanes are adjacent isomorphic words, which SLP-class
 * optimizers merge into vector registers on 64-bit targets, while the code
 * remains plain sequential 32-bit operations for smaller CPUs. When vector
 * extensions are available, the S-box is evaluated explicitly on the lanes of
 * 4x32-bit vectors instead of relying on autovectorization.
 */

#        define SWAPMOVE(a, b, mask, n)                     \
            do {                                            \
                const uint32_t tmp = (b ^ (a >> n)) & mask; \
                b ^= tmp;                                   \
                a ^= (tmp << n);                            \
            } while (0)

typedef CRYPTO_ALIGN(32) uint32_t AesBlocks[32];

#        if (defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 12)) &&      \
            defined(NATIVE_LITTLE_ENDIAN) &&                                      \
            (defined(__SSE2__) || defined(__ARM_NEON) || defined(__ALTIVEC__)) && \
            !defined(AEGIS_NO_VECTOR_SBOX)
#            define SBOX_VECTORIZED
#        endif

#        ifdef SBOX_VECTORIZED

typedef uint32_t Vec __attribute__((vector_size(16)));
typedef uint8_t  VecBytes __attribute__((vector_size(16)));

#            define LANEROT1(V) __builtin_shufflevector((V), (V), 1, 2, 3, 0)
#            define LANEROT2(V) __builtin_shufflevector((V), (V), 2, 3, 0, 1)

static inline void
sbox_vec(Vec u[8])
{
    const Vec s0  = u[1] ^ u[4];
    const Vec s1  = u[5] ^ u[7];
    const Vec s2  = u[3] ^ s0;
    const Vec s3  = u[0] ^ u[2];
    const Vec q0  = s1 ^ s2;
    const Vec s4  = u[0] ^ u[6];
    const Vec s5  = u[2] ^ u[6];
    const Vec s6  = u[3] ^ s1;
    const Vec s7  = u[5] ^ s3;
    const Vec q1  = s1 ^ s5;
    const Vec q2  = u[2] ^ q0;
    const Vec q3  = s4 ^ s2;
    const Vec q4  = s3 ^ q0;
    const Vec s8  = u[4] ^ s3;
    const Vec q5  = s6 ^ s8;
    const Vec q6  = u[2] ^ u[3];
    const Vec q7  = u[6] ^ s2;
    const Vec s9  = u[6] ^ s0;
    const Vec q8  = s3 ^ s9;
    const Vec q9  = s4 ^ s6;
    const Vec q10 = s0 ^ s5;
    const Vec q12 = u[7] ^ s2;
    const Vec q13 = u[1] ^ s7;
    const Vec q14 = u[7] ^ s3;
    const Vec q15 = s2 ^ s7;
    const Vec q16 = u[1] ^ s1;
    const Vec q17 = u[1] ^ u[7];
    const Vec q11 = u[5];

    const Vec t20 = q6 & q12;
    const Vec t21 = q3 & q14;
    const Vec t22 = q1 & q16;
    const Vec t23 = q2 & q17;
    const Vec x0  = ((q3 | q14) ^ (q0 & q7)) ^ (t20 ^ t22);
    const Vec x1  = ((q4 | q13) ^ (q10 & q11)) ^ (t21 ^ t20);
    const Vec x2  = ((q2 | q17) ^ (q5 & q9)) ^ (t21 ^ t22);
    const Vec x3  = ((q8 | q15) ^ t23) ^ (t21 ^ (q4 & q13));

    const Vec a   = x1 & ~x3;
    const Vec b   = x0 & ~x3;
    const Vec c   = x3 & ~x1;
    const Vec d   = x2 & ~x1;
    const Vec e   = x0 ^ a;
    const Vec y0  = x3 ^ (x2 & ~e);
    const Vec f   = x1 ^ b;
    const Vec y1  = c ^ (x2 & f);
    const Vec g   = x2 ^ c;
    const Vec y2  = x1 ^ (x0 & ~g);
    const Vec h   = x3 ^ d;
    const Vec y3  = a ^ (x0 & h);
    const Vec y02 = y2 ^ y0;
    const Vec y13 = y3 ^ y1;
    const Vec y23 = y3 ^ y2;
    const Vec y01 = y1 ^ y0;
    const Vec y00 = y02 ^ y13;

    const Vec a0  = y01 & q11;
    const Vec a1  = y0 & q12;
    const Vec a2  = y1 & q0;
    const Vec a3  = y23 & q17;
    const Vec a4  = y2 & q5;
    const Vec a5  = y3 & q15;
    const Vec a6  = y13 & q14;
    const Vec a7  = y00 & q16;
    const Vec a8  = y02 & q13;
    const Vec a9  = y01 & q7;
    const Vec a10 = y0 & q10;
    const Vec a11 = y1 & q6;
    const Vec a12 = y23 & q2;
    const Vec a13 = y2 & q9;
    const Vec a14 = y3 & q8;
    const Vec a15 = y13 & q3;
    const Vec a16 = y00 & q1;
    const Vec a17 = y02 & q4;

    const Vec r0  = a1 ^ a5;
    const Vec r1  = a9 ^ a15;
    const Vec r2  = a4 ^ r0;
    const Vec r3  = a2 ^ a10;
    const Vec r4  = a11 ^ a17;
    const Vec r5  = a8 ^ r1;
    const Vec r6  = a0 ^ a16;
    const Vec r7  = a7 ^ a13;
    const Vec r8  = a11 ^ a14;
    const Vec r9  = r3 ^ r4;
    const Vec r10 = r5 ^ r6;
    const Vec r11 = r2 ^ r9;
    const Vec r12 = a3 ^ r0;
    const Vec r13 = r7 ^ r8;
    const Vec r14 = r12 ^ r13;
    u[0]          = r10 ^ r14;
    const Vec r15 = a6 ^ a10;
    const Vec r16 = r15 ^ r2;
    u[1]          = ~(r10 ^ r16);
    u[2]          = ~(a2 ^ r2);
    const Vec r17 = a12 ^ a13;
    const Vec r18 = a15 ^ r17;
    u[3]          = r18 ^ r11;
    const Vec r19 = a1 ^ a14;
    const Vec r20 = a17 ^ r3;
    const Vec r21 = r7 ^ r19;
    const Vec r22 = r5 ^ r20;
    u[4]          = r21 ^ r22;
    const Vec r23 = a9 ^ a12;
    u[5]          = r8 ^ r23;
    u[6]          = ~(r1 ^ r4);
    u[7]          = ~(a16 ^ r11);
}

/* Rotate the 32-bit words of group 1 left by 24, group 2 by 16 and group 3 by 8. The rotation
 * amounts are all multiples of 8, so this is a single byte shuffle per bit-plane vector. */
static inline Vec
shiftrows_vec(const Vec v)
{
    const VecBytes b = (VecBytes) v;

    return (Vec) __builtin_shufflevector(b, b, 0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13,
                                         14);
}

/* Bitsliced mixcolumns: with D_k = V_k ^ rot1(V_k) and S_k the XOR of the three other lanes of
 * V_k, the new bit-plane k is D_{k+1} ^ S_k, with the reduction term D_0 also folded into planes
 * 3, 4, 6 and 7. Scheduled so that each D_k is consumed as soon as it is produced to keep the
 * number of live vectors low. */
static inline void
mixcolumns_vec(Vec u[8])
{
    const Vec r0 = LANEROT1(u[0]);
    const Vec d0 = u[0] ^ r0;
    const Vec s0 = r0 ^ LANEROT2(d0);
    const Vec r1 = LANEROT1(u[1]);
    const Vec d1 = u[1] ^ r1;
    const Vec s1 = r1 ^ LANEROT2(d1);
    const Vec r2 = LANEROT1(u[2]);
    const Vec d2 = u[2] ^ r2;
    const Vec s2 = r2 ^ LANEROT2(d2);
    const Vec r3 = LANEROT1(u[3]);
    const Vec d3 = u[3] ^ r3;
    const Vec s3 = r3 ^ LANEROT2(d3);
    const Vec r4 = LANEROT1(u[4]);
    const Vec d4 = u[4] ^ r4;
    const Vec s4 = r4 ^ LANEROT2(d4);
    const Vec r5 = LANEROT1(u[5]);
    const Vec d5 = u[5] ^ r5;
    const Vec s5 = r5 ^ LANEROT2(d5);
    const Vec r6 = LANEROT1(u[6]);
    const Vec d6 = u[6] ^ r6;
    const Vec s6 = r6 ^ LANEROT2(d6);
    const Vec r7 = LANEROT1(u[7]);
    const Vec d7 = u[7] ^ r7;
    const Vec s7 = r7 ^ LANEROT2(d7);

    u[0] = d1 ^ s0;
    u[1] = d2 ^ s1;
    u[2] = d3 ^ s2;
    u[3] = d4 ^ d0 ^ s3;
    u[4] = d5 ^ d0 ^ s4;
    u[5] = d6 ^ s5;
    u[6] = d7 ^ d0 ^ s6;
    u[7] = d0 ^ s7;
}

static void
aes_round(AesBlocks st)
{
    Vec    u[8];
    size_t i;

    memcpy(u, st, sizeof(AesBlocks));

    sbox_vec(u);

    for (i = 0; i < 8; i++) {
        u[i] = shiftrows_vec(u[i]);
    }

    mixcolumns_vec(u);

    memcpy(st, u, sizeof(AesBlocks));
}

#        else

/* The scalar fallback uses the same permuted layout as the vectorized code. The sbox is
 * evaluated one group at a time to keep register pressure low on 32-bit CPUs, but shiftrows
 * and mixcolumns work on adjacent isomorphic quads that compilers with vector units can merge
 * into wide registers. */
static void
sbox(uint32_t *u)
{
    const uint32_t s0  = u[4] ^ u[16];
    const uint32_t s1  = u[20] ^ u[28];
    const uint32_t s2  = u[12] ^ s0;
    const uint32_t s3  = u[0] ^ u[8];
    const uint32_t q0  = s1 ^ s2;
    const uint32_t s4  = u[0] ^ u[24];
    const uint32_t s5  = u[8] ^ u[24];
    const uint32_t s6  = u[12] ^ s1;
    const uint32_t s7  = u[20] ^ s3;
    const uint32_t q1  = s1 ^ s5;
    const uint32_t q2  = u[8] ^ q0;
    const uint32_t q3  = s4 ^ s2;
    const uint32_t q4  = s3 ^ q0;
    const uint32_t s8  = u[16] ^ s3;
    const uint32_t q5  = s6 ^ s8;
    const uint32_t q6  = u[8] ^ u[12];
    const uint32_t q7  = u[24] ^ s2;
    const uint32_t s9  = u[24] ^ s0;
    const uint32_t q8  = s3 ^ s9;
    const uint32_t q9  = s4 ^ s6;
    const uint32_t q10 = s0 ^ s5;
    const uint32_t q12 = u[28] ^ s2;
    const uint32_t q13 = u[4] ^ s7;
    const uint32_t q14 = u[28] ^ s3;
    const uint32_t q15 = s2 ^ s7;
    const uint32_t q16 = u[4] ^ s1;
    const uint32_t q17 = u[4] ^ u[28];
    const uint32_t q11 = u[20];

    const uint32_t t20 = q6 & q12;
    const uint32_t t21 = q3 & q14;
    const uint32_t t22 = q1 & q16;
    const uint32_t t23 = q2 & q17;
    const uint32_t x0  = ((q3 | q14) ^ (q0 & q7)) ^ (t20 ^ t22);
    const uint32_t x1  = ((q4 | q13) ^ (q10 & q11)) ^ (t21 ^ t20);
    const uint32_t x2  = ((q2 | q17) ^ (q5 & q9)) ^ (t21 ^ t22);
    const uint32_t x3  = ((q8 | q15) ^ t23) ^ (t21 ^ (q4 & q13));

    const uint32_t a   = x1 & ~x3;
    const uint32_t b   = x0 & ~x3;
    const uint32_t c   = x3 & ~x1;
    const uint32_t d   = x2 & ~x1;
    const uint32_t e   = x0 ^ a;
    const uint32_t y0  = x3 ^ (x2 & ~e);
    const uint32_t f   = x1 ^ b;
    const uint32_t y1  = c ^ (x2 & f);
    const uint32_t g   = x2 ^ c;
    const uint32_t y2  = x1 ^ (x0 & ~g);
    const uint32_t h   = x3 ^ d;
    const uint32_t y3  = a ^ (x0 & h);
    const uint32_t y02 = y2 ^ y0;
    const uint32_t y13 = y3 ^ y1;
    const uint32_t y23 = y3 ^ y2;
    const uint32_t y01 = y1 ^ y0;
    const uint32_t y00 = y02 ^ y13;

    const uint32_t a0  = y01 & q11;
    const uint32_t a1  = y0 & q12;
    const uint32_t a2  = y1 & q0;
    const uint32_t a3  = y23 & q17;
    const uint32_t a4  = y2 & q5;
    const uint32_t a5  = y3 & q15;
    const uint32_t a6  = y13 & q14;
    const uint32_t a7  = y00 & q16;
    const uint32_t a8  = y02 & q13;
    const uint32_t a9  = y01 & q7;
    const uint32_t a10 = y0 & q10;
    const uint32_t a11 = y1 & q6;
    const uint32_t a12 = y23 & q2;
    const uint32_t a13 = y2 & q9;
    const uint32_t a14 = y3 & q8;
    const uint32_t a15 = y13 & q3;
    const uint32_t a16 = y00 & q1;
    const uint32_t a17 = y02 & q4;

    const uint32_t r0  = a1 ^ a5;
    const uint32_t r1  = a9 ^ a15;
    const uint32_t r2  = a4 ^ r0;
    const uint32_t r3  = a2 ^ a10;
    const uint32_t r4  = a11 ^ a17;
    const uint32_t r5  = a8 ^ r1;
    const uint32_t r6  = a0 ^ a16;
    const uint32_t r7  = a7 ^ a13;
    const uint32_t r8  = a11 ^ a14;
    const uint32_t r9  = r3 ^ r4;
    const uint32_t r10 = r5 ^ r6;
    const uint32_t r11 = r2 ^ r9;
    const uint32_t r12 = a3 ^ r0;
    const uint32_t r13 = r7 ^ r8;
    const uint32_t r14 = r12 ^ r13;
    u[0]               = r10 ^ r14;
    const uint32_t r15 = a6 ^ a10;
    const uint32_t r16 = r15 ^ r2;
    u[4]               = ~(r10 ^ r16);
    u[8]               = ~(a2 ^ r2);
    const uint32_t r17 = a12 ^ a13;
    const uint32_t r18 = a15 ^ r17;
    u[12]              = r18 ^ r11;
    const uint32_t r19 = a1 ^ a14;
    const uint32_t r20 = a17 ^ r3;
    const uint32_t r21 = r7 ^ r19;
    const uint32_t r22 = r5 ^ r20;
    u[16]              = r21 ^ r22;
    const uint32_t r23 = a9 ^ a12;
    u[20]              = r8 ^ r23;
    u[24]              = ~(r1 ^ r4);
    u[28]              = ~(a16 ^ r11);
}

static void
sboxes(AesBlocks st)
{
    size_t i;

    for (i = 0; i < 4; i++) {
        sbox(st + i);
    }
}

static void
shiftrows(AesBlocks st)
{
    size_t i;

    for (i = 0; i < 32; i += 4) {
        st[i + 1] = AEGIS_ROTL32(st[i + 1], 24);
        st[i + 2] = AEGIS_ROTL32(st[i + 2], 16);
        st[i + 3] = AEGIS_ROTL32(st[i + 3], 8);
    }
}

static void
mixcolumns(AesBlocks st)
{
    uint32_t t2_0, t2_1, t2_2, t2_3;
    uint32_t t, t_bis, t0_0, t0_1, t0_2, t0_3;
    uint32_t t1_0, t1_1, t1_2, t1_3;

    t2_0   = st[0] ^ st[1];
    t2_1   = st[1] ^ st[2];
    t2_2   = st[2] ^ st[3];
    t2_3   = st[3] ^ st[0];
    t0_0   = st[28] ^ st[29];
    t0_1   = st[29] ^ st[30];
    t0_2   = st[30] ^ st[31];
    t0_3   = st[31] ^ st[28];
    t      = st[28];
    st[28] = t2_0 ^ t0_2 ^ st[29];
    st[29] = t2_1 ^ t0_2 ^ t;
    t      = st[30];
    st[30] = t2_2 ^ t0_0 ^ st[31];
    st[31] = t2_3 ^ t0_0 ^ t;
    t1_0   = st[24] ^ st[25];
    t1_1   = st[25] ^ st[26];
    t1_2   = st[26] ^ st[27];
    t1_3   = st[27] ^ st[24];
    t      = st[24];
    st[24] = t0_0 ^ t2_0 ^ st[25] ^ t1_2;
    t_bis  = st[25];
    st[25] = t0_1 ^ t2_1 ^ t1_2 ^ t;
    t      = st[26];
    st[26] = t0_2 ^ t2_2 ^ t1_3 ^ t_bis;
    st[27] = t0_3 ^ t2_3 ^ t1_0 ^ t;
    t0_0   = st[20] ^ st[21];
    t0_1   = st[21] ^ st[22];
    t0_2   = st[22] ^ st[23];
    t0_3   = st[23] ^ st[20];
    t      = st[20];
    st[20] = t1_0 ^ t0_1 ^ st[23];
    t_bis  = st[21];
    st[21] = t1_1 ^ t0_2 ^ t;
    t      = st[22];
    st[22] = t1_2 ^ t0_3 ^ t_bis;
    st[23] = t1_3 ^ t0_0 ^ t;
    t1_0   = st[16] ^ st[17];
    t1_1   = st[17] ^ st[18];
    t1_2   = st[18] ^ st[19];
    t1_3   = st[19] ^ st[16];
    t      = st[16];
    st[16] = t0_0 ^ t2_0 ^ t1_1 ^ st[19];
    t_bis  = st[17];
    st[17] = t0_1 ^ t2_1 ^ t1_2 ^ t;
    t      = st[18];
    st[18] = t0_2 ^ t2_2 ^ t1_3 ^ t_bis;
    st[19] = t0_3 ^ t2_3 ^ t1_0 ^ t;
    t0_0   = st[12] ^ st[13];
    t0_1   = st[13] ^ st[14];
    t0_2   = st[14] ^ st[15];
    t0_3   = st[15] ^ st[12];
    t      = st[12];
    st[12] = t1_0 ^ t2_0 ^ t0_1 ^ st[15];
    t_bis  = st[13];
    st[13] = t1_1 ^ t2_1 ^ t0_2 ^ t;
    t      = st[14];
    st[14] = t1_2 ^ t2_2 ^ t0_3 ^ t_bis;
    st[15] = t1_3 ^ t2_3 ^ t0_0 ^ t;
    t1_0   = st[8] ^ st[9];
    t1_1   = st[9] ^ st[10];
    t1_2   = st[10] ^ st[11];
    t1_3   = st[11] ^ st[8];
    t      = st[8];
    st[8]  = t0_0 ^ t1_1 ^ st[11];
    t_bis  = st[9];
    st[9]  = t0_1 ^ t1_2 ^ t;
    t      = st[10];
    st[10] = t0_2 ^ t1_3 ^ t_bis;
    st[11] = t0_3 ^ t1_0 ^ t;
    t0_0   = st[4] ^ st[5];
    t0_1   = st[5] ^ st[6];
    t0_2   = st[6] ^ st[7];
    t0_3   = st[7] ^ st[4];
    t      = st[4];
    st[4]  = t1_0 ^ t0_1 ^ st[7];
    t_bis  = st[5];
    st[5]  = t1_1 ^ t0_2 ^ t;
    t      = st[6];
    st[6]  = t1_2 ^ t0_3 ^ t_bis;
    st[7]  = t1_3 ^ t0_0 ^ t;
    t      = st[0];
    st[0]  = t0_0 ^ t2_1 ^ st[3];
    t_bis  = st[1];
    st[1]  = t0_1 ^ t2_2 ^ t;
    t      = st[2];
    st[2]  = t0_2 ^ t2_3 ^ t_bis;
    st[3]  = t0_3 ^ t2_0 ^ t;
}

static void
aes_round(AesBlocks st)
{
    sboxes(st);
    shiftrows(st);
    mixcolumns(st);
}

#        endif

static void
pack(AesBlocks st)
{
    size_t i;

    for (i = 0; i < 32; i += 4) {
        SWAPMOVE(st[i], st[i + 1], 0x00ff00ff, 8);
        SWAPMOVE(st[i + 2], st[i + 3], 0x00ff00ff, 8);
        SWAPMOVE(st[i], st[i + 2], 0x0000ffff, 16);
        SWAPMOVE(st[i + 1], st[i + 3], 0x0000ffff, 16);
    }
    for (i = 0; i < 4; i++) {
        SWAPMOVE(st[i + 4], st[i], 0x55555555, 1);
        SWAPMOVE(st[i + 12], st[i + 8], 0x55555555, 1);
        SWAPMOVE(st[i + 20], st[i + 16], 0x55555555, 1);
        SWAPMOVE(st[i + 28], st[i + 24], 0x55555555, 1);
        SWAPMOVE(st[i + 8], st[i], 0x33333333, 2);
        SWAPMOVE(st[i + 12], st[i + 4], 0x33333333, 2);
        SWAPMOVE(st[i + 24], st[i + 16], 0x33333333, 2);
        SWAPMOVE(st[i + 28], st[i + 20], 0x33333333, 2);
        SWAPMOVE(st[i + 16], st[i], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 20], st[i + 4], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 24], st[i + 8], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 28], st[i + 12], 0x0f0f0f0f, 4);
    }
}

static void
unpack(AesBlocks st)
{
    size_t i;

    for (i = 0; i < 4; i++) {
        SWAPMOVE(st[i + 4], st[i], 0x55555555, 1);
        SWAPMOVE(st[i + 12], st[i + 8], 0x55555555, 1);
        SWAPMOVE(st[i + 20], st[i + 16], 0x55555555, 1);
        SWAPMOVE(st[i + 28], st[i + 24], 0x55555555, 1);
        SWAPMOVE(st[i + 8], st[i], 0x33333333, 2);
        SWAPMOVE(st[i + 12], st[i + 4], 0x33333333, 2);
        SWAPMOVE(st[i + 24], st[i + 16], 0x33333333, 2);
        SWAPMOVE(st[i + 28], st[i + 20], 0x33333333, 2);
        SWAPMOVE(st[i + 16], st[i], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 20], st[i + 4], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 24], st[i + 8], 0x0f0f0f0f, 4);
        SWAPMOVE(st[i + 28], st[i + 12], 0x0f0f0f0f, 4);
    }
    for (i = 0; i < 32; i += 4) {
        SWAPMOVE(st[i], st[i + 2], 0x0000ffff, 16);
        SWAPMOVE(st[i + 1], st[i + 3], 0x0000ffff, 16);
        SWAPMOVE(st[i], st[i + 1], 0x00ff00ff, 8);
        SWAPMOVE(st[i + 2], st[i + 3], 0x00ff00ff, 8);
    }
}

static void
softaes_blocks_encrypt(SoftAesBlock *out, const SoftAesBlock *in, const SoftAesBlock *rk,
                       const size_t n)
{
    AesBlocks st;
    size_t    i;

    if (n < 8) {
        memset(st, 0, sizeof st);
    }
    for (i = 0; i < n; i++) {
        st[i * 4 + 0] = in[i].w0;
        st[i * 4 + 1] = in[i].w1;
        st[i * 4 + 2] = in[i].w2;
        st[i * 4 + 3] = in[i].w3;
    }
    pack(st);
    aes_round(st);
    unpack(st);
    for (i = 0; i < n; i++) {
        out[i].w0 = st[i * 4 + 0] ^ rk[i].w0;
        out[i].w1 = st[i * 4 + 1] ^ rk[i].w1;
        out[i].w2 = st[i * 4 + 2] ^ rk[i].w2;
        out[i].w3 = st[i * 4 + 3] ^ rk[i].w3;
    }
}

static void
softaes_blocks_encrypt_x8(SoftAesBlock out[8], const SoftAesBlock in[8], const SoftAesBlock rk[8])
{
    softaes_blocks_encrypt(out, in, rk, 8);
}

static void
softaes_blocks_encrypt_x6(SoftAesBlock out[6], const SoftAesBlock in[6], const SoftAesBlock rk[6])
{
    softaes_blocks_encrypt(out, in, rk, 6);
}
#    endif

#    if defined(FAVOR_PERFORMANCE) && (defined(__GNUC__) || defined(__clang__)) && \
        defined(NATIVE_LITTLE_ENDIAN)

/*
 * Every output column is stored at once and followed by a memory barrier,
 * or the compiler hoists all sixteen table loads of a round above their
 * XOR consumers and register-poor targets (wasmtime) spill the lot.
 */

static inline void
softaes_round_mem(const uint8_t *x, uint32_t *dst)
{
    dst[0] ^= LUT0[x[0]] ^ LUT1[x[5]] ^ LUT2[x[10]] ^ LUT3[x[15]];
    __asm__ __volatile__("" ::: "memory");
    dst[1] ^= LUT0[x[4]] ^ LUT1[x[9]] ^ LUT2[x[14]] ^ LUT3[x[3]];
    __asm__ __volatile__("" ::: "memory");
    dst[2] ^= LUT0[x[8]] ^ LUT1[x[13]] ^ LUT2[x[2]] ^ LUT3[x[7]];
    __asm__ __volatile__("" ::: "memory");
    dst[3] ^= LUT0[x[12]] ^ LUT1[x[1]] ^ LUT2[x[6]] ^ LUT3[x[11]];
    __asm__ __volatile__("" ::: "memory");
}

#        define SOFTAES_ROT(SRC, DST) \
            softaes_round_mem((const uint8_t *) (w + 4 * (SRC)), w + 4 * (DST))

static void
softaes_aegis_rotate8_x1(SoftAesBlock st[8])
{
    uint32_t      *w = (uint32_t *) (void *) st;
    uint32_t       tmp[4];
    const uint8_t *tp = (const uint8_t *) tmp;

    COMPILER_ASSERT(sizeof(SoftAesBlock) == 16);
    memcpy(tmp, w + 4 * 7, 16);
    __asm__("" : "+r"(tp));
    SOFTAES_ROT(6, 7);
    SOFTAES_ROT(5, 6);
    SOFTAES_ROT(4, 5);
    SOFTAES_ROT(3, 4);
    SOFTAES_ROT(2, 3);
    SOFTAES_ROT(1, 2);
    SOFTAES_ROT(0, 1);
    softaes_round_mem(tp, w);
}

static void
softaes_aegis_rotate8_x2(SoftAesBlock st[16])
{
    uint32_t      *w = (uint32_t *) (void *) st;
    uint32_t       tmp[8];
    const uint8_t *tp = (const uint8_t *) tmp;

    COMPILER_ASSERT(sizeof(SoftAesBlock) == 16);
    memcpy(tmp, w + 4 * 14, 32);
    __asm__("" : "+r"(tp));
    SOFTAES_ROT(13, 15);
    SOFTAES_ROT(12, 14);
    SOFTAES_ROT(11, 13);
    SOFTAES_ROT(10, 12);
    SOFTAES_ROT(9, 11);
    SOFTAES_ROT(8, 10);
    SOFTAES_ROT(7, 9);
    SOFTAES_ROT(6, 8);
    SOFTAES_ROT(5, 7);
    SOFTAES_ROT(4, 6);
    SOFTAES_ROT(3, 5);
    SOFTAES_ROT(2, 4);
    SOFTAES_ROT(1, 3);
    SOFTAES_ROT(0, 2);
    softaes_round_mem(tp, w);
    softaes_round_mem(tp + 16, w + 4);
}

static void
softaes_aegis_rotate8_x4(SoftAesBlock st[32])
{
    uint32_t      *w = (uint32_t *) (void *) st;
    uint32_t       tmp[16];
    const uint8_t *tp = (const uint8_t *) tmp;

    COMPILER_ASSERT(sizeof(SoftAesBlock) == 16);
    memcpy(tmp, w + 4 * 28, 64);
    __asm__("" : "+r"(tp));
    SOFTAES_ROT(27, 31);
    SOFTAES_ROT(26, 30);
    SOFTAES_ROT(25, 29);
    SOFTAES_ROT(24, 28);
    SOFTAES_ROT(23, 27);
    SOFTAES_ROT(22, 26);
    SOFTAES_ROT(21, 25);
    SOFTAES_ROT(20, 24);
    SOFTAES_ROT(19, 23);
    SOFTAES_ROT(18, 22);
    SOFTAES_ROT(17, 21);
    SOFTAES_ROT(16, 20);
    SOFTAES_ROT(15, 19);
    SOFTAES_ROT(14, 18);
    SOFTAES_ROT(13, 17);
    SOFTAES_ROT(12, 16);
    SOFTAES_ROT(11, 15);
    SOFTAES_ROT(10, 14);
    SOFTAES_ROT(9, 13);
    SOFTAES_ROT(8, 12);
    SOFTAES_ROT(7, 11);
    SOFTAES_ROT(6, 10);
    SOFTAES_ROT(5, 9);
    SOFTAES_ROT(4, 8);
    SOFTAES_ROT(3, 7);
    SOFTAES_ROT(2, 6);
    SOFTAES_ROT(1, 5);
    SOFTAES_ROT(0, 4);
    softaes_round_mem(tp, w);
    softaes_round_mem(tp + 16, w + 4);
    softaes_round_mem(tp + 32, w + 8);
    softaes_round_mem(tp + 48, w + 12);
}

static void
softaes_aegis_rotate6_x1(SoftAesBlock st[6])
{
    uint32_t      *w = (uint32_t *) (void *) st;
    uint32_t       tmp[4];
    const uint8_t *tp = (const uint8_t *) tmp;

    COMPILER_ASSERT(sizeof(SoftAesBlock) == 16);
    memcpy(tmp, w + 4 * 5, 16);
    __asm__("" : "+r"(tp));
    SOFTAES_ROT(4, 5);
    SOFTAES_ROT(3, 4);
    SOFTAES_ROT(2, 3);
    SOFTAES_ROT(1, 2);
    SOFTAES_ROT(0, 1);
    softaes_round_mem(tp, w);
}

static void
softaes_aegis_rotate6_x2(SoftAesBlock st[12])
{
    uint32_t      *w = (uint32_t *) (void *) st;
    uint32_t       tmp[8];
    const uint8_t *tp = (const uint8_t *) tmp;

    COMPILER_ASSERT(sizeof(SoftAesBlock) == 16);
    memcpy(tmp, w + 4 * 10, 32);
    __asm__("" : "+r"(tp));
    SOFTAES_ROT(9, 11);
    SOFTAES_ROT(8, 10);
    SOFTAES_ROT(7, 9);
    SOFTAES_ROT(6, 8);
    SOFTAES_ROT(5, 7);
    SOFTAES_ROT(4, 6);
    SOFTAES_ROT(3, 5);
    SOFTAES_ROT(2, 4);
    SOFTAES_ROT(1, 3);
    SOFTAES_ROT(0, 2);
    softaes_round_mem(tp, w);
    softaes_round_mem(tp + 16, w + 4);
}

static void
softaes_aegis_rotate6_x4(SoftAesBlock st[24])
{
    uint32_t      *w = (uint32_t *) (void *) st;
    uint32_t       tmp[16];
    const uint8_t *tp = (const uint8_t *) tmp;

    COMPILER_ASSERT(sizeof(SoftAesBlock) == 16);
    memcpy(tmp, w + 4 * 20, 64);
    __asm__("" : "+r"(tp));
    SOFTAES_ROT(19, 23);
    SOFTAES_ROT(18, 22);
    SOFTAES_ROT(17, 21);
    SOFTAES_ROT(16, 20);
    SOFTAES_ROT(15, 19);
    SOFTAES_ROT(14, 18);
    SOFTAES_ROT(13, 17);
    SOFTAES_ROT(12, 16);
    SOFTAES_ROT(11, 15);
    SOFTAES_ROT(10, 14);
    SOFTAES_ROT(9, 13);
    SOFTAES_ROT(8, 12);
    SOFTAES_ROT(7, 11);
    SOFTAES_ROT(6, 10);
    SOFTAES_ROT(5, 9);
    SOFTAES_ROT(4, 8);
    SOFTAES_ROT(3, 7);
    SOFTAES_ROT(2, 6);
    SOFTAES_ROT(1, 5);
    SOFTAES_ROT(0, 4);
    softaes_round_mem(tp, w);
    softaes_round_mem(tp + 16, w + 4);
    softaes_round_mem(tp + 32, w + 8);
    softaes_round_mem(tp + 48, w + 12);
}

#    else

static void
softaes_aegis_rotate(SoftAesBlock *st, const size_t blocks, const size_t lanes)
{
    SoftAesBlock in[8], rk[8], out[8];
    size_t       b, l;

    if (lanes == 1) {
        for (b = 0; b < blocks; b++) {
            in[b] = st[(b + blocks - 1) % blocks];
        }
        if (blocks == 8) {
            softaes_blocks_encrypt_x8(st, in, st);
        } else {
            softaes_blocks_encrypt_x6(st, in, st);
        }
        return;
    }
    for (l = 0; l < lanes; l++) {
        for (b = 0; b < blocks; b++) {
            in[b] = st[((b + blocks - 1) % blocks) * lanes + l];
            rk[b] = st[b * lanes + l];
        }
        if (blocks == 8) {
            softaes_blocks_encrypt_x8(out, in, rk);
        } else {
            softaes_blocks_encrypt_x6(out, in, rk);
        }
        for (b = 0; b < blocks; b++) {
            st[b * lanes + l] = out[b];
        }
    }
}

static void
softaes_aegis_rotate8_x1(SoftAesBlock st[8])
{
    softaes_aegis_rotate(st, 8, 1);
}

static void
softaes_aegis_rotate8_x2(SoftAesBlock st[16])
{
    softaes_aegis_rotate(st, 8, 2);
}

static void
softaes_aegis_rotate8_x4(SoftAesBlock st[32])
{
    softaes_aegis_rotate(st, 8, 4);
}

static void
softaes_aegis_rotate6_x1(SoftAesBlock st[6])
{
    softaes_aegis_rotate(st, 6, 1);
}

static void
softaes_aegis_rotate6_x2(SoftAesBlock st[12])
{
    softaes_aegis_rotate(st, 6, 2);
}

static void
softaes_aegis_rotate6_x4(SoftAesBlock st[24])
{
    softaes_aegis_rotate(st, 6, 4);
}

#    endif

#endif /* SOFTAES_SIMD128 */
