/*
** Tests for the AES implementations (aes_core.c, aes_gcm.c):
**
** 1. Known-answer tests for every AES backend that is compiled in and
**    available on this machine: FIPS-197 (block encryption), NIST SP 800-38A
**    (CBC), CBC with ciphertext stealing (reference values computed with an
**    independent implementation), the XAES-256-GCM test vectors of
**    c2sp.org/XAES-256-GCM and AES-256-GCM-SIV vectors (RFC 8452 C.2 and C.3,
**    the Wycheproof cases with a wrapped counter or a modified tag, values
**    computed with OpenSSL via Python cryptography, plus the 32-bit counter
**    wrap) with every GHASH variant.
** 2. All backends must give the same result for random keys, IVs and data:
**    CBC with and without ciphertext stealing, block encryption (ECB) and
**    XAES-256-GCM, also for buffers that do not start on an aligned address.
** 3. XAES-256-GCM must reject a changed ciphertext, tag, AAD, nonce or page
**    number, and must not return any plaintext in that case.
** 4. Invalid use (wrong direction, key length, data length) must be refused.
** 5. The cipher scheme aes256gcm on database level, with both algorithms, both
**    key derivation functions and a raw key: the database must open with its
**    own configuration only, no plaintext may reach the file, a changed byte
**    in a page or in byte 20 of the header and a page at the place of another
**    one must be detected, every write must use a new nonce, hmac_check=0
**    must still read a page whose free space was changed, and a plaintext
**    header must work with the salt given separately.
**
** Usage: aestest [rounds]
*/

#include "sqlite3mc.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, ...) do { \
  checks++; \
  if (!(cond)) { failures++; if (failures <= 50) { printf("  [FAIL] "); printf(__VA_ARGS__); printf("\n"); } } \
} while (0)

static const int implIds[] = { AES_IMPL_HW, AES_IMPL_VPAES, AES_IMPL_CT64, AES_IMPL_CT32, AES_IMPL_RIJNDAEL };
static const char* implNames[] = { "auto", "hardware", "vpaes", "ct64", "ct32", "rijndael" };
static const int ghashIds[] = { AES_GHASH_BITWISE, AES_GHASH_CTMUL64, AES_GHASH_PCLMUL, AES_GHASH_PMULL };
static const char* ghashNames[] = { "auto", "bitwise", "ctmul64", "pclmul", "pmull" };

#define MAX_IMPLS 5
static int impls[MAX_IMPLS];
static int implCount;

/* Deterministic pseudo random numbers (xorshift64*) */
static uint64_t rngState = 0x9e3779b97f4a7c15ULL;
static unsigned int rnd(void)
{
  rngState ^= rngState >> 12;
  rngState ^= rngState << 25;
  rngState ^= rngState >> 27;
  return (unsigned int) ((rngState * 0x2545f4914f6cdd1dULL) >> 32);
}
static void rndFill(unsigned char* p, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) p[i] = (unsigned char) rnd();
}

static int fromHex(const char* hex, unsigned char* out)
{
  int n = 0;
  while (hex[0] != 0 && hex[1] != 0)
  {
    out[n++] = (unsigned char) ((sqlite3mcConvertHex2Int(hex[0]) << 4) | sqlite3mcConvertHex2Int(hex[1]));
    hex += 2;
  }
  return n;
}

static int allZero(const unsigned char* p, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) if (p[i] != 0) return 0;
  return 1;
}

/*
** 1. Known-answer tests
*/
static const struct { const char *key, *plain, *cipher; } blockVectors[] =
{
  /* FIPS-197, C.1 and C.3 */
  { "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a" },
  { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089" },
};

static const struct { const char *key, *iv, *plain, *cipher; } cbcVectors[] =
{
  /* NIST SP 800-38A, F.2.1 and F.2.5 */
  { "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7" },
  { "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "000102030405060708090a0b0c0d0e0f",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b" },
  /* CBC with ciphertext stealing (CS3), computed with Go's crypto/aes and crypto/cipher */
  { "41552839245c203106f61bd675e3ca04", "b6df0a1f17200eb4a0ae2053dd0e3d29",
    "8ab4b89a8ff6a03670abca95bda44b63ab", "1f774be3ab5041bffa0ff008468a6ce266" },
  { "fc531667002f1ebb67ca3e75d759e257", "598525ffbb7248c65de585602bb53b26",
    "b5fa46855f02e484e33c39c0d4d169daee6fc525afd566e827cbfa0b2423d8a9e6",
    "1c533667d38fba6afb3079daa20bca50437c76db9fda054e4734d72ca13f8aee0e" },
  { "a61d27b5f45ecd8442b4b827d11f52ff57958a19a73f4e67131054e8dc5ba76f", "4ff7b6684b972b5605398b2dfc5b2167",
    "0e8330da06905b46e8d8353fbbe2d8f734", "f038b40866eb000b7e7650c1a94fbba13e" },
  { "2fd3ae26424cd862a7fcb5786e22388e70d7fe54a0bfe8994aaaea13b5d1cdae", "4a9b07da83342709726519be64e8c2ea",
    "b5e27d92a2cea68258a1a3a34dc98cd738f0ab13b06af5f176437aaab65b9a1860",
    "c70f3cb9823dc350bb0fb52cf2f2f5efce682a281936065c5a79e69c4fc33fc0f1" },
  { "f4810cf3989f83f53d91f048d03c0bc45b4973eeca324136f554b110a16ddc52", "fb7754dca84a521d4bf56a65f7098e62",
    "e643fd1a0c1db324774ec1f083a2a515c42c8bfe03ebeb1d76054780ed75ff15c63b9fbd1e0ee844bc17e310364f73",
    "7ff4a3590859438d92b97e68cb33cd010da8ed95e07ebbf3c2ce79b30de6b11514138b4261e13d9072b747c9c7493d" },
};

/* c2sp.org/XAES-256-GCM: key, nonce, AAD, plaintext, ciphertext || tag */
static const struct { const char *key, *nonce, *aad, *plain, *sealed; } xaesVectors[] =
{
  { "0101010101010101010101010101010101010101010101010101010101010101",
    "4142434445464748494a4b4c4d4e4f505152535455565758", "",
    "584145532d3235362d47434d", "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271" },
  { "0303030303030303030303030303030303030303030303030303030303030303",
    "4142434445464748494a4b4c4d4e4f505152535455565758", "633273702e6f72672f584145532d3235362d47434d",
    "584145532d3235362d47434d", "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d" },
};

/* AES-256-GCM-SIV: key, nonce, AAD, plaintext, ciphertext || tag.
** The first 26 entries are RFC 8452, C.2 (all vectors) and C.3 (counter wrap); the others were computed
** with an independent implementation (Python cryptography / OpenSSL, AESGCMSIV) for various AAD and
** plaintext lengths. */
static const struct { const char *key, *nonce, *aad, *plain, *sealed; } gcmSivVectors[] =
{
  /* RFC 8452 C.2, vector 1 */
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "",
    "", "07f5f4169bbf55a8400cd47ea6fd400f" },
  /* RFC 8452 C.2, vectors 2 to 24 */
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "",
    "0100000000000000", "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "",
    "010000000000000000000000", "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "",
    "01000000000000000000000000000000", "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "",
    "0100000000000000000000000000000002000000000000000000000000000000",
    "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "",
    "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000",
    "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e39cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "",
    "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
    "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "01",
    "0200000000000000", "1de22967237a813291213f267e3b452f02d01ae33e4ec854" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "01",
    "020000000000000000000000", "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "01",
    "02000000000000000000000000000000", "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "01",
    "0200000000000000000000000000000003000000000000000000000000000000",
    "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365aea1bad12702e1965604374aab96dbbc" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "01",
    "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
    "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "01",
    "02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000",
    "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc98cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c895bde0285037c5de81e5b570a049b62a0" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
    "010000000000000000000000", "02000000", "22b3f4cd1835e517741dfddccfa07fa4661b74cf" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
    "010000000000000000000000000000000200", "0300000000000000000000000000000004000000",
    "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59cabfe307" },
  { "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
    "0100000000000000000000000000000002000000", "030000000000000000000000000000000400",
    "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543" },
  { "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200", "e0eaf5284d884a0e77d31646", "", "",
    "169fbb2fbf389a995f6390af22228a62" },
  { "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269", "e4b47801afc0577e34699b9e", "4fbdc66f14",
    "671fdd", "0eaccb93da9bb81333aee0c785b240d319719d" },
  { "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3", "2f6d1f0434d8848c1177441f",
    "6787f3ea22c127aaf195", "195495860f04", "a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c" },
  { "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0", "9f572c614b4745914474e7c7",
    "489c8fde2be2cf97e74e932d4ed87d", "c9882e5386fd9f92ec", "0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2" },
  { "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235", "5c9e940fea2f582950a70d5a",
    "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f", "1db2316fd568378da107b52b",
    "8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5" },
  { "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb", "6de71860f762ebfbd08284e4",
    "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f", "21702de0de18baa9c9596291b08466",
    "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd" },
  { "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7", "028ec6eb5ea7e298342a94d4",
    "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7", "b202b370ef9768ec6561c4fe6b7e7296fa85",
    "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d0a49" },
  { "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23", "688089e55540db1872504e1c",
    "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541",
    "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
    "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a286594" },
  /* RFC 8452 C.3, counter wrap */
  { "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "",
    "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108",
    "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3eaffffffff000000000000000000000000" },
  { "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "",
    "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000",
    "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff000000000000000000000000" },
  /* computed with Python cryptography */
  { "af73cd4542b77e975d4d4ac44ff2c6e4d27f14240d537b96d74105043841e062", "ef19eb7d03fd3c0db155d1d8", "",
    "", "57a203d519e4bb328adfad161a656d77" },
  { "bdf58e99f8606c8c3b6a421c466c7f40be4973257fddf7164b87c1d0e2e39da3", "fad11fc8e14e6e4aab879aa9", "27595baf5d2a25b94e3fbac1",
    "", "44042c077803c070369938c8184d43e4" },
  { "06b264ab04914fe342e9b8713f13e9609f13494b5980b103fe925cedf91bba77", "dbddcfdd6041ae47f1189b60", "",
    "80", "408479d4716abd7e7365c6630da1c2a7c8" },
  { "ce082318ab7174ef1bc49705c20fdaddf7c7b59a10ad6a2db2e1c5349f058f49", "670cded7c98e7f504db545cf", "3251e1f5",
    "9bdc4d", "f08c8a3fafdb1dd3df322b2809c3c39064c3f4" },
  { "fd3b632d55dd65e065aa62a1b27de0ee643abf4291defbdcf877e5e227f8416c", "7ee0c2c8df10b9ad2da81381", "",
    "2b02fa2589cca618fdbddca6", "fe9527d19c04d01444768e99bad3a0ead8306710d531127059dde022" },
  { "dc3974ff86e6a9a8c6e3d21c01e254f4c1dd9ec306d03af9b6408fdebb05fd20", "7a092fb793f1de648a8a789c", "bd",
    "2b293458c24592d2d047e5045dce5f", "4d11f2808da7b598ad4d129b02c15a47f5c9418c9bce33860d9303b7b92337" },
  { "ca18f46b308975ee2e18509c9392ca8e678dc1a9c0102d41a05affd7293d0736", "e53e98c93a24f5fcffd467a9", "",
    "58c25d9ae3df1a7f1f5a428b1fc42ab2", "f9d1eeb604fa88052cd416921314ea753d3730d992f38295155b18e40928de09" },
  { "ec098f9e084133873db975b58f213f223ce642bc9bbc8c637c79ee9baca27442", "9103526b4398f8a232f89c8a", "885eb5dcbebbf658bf7800408d7f49e1",
    "5c72e5db50ef9fd1f54daad9293a0ede", "6530e9ed55c4204d33f042405c80112ec76573fa698c11987930634d497be9c9" },
  { "74bddcdee4160fc9c1e5b5a3d5854c835db973b5595e5e9c75c9afcceb2502b0", "494692ab6d5ef3650a6fb83c", "ce0346e8c2",
    "6ee29d688d33fffeaaa6b572a860a5f68b", "c87150e67bd16f44642800b8a886d9f20c5a6fe66e23b87689db018f8a8f4936dc" },
  { "2622ad683b00088739425e2f3606750ae384d94e973d6f256febf633b3682572", "8b02a24734ccaad803c6aa3d", "777a42333ccbd2e464409cda77925fd01f",
    "5a35973f10d42076535707c2c5ded67c1b96b326aade6903f19055b973c9a9", "4653b97d35ea0b307238c9ab5192ceb0d52a5154b3460c187abddc21c293df0cb249518bc03ca9d21308ac28f66d81" },
  { "1b7f40a6c20284ef376d4f43337d86f64dd512c23a6eaa22979b334b3079fbec", "47be93ce31d829ca5e04b13c", "a7ca7ff1cc31af7d5031b84dc678df4ed9e1072e4704ec19074550d01e9c788e",
    "0c6a20132776ef7bd8d7e37088ebaea01632b04ff9c5f8a3e43f26360e9b5d53", "1a4f87c94317734e07b1cf4e873f34fc504ace5db480ea1d23372dcf83d6208d235492dea93523837d4bf6c750df66d0" },
  { "afb0907553e6d892cd46af905c9e07a73794b2a7e53e499bfbc5a099a890ac3f", "5cd5b3c5595a1decb5c90fd4", "",
    "15c3216787c1c60d11d05d5644142e7b2f253b28fda41fc0ff3098811fca03d4f5", "4b6527a3b2bce62402cad0d8054a1ef8211c24949d5e1b10f11cecafc84a7c317c08b55e1d98d7b94549e737725ef5c646" },
  { "1e15728c3ea9789060506a383cc68b4826907cbc2603521345ee676b0d941263", "d4fca0f71d7148cfd6ed8bc3", "9fc6279880c4af33bfafd361dfa539f4152e3002a9681f1772be168776efb3953f69651eebbc8e57a5c13c947f73c7",
    "a0461799b9b1f076fc87c6f14ca00cb900fdc4bca3861185b6399e01efe768c0e6d7395d1c1c7f7a70303026f9d17e3b", "6194afae42aca2edaeb6b93d258f9a83c04b3d611d476a8e1365a644c9c16af5550315b80dd72687a06af660741e8b2fa0f59fe7591cc1ed44e098e49c9e5026" },
  { "b03044f3b979b3061f3fc5a6246f536e77894b8368c6f891c88f5e462877ee84", "c2be57a62f4e35e5fa48f39b", "3542651c276fa339fa235dc685652a",
    "b3f16e2b3a99da4e85d7c5ffed1ec027304e1fa79a4a6644971d654506a31bddfa5aa666604d6f3cfc1829940e7ddf546b4586463172a9286b23cf6431b7a3", "834f49b2954c467cc08b5124bab1b7bae98e01f4a4e7b24ac0c5c3000e6d07c0f40686d39ea393b07bf2085b267c4bf69bd84e8179003af58d1757ec6b583d2dc9c2b7a4e9b34220a3dc99ad83987e" },
  { "1ea5d94946b14ad24781c32280d612439e562f44b1f95ccf08e99aa1cb706d8b", "d71a54d64fa27e284fee7d83", "f8b4509cda9e6e9c96cffa80f654619e59dee713a735f2449e3f823648d733c075b91014799c1721f63169e80454d1a70e83d64fa06ebc67b38afbac6a954706",
    "7134346f50c18e1780c4c4f55145ecefc7c5563cd1eec6f2cb31223b394ac85c21e59b2a4e4ac5db5cddd2994aee864cae8c537701fbc9c5e86c46f9874b7d86", "b583a25fd1be6d2890f1a27a3ffbe335774b750e4b9da9c20f4bacc14d29bc3124fe47ff31af6eeda9af2f49541e00fbd3aa9bce3b5c3c8bd96c7bd8c3e1eb2767d8ff0405ac6f6b08d10f51be34edeb" },
  { "4caedd249866a124140de582167117cf2afaaa1cdb6086bd689829e77545b20a", "18d854dd85389588ed38a01a", "31f756791bacee78c7",
    "d3d1873668190701872868d7880669696599138a1375920d74e9878db114deae86cc36169fa465929a978df1a2fc72b8e0b98ba3f7f8a25386af8e6392887e83589aa34bb0b560ea63ad3226e6b552756691f7c280531b8d1ed7f81c03991b79f88a5d18", "54a0bd3a9275c6925400911fcd8b4f7d7e13cfc38092a5fb76f3a3700c04eb2f4c6a2feb305e279912370325973be95f3dfe3ac6ab2a60831d2123320dd68bec6290215079d05450ded5ce3c2e3d5999a085bb10b9acd2aab94d7dbb5bdce6e71e9330e267def557e8ed666124f254997d540fc7" },
  { "eba399214260e09af797e47c43ef4073d8fe65d798838ac319ea61529d118382", "a7dd06eacb7c3c9e1de26b29", "9f4f63",
    "bb08ccb8d1131374b641c7fd1d5cdcf81a24c2d73a2f1c809c27ba75cbb91d9a69c98c89e7477cb1c694e25853619c9442d56e518e8c3781667b4efdb48b167b204450bba28140ae135e54baee8c6ffc7d4818a5f01ba8ad067eea0234ddbb4b0b2ffc60efb79f121d73d33206888bac87d35933074c58c66ee24c76bd3a9de8d6", "3735f126bae82018d4aaf6f671e792e9dd9f6029dc4b39e5021af344b5be476ffa374f58f97650db47ec205e37f16563dfc32464aefd0d88439a4fd94ddd4f6b9307b71fbc31207aa6e4b3f071d0931dc8c41216a579cd4d551b7814c7fc507ac90c9ce4835e6aeb3e3aad603119bd9bf6c7e937829ff024cb296939e8524ab94b2528d4c1815016f9329cc629515cef82" },
  { "71c9f8cd3a74d11d7cff1c90a8a874bb87dada125fb18430db0986f6d216335a", "13977249ab678ea84980a4c0", "",
    "5fae8dbfabe13d9bbc99bef2d079728c152ff802b8055c2c13785a29de51ed961264049bda9b9dfd5aa6c4290587e7597643394bc72086366513d298b867e4367c9a88638ae4b74ce13aab9b89dfb0dbcc2cfa80296ebe111d57ea69696a7af6c178cbfde3fa4d113de256bb1d5b485d35994d55a068c43c38e6eeec8cc105c92779bec3eb3594fdb7344cf40815eb5d0a1d1a6b807fe8b7f18bc9553fd6839b51ac3dc36f5bf0b6b7c3a851a53e2ea8e853d73e81c4fa5d23d70c5feebb074363eca9403103fb21ffef8b72cd1497703dbe7b99b6b21837c3c5cc5eced7064ec0b0ce45cde1009acf0ec378d2d22dbf2109937d1117f22a6dbecee4c38a4c", "1c9f9440c60fd1933178ba26df0ed864bd8495814e5d2e44dcbfada1ca3428695f3d22bae093cff95c6317f6f0eb583db156f0a3fe89a82c2d346e999207e905a95be8afc3b16808b2629d86107cdce050b2bb2a0b72a143cd10af624908e5a3b6ee513b559803ca1781c6c5213a6fd753147e19c845e46af937da7e26cd8da2cb5f39612b7aef6f7d2710d16cc8090672848545d5887c0f383eddad477cb31692cc0d6a45466ac29bc9106a846ce61be4ff72dfa08163f71f90d0257d187a3ee769807905bde8dc44cd0b0f92048537b7d513d107ef17ab6674925f995c1d86c07568c879efbfd2a2279ddafb3e20addc6e647a627dce282a08c29f4412a1c451a00f460eb6264548b55b98bf7995" },
  { "2865151397f042826c91f1055cfc2405883b71a61282d2a3d24c995d5d062a89", "551ece5ad32afbda79c3f0be", "9a598f820ee822d11493c4c6273e350b",
    "e099b2a0dac7847423670bd567cccb6c42f052bbaedc308df01f0e6576503a630c02c25a3841daa2932bd1d9b511cfc8f75d6c95dcde5310e406fddd58e8e5a4e783a5251047039bbcc79bf26b96605f3b5db46291696523368c31b7e356df21dc3390cfa7953f6673cd7f5d1f02ea76a913d7ccba53d5b0cee52e83500b3536ba03d7c2bbbc6344a58823162e525a925a8fc673d0f31f84530acf38818fb5007227d7db044f80e206a4ec0b043e54216cdcd06de857e6fc9ea9498eb5a2cf563fd695a55461e480b0eda37cdb9f144c8edcbd8c41bde9cff0aa590d8585dd1267695226d48f394d48fb473b2f885eb0267117e90a94041ef8526eb72a09df7b", "8383b853dbcf8c762712981c654a856ba4d50ab2a8b90f11a1f317a929b89bc0e060bbcda8005fc6cc63cfa277fa82950486810fc4e1fc6e8b3c4c6bd7abfd42b8e2b833d83f4b896902ab872fca8c782e15a267b813f77789da774b822d371a68f45a72d794ce71b2d08a50816c5b4a0ff4bec16aa4e8c2b486c87f300f30fc9cbd678f8a43905615d56270efe8a2ceba768de7f2a6439fae207f1cb1098ca6fde44bc7727ecb034579c2584ad2cce7d8cc7aa7adac73d64546e93414cd7311ac74b6155b5f35270422c140f4c4da661a4dbef0fc579fc3ca7168bf5caa6dea25fb739f69ed009190c557be1cccc41b6827af18faaae87b4f7832ad911f2a5a98ba37b5de5a71c47d1adb07c0fb36dc" },
  { "22419f8f4553ebcb2fe7131059ede2ef61454145045e38dc0428754d2dcae32b", "b5e9ff1958ae67a1a0924c11", "35e94f71b2b94398d107e41840bdef42ab9f6a45",
    "afc0ccd862b6611802a751fb6b6b84b2bf9fb9dac887c26c7a26083c8735c6ade3e87892785de8eb73530e009004ca640484972dc144353546624a14caad6c07008667521f8cee5e2a444e063fb7897c93afde66d5074efb969aebed394f2a0972405446acfabb77a20249d76f0dc674c7deccc192efb1157264c3f639e1da80c01004210212a3ee60608f293269b5347a4d489f142b029239014666e457233f3352c755e655b1a5a77d0895048011b479d3b1af50cb25734d6ade860815583a64ff3d86a21dff81c44d2a75fc26ced6c6648cbabe19d627ceacc0ec35afb20e64013fdaab602f9b4f892a7e2236cd27c1d60b77aa344d8a4cf9f2fdaa67f0d090", "03604b5749448ccc9fb37a7bdc1f906b0cbaa6724438544f6e56abac88da9afc24cd624875e6351a12ae2847ba94b2224bab76b017efb5783d070414e3bf528512b656da5ef67689cdad44bb994a5c956b9b4330fe8e267302b9c07865cf4de96d31e1fa60c74a90a9dd2206e82712ef7d499d641624a7e793abb239e35135a8ed69743b4c5eec20a6b999fa24efbd6a523009617144c2a3545d897f6122828aadcb4760ffe56420c265ad27539eb9daa0b7014c0874264057f41c87784029be4b9168f6c4303b13ccec6f0ea5478ed30acd310bae33b338b1380567afc217bc762ae4337b2d16cbf4d2d911e14338ef08f260542a80ee5ded7505fb1663586304da0b298e8f87dcf76501e8bf66c33042" },
};

/*
** AES-256-GCM-SIV cases of Wycheproof (github.com/C2SP/wycheproof, testvectors_v1/aes_gcm_siv_test.json)
** with the flags WrappedIv (valid: the 32-bit counter wraps around) and ModifiedTag (invalid: one or
** more bits of the tag are flipped, open must fail and must not return any plaintext).
** tcId, key, nonce, AAD, plaintext, ciphertext || tag, valid
*/
static const struct { int tcId; const char *key, *nonce, *aad, *plain, *sealed; int valid; } gcmSivWycheproof[] =
{
  { 164, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "010101010101010101010101",
    "40c32e00c2fdab59c1a1c573b46b5068",
    "bdd411814564c4218d224d50591c818855a862a0a519ac0b3d71a2edb12aa71eb81959bcc6b84c45aa424c9aca0b7bdd",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    1 },
  { 165, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000000000000000000000",
    "2cc3a1973e0560f7224a394e52fa8488",
    "d04846a01f472262e60a1cb4cfcbdcb05c3f819628a3a49395c5dae96c434b2417ce071699afa74a60c32c0bafd9c01a",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff",
    1 },
  { 166, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "010101010101010101010101",
    "2e34d12622a441b557eeb1d647c6cb73",
    "79637cee9decf33e3080de3d2c55bd21cd529ba8080b583edb6cfe13cda04bd00debe58b8cd48d6e02a1ecfc4d87923a",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fefffffffefffffffefffffffeffffff",
    1 },
  { 167, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000000000000000000000",
    "0814a95481bf915a4097949e3525c7e7",
    "6492a73880dac7f36743715b0fc7063d3e46a25044310bba5849ed88bfcb54b0adbe3978040bda849906e1aa09d1a8e3",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffff7f00112233445566778899aabb",
    1 },
  { 168, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "010101010101010101010101",
    "b691ef42f2ab8d1b4a581bb08394b13a",
    "7848d9e872f40bca1b82a4e7185fb75193b3496cc1dc2a72b86ed156ab8389e71687ed25eb6485e66561fa8c39853368",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffff7f0011223344556677",
    1 },
  { 169, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "a5b997fe28ddf26fe182eb8db608bd14", "f663044a4e7dd822aba0b7de2d869981",
    "0000000000000000000000000000000013a1883272188b4c8d2727178198fe95", 0 },
  { 170, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "5906c4d15a8dc345026d29c98e55cfcd", "759dfbbb8a251ccc", "000000000000000000000000000000000000000000000000", 0 },
  { 171, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "de645c9a49b8e777ca18c54048b7bde8", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
  { 172, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "3dbceccc23f7bc994c4df048e43c59fb", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 173, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "369e1e751ac0d45a5401775304dbe1a0", "f663044a4e7dd822aba0b7de2d869981",
    "0000000000000000000000000000000013a1883272188b4c8d2727178198fe95", 0 },
  { 174, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "0bf63034cdfd77e90b94936583199da8", "759dfbbb8a251ccc", "000000000000000000000000000000000000000000000000", 0 },
  { 175, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "2241caabc859139436c23a274eebf0d1", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 176, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "9b6589f03d26c71a67ffb6c9bea6fdb5", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
  { 177, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "086f2deb0c0e871a2a38df9adc1f3e9d", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 178, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "9dbcadbc6f27b088037e6f738b16c105", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 179, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "d44919c638e293a9ce8647d00b8e58c5", "759dfbbb8a251ccc", "000000000000000000000000000000000000000000000000", 0 },
  { 180, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "c0537898455fa05d51f7554f12596617", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
  { 181, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "45ba6c8dd2f6364e32e43429eee15faa", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 182, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "1d6b385d7eee3e166a8e2776755602fd", "f663044a4e7dd822aba0b7de2d869981",
    "0000000000000000000000000000000013a1883272188b4c8d2727178198fe95", 0 },
  { 183, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "7a972ec263df56ebe4f001a718e47200", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
  { 184, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "fd9d1ffd0dcfe6f0a1c2695477b1cd96", "f663044a4e7dd822aba0b7de2d869981",
    "0000000000000000000000000000000013a1883272188b4c8d2727178198fe95", 0 },
  { 185, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "7e5cbe5af5820f0757072bab5758d327", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
  { 186, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "9294a1bd55de4c4f642ed5b9b2058da6", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 187, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "a3afb9ce48b7cd22dddd8f37cd451cd8", "759dfbbb8a251ccc", "000000000000000000000000000000000000000000000000", 0 },
  { 188, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "f4cf766370972a85f9b1f511e5ea693a", "f663044a4e7dd822aba0b7de2d869981",
    "0000000000000000000000000000000013a1883272188b4c8d2727178198fe95", 0 },
  { 189, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "ddb6b2168243150206fe5c513f7e6c37", "759dfbbb8a251ccc", "000000000000000000000000000000000000000000000000", 0 },
  { 190, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "63d504e4e4729cb5c8a29bc08723efe4", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
  { 191, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "1fed71d3675dd386d3c65664710b3eba", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 192, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "454aac70fc89f9de4e045e46bcb048c0", "f663044a4e7dd822aba0b7de2d869981",
    "0000000000000000000000000000000013a1883272188b4c8d2727178198fe95", 0 },
  { 193, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "8ecff481b5c13a653d624e3441c6573c", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
  { 194, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "0591c8849ce9f1aaee5769eb3e28d51a", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 195, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "c61613923b69169d512bdc788bfa62a3", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 196, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "e5879b6d2d5bb63b290b49a08e631f6a", "f663044a4e7dd822aba0b7de2d869981",
    "0000000000000000000000000000000013a1883272188b4c8d2727178198fe95", 0 },
  { 197, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "00ea3f6b86feece042d68677fd378635", "759dfbbb8a251ccc", "000000000000000000000000000000000000000000000000", 0 },
  { 198, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "5a95d77d7e02d9b92c59b9618f276f38", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
  { 199, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "498eeebd21577b187a36c59285864cd2", "", "0987e35e40981a2730c1740c7201731f", 0 },
  { 200, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "3305208cc80840a9b49616b1109ef788", "f663044a4e7dd822aba0b7de2d869981",
    "0000000000000000000000000000000013a1883272188b4c8d2727178198fe95", 0 },
  { 201, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "5e53ca98c89c017426e4bc07090840b0", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
  { 202, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "000000000000000000000000",
    "55a2987aa94bf46ad1b6d253a44c1622", "49861b1fb6bcf8e4", "ffffffffffffffffffffffffffffffffffffffffffffffff", 0 },
};

static void testKnownAnswers(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32], iv[16], plain[64], cipher[80], buf[80], aad[32], nonce[24], tag[16];
  AesCtx ctx;
  size_t i, g;

  for (i = 0; i < sizeof(blockVectors) / sizeof(blockVectors[0]); i++)
  {
    int keyLen = fromHex(blockVectors[i].key, key);
    fromHex(blockVectors[i].plain, plain);
    fromHex(blockVectors[i].cipher, cipher);
    CHECK(sqlite3mcAesCbcInitImpl(&ctx, key, keyLen, AES_FOR_ENCRYPT, impl) == SQLITE_OK, "%s: init AES-%d", name, keyLen * 8);
    CHECK(sqlite3mcAesEncryptBlocks(&ctx, plain, buf, 1) == SQLITE_OK && memcmp(buf, cipher, 16) == 0,
          "%s: FIPS-197 AES-%d", name, keyLen * 8);
    sqlite3mcAesCbcWipe(&ctx);
  }

  for (i = 0; i < sizeof(cbcVectors) / sizeof(cbcVectors[0]); i++)
  {
    int keyLen = fromHex(cbcVectors[i].key, key);
    int len;
    fromHex(cbcVectors[i].iv, iv);
    len = fromHex(cbcVectors[i].plain, plain);
    fromHex(cbcVectors[i].cipher, cipher);
    sqlite3mcAesCbcInitImpl(&ctx, key, keyLen, AES_FOR_BOTH, impl);
    memcpy(buf, plain, len);
    CHECK(sqlite3mcAesCbcEncrypt(&ctx, iv, buf, len) == SQLITE_OK && memcmp(buf, cipher, len) == 0,
          "%s: CBC AES-%d encrypt, %d bytes", name, keyLen * 8, len);
    CHECK(sqlite3mcAesCbcDecrypt(&ctx, iv, buf, len) == SQLITE_OK && memcmp(buf, plain, len) == 0,
          "%s: CBC AES-%d decrypt, %d bytes", name, keyLen * 8, len);
    sqlite3mcAesCbcWipe(&ctx);
  }

  for (g = 0; g < sizeof(ghashIds) / sizeof(ghashIds[0]); g++)
  {
    if (sqlite3mcAesGhashSelect(ghashIds[g]) != 0) continue;
    for (i = 0; i < sizeof(xaesVectors) / sizeof(xaesVectors[0]); i++)
    {
      int aadLen, len;
      fromHex(xaesVectors[i].key, key);
      fromHex(xaesVectors[i].nonce, nonce);
      aadLen = fromHex(xaesVectors[i].aad, aad);
      len = fromHex(xaesVectors[i].plain, plain);
      fromHex(xaesVectors[i].sealed, cipher);
      CHECK(sqlite3mcAesXaesInitImpl(&ctx, key, impl) == SQLITE_OK, "%s: XAES init", name);
      CHECK(sqlite3mcAesXaesSeal(&ctx, nonce, aad, aadLen, plain, len, buf, tag) == SQLITE_OK &&
            memcmp(buf, cipher, len) == 0 && memcmp(tag, cipher + len, 16) == 0,
            "%s/%s: XAES-256-GCM test vector %d", name, ghashNames[ghashIds[g]], (int) i + 1);
      CHECK(sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, buf, len, tag, buf) == SQLITE_OK && memcmp(buf, plain, len) == 0,
            "%s/%s: XAES-256-GCM test vector %d, open", name, ghashNames[ghashIds[g]], (int) i + 1);
      sqlite3mcAesCbcWipe(&ctx);
    }
  }
  sqlite3mcAesGhashSelect(AES_GHASH_AUTO);
}

static void testKnownAnswersGcmSiv(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32], nonce[12], aad[64], plain[320], sealed[336], buf[336], tag[16];
  AesCtx ctx;
  size_t i, g;

  for (g = 0; g < sizeof(ghashIds) / sizeof(ghashIds[0]); g++)
  {
    if (sqlite3mcAesGhashSelect(ghashIds[g]) != 0) continue;
    for (i = 0; i < sizeof(gcmSivVectors) / sizeof(gcmSivVectors[0]); i++)
    {
      int aadLen, len;
      fromHex(gcmSivVectors[i].key, key);
      fromHex(gcmSivVectors[i].nonce, nonce);
      aadLen = fromHex(gcmSivVectors[i].aad, aad);
      len = fromHex(gcmSivVectors[i].plain, plain);
      fromHex(gcmSivVectors[i].sealed, sealed);
      CHECK(sqlite3mcAesGcmSivInitImpl(&ctx, key, impl) == SQLITE_OK, "%s: GCM-SIV init", name);
      CHECK(sqlite3mcAesGcmSivSeal(&ctx, nonce, aad, aadLen, plain, len, buf, tag) == SQLITE_OK &&
            memcmp(buf, sealed, len) == 0 && memcmp(tag, sealed + len, 16) == 0,
            "%s/%s: AES-256-GCM-SIV test vector %d", name, ghashNames[ghashIds[g]], (int) i + 1);
      CHECK(sqlite3mcAesGcmSivOpen(&ctx, nonce, aad, aadLen, buf, len, tag, buf) == SQLITE_OK && memcmp(buf, plain, len) == 0,
            "%s/%s: AES-256-GCM-SIV test vector %d, open", name, ghashNames[ghashIds[g]], (int) i + 1);
      sqlite3mcAesCbcWipe(&ctx);
    }
  }
  sqlite3mcAesGhashSelect(AES_GHASH_AUTO);
}

/*
** Wycheproof: valid cases must give ciphertext and tag, invalid ones must be rejected
** and must not leave any plaintext in the output buffer.
*/
static void testWycheproofGcmSiv(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32], nonce[12], aad[64], plain[64], sealed[80], buf[80], tag[16];
  AesCtx ctx;
  size_t i, g;

  for (g = 0; g < sizeof(ghashIds) / sizeof(ghashIds[0]); g++)
  {
    if (sqlite3mcAesGhashSelect(ghashIds[g]) != 0) continue;
    for (i = 0; i < sizeof(gcmSivWycheproof) / sizeof(gcmSivWycheproof[0]); i++)
    {
      int aadLen, len;
      fromHex(gcmSivWycheproof[i].key, key);
      fromHex(gcmSivWycheproof[i].nonce, nonce);
      aadLen = fromHex(gcmSivWycheproof[i].aad, aad);
      len = fromHex(gcmSivWycheproof[i].plain, plain);
      fromHex(gcmSivWycheproof[i].sealed, sealed);
      CHECK(sqlite3mcAesGcmSivInitImpl(&ctx, key, impl) == SQLITE_OK, "%s: GCM-SIV init", name);
      if (gcmSivWycheproof[i].valid)
      {
        CHECK(sqlite3mcAesGcmSivSeal(&ctx, nonce, aad, aadLen, plain, len, buf, tag) == SQLITE_OK &&
              memcmp(buf, sealed, len) == 0 && memcmp(tag, sealed + len, 16) == 0,
              "%s/%s: Wycheproof tcId %d, seal", name, ghashNames[ghashIds[g]], gcmSivWycheproof[i].tcId);
        CHECK(sqlite3mcAesGcmSivOpen(&ctx, nonce, aad, aadLen, sealed, len, sealed + len, buf) == SQLITE_OK &&
              memcmp(buf, plain, len) == 0,
              "%s/%s: Wycheproof tcId %d, open", name, ghashNames[ghashIds[g]], gcmSivWycheproof[i].tcId);
      }
      else
      {
        memset(buf, 0x5a, sizeof(buf));
        CHECK(sqlite3mcAesGcmSivOpen(&ctx, nonce, aad, aadLen, sealed, len, sealed + len, buf) == AES_GCM_TAG_MISMATCH &&
              allZero(buf, len),
              "%s/%s: Wycheproof tcId %d (modified tag) accepted or plaintext returned",
              name, ghashNames[ghashIds[g]], gcmSivWycheproof[i].tcId);
      }
      sqlite3mcAesCbcWipe(&ctx);
    }
  }
  sqlite3mcAesGhashSelect(AES_GHASH_AUTO);
}

/*
** The 32-bit counter of AES-GCM-SIV wraps around (RFC 8452, C.3). Expected keystream
** computed with an independent implementation (AES-ECB of Python cryptography), counter
** blocks 0xfffffffd, 0xfffffffe, 0xffffffff, 0, 1, ...
*/
static void testGcmSivCounterWrap(int impl)
{
  const char* name = implNames[impl];
  static const char* keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  static const char* tagHex = "fdffffff0405060708090a0b0c0d0e0f";
  static const char* ksHex =
    "14b793e17f3adba7a9a5f3503281219b1ab87f42b06715f67c25fc4a7dd6f1326dc6dfe6d2804843264e8673a83f5160"
    "ec2fcbf6fbc7c82ed10d5d3d901d4912269f437ab78556b93b501502407025f1b5dc9aba5487d6f47701611d29b63a44"
    "acc605022e0c92982b1d2699a819918e10ffdff0abf136c9333d64598af3b510df995b72e3348cbfcb05a53cf34929fd"
    "ea45ae6cca32ef6bcaf0bc3dbb9e0ea6d7a47f76243fd3d99711038cce78c010930b223485dd47be85e70471419b4acc";
  unsigned char key[32], tag[16], ks[192], zero[192], out[192];
  AesCtx ctx;
  int len = fromHex(ksHex, ks);
  fromHex(keyHex, key);
  fromHex(tagHex, tag);
  memset(zero, 0, sizeof(zero));
  CHECK(len == 192, "%s: wrap vector length", name);
  CHECK(sqlite3mcAesCbcInitImpl(&ctx, key, 32, AES_FOR_ENCRYPT, impl) == SQLITE_OK, "%s: wrap init", name);
  CHECK(aesGcmSivCtrXor(&ctx, tag, zero, len, out) == SQLITE_OK && memcmp(out, ks, len) == 0,
        "%s: GCM-SIV counter wrap", name);
  sqlite3mcAesCbcWipe(&ctx);
}

/*
** 2. All backends against each other
*/
#define MAX_LEN 4200
static unsigned char data[MAX_LEN + 32];
static unsigned char ref[MAX_LEN + 32];
static unsigned char work[MAX_LEN + 32];

static void testCrossCbc(int rounds)
{
  unsigned char key[32], iv[16], ivCopy[16];
  AesCtx ctx;
  int r, k;
  for (r = 0; r < rounds; r++)
  {
    int keyLen = (r & 1) ? 32 : 16;
    int len = (r % 5 == 0) ? 16 * (1 + rnd() % (MAX_LEN / 16)) : 16 + rnd() % (MAX_LEN - 15);
    int offset = rnd() % 16;
    rndFill(key, keyLen);
    rndFill(iv, 16);
    rndFill(data, len);
    memcpy(ivCopy, iv, 16);
    for (k = 0; k < implCount; k++)
    {
      unsigned char* p = work + offset;
      memcpy(p, data, len);
      sqlite3mcAesCbcInitImpl(&ctx, key, keyLen, AES_FOR_BOTH, impls[k]);
      CHECK(sqlite3mcAesCbcEncrypt(&ctx, iv, p, len) == SQLITE_OK, "%s: CBC encrypt, %d bytes", implNames[impls[k]], len);
      if (k == 0)
        memcpy(ref, p, len);
      else
        CHECK(memcmp(ref, p, len) == 0, "%s: CBC AES-%d, %d bytes, offset %d differs from %s",
              implNames[impls[k]], keyLen * 8, len, offset, implNames[impls[0]]);
      CHECK(sqlite3mcAesCbcDecrypt(&ctx, iv, p, len) == SQLITE_OK && memcmp(p, data, len) == 0,
            "%s: CBC AES-%d, %d bytes, decrypt", implNames[impls[k]], keyLen * 8, len);
      CHECK(memcmp(iv, ivCopy, 16) == 0, "%s: IV changed", implNames[impls[k]]);
      sqlite3mcAesCbcWipe(&ctx);
    }
  }
}

static void testCrossBlocks(int rounds)
{
  unsigned char key[32];
  AesCtx ctx;
  int r, k;
  for (r = 0; r < rounds; r++)
  {
    int keyLen = (r & 1) ? 32 : 16;
    size_t blocks = 1 + rnd() % 64;
    int offset = rnd() % 16;
    rndFill(key, keyLen);
    rndFill(data, blocks * 16);
    for (k = 0; k < implCount; k++)
    {
      unsigned char* out = work + offset;
      sqlite3mcAesCbcInitImpl(&ctx, key, keyLen, AES_FOR_ENCRYPT, impls[k]);
      CHECK(sqlite3mcAesEncryptBlocks(&ctx, data, out, blocks) == SQLITE_OK, "%s: block encryption", implNames[impls[k]]);
      if (k == 0)
        memcpy(ref, out, blocks * 16);
      else
        CHECK(memcmp(ref, out, blocks * 16) == 0, "%s: %d blocks AES-%d differ from %s",
              implNames[impls[k]], (int) blocks, keyLen * 8, implNames[impls[0]]);
      memcpy(out, data, blocks * 16);
      sqlite3mcAesEncryptBlocks(&ctx, out, out, blocks);
      CHECK(memcmp(ref, out, blocks * 16) == 0, "%s: %d blocks in place", implNames[impls[k]], (int) blocks);
      sqlite3mcAesCbcWipe(&ctx);
    }
  }
}

/*
** 2. and 3.: XAES-256-GCM with every backend and every GHASH variant
*/
static void testCrossXaes(int rounds)
{
  unsigned char key[32], nonce[24], aad[40], tag[16], refTag[16], badTag[16];
  AesCtx ctx;
  int r, k;
  size_t g;
  for (r = 0; r < rounds; r++)
  {
    size_t len = rnd() % (MAX_LEN + 1);
    size_t aadLen = rnd() % sizeof(aad);
    int first = 1;
    rndFill(key, 32);
    rndFill(nonce, 24);
    rndFill(aad, aadLen);
    rndFill(data, len);
    for (k = 0; k < implCount; k++)
    {
      for (g = 0; g < sizeof(ghashIds) / sizeof(ghashIds[0]); g++)
      {
        const char* name = implNames[impls[k]];
        const char* gname = ghashNames[ghashIds[g]];
        int rc;
        if (sqlite3mcAesGhashSelect(ghashIds[g]) != 0) continue;
        sqlite3mcAesXaesInitImpl(&ctx, key, impls[k]);
        CHECK(sqlite3mcAesXaesSeal(&ctx, nonce, aad, aadLen, data, len, work, tag) == SQLITE_OK, "%s/%s: XAES seal", name, gname);
        if (first)
        {
          memcpy(ref, work, len);
          memcpy(refTag, tag, 16);
          first = 0;
        }
        else
        {
          CHECK(memcmp(ref, work, len) == 0 && memcmp(refTag, tag, 16) == 0,
                "%s/%s: XAES, %d bytes, AAD %d bytes differs", name, gname, (int) len, (int) aadLen);
        }
        CHECK(sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, work, len, tag, work) == SQLITE_OK && memcmp(work, data, len) == 0,
              "%s/%s: XAES open in place, %d bytes", name, gname, (int) len);

        /* Tag, ciphertext, AAD and nonce changed: refused, no plaintext */
        memcpy(badTag, tag, 16);
        badTag[rnd() % 16] ^= (unsigned char) (1 << (rnd() % 8));
        memset(work, 0x55, len);
        rc = sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, ref, len, badTag, work);
        CHECK(rc == AES_GCM_TAG_MISMATCH && allZero(work, len), "%s/%s: changed tag accepted", name, gname);
        if (len > 0)
        {
          size_t pos = rnd() % len;
          ref[pos] ^= 0x01;
          memset(work, 0x55, len);
          rc = sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, ref, len, tag, work);
          CHECK(rc == AES_GCM_TAG_MISMATCH && allZero(work, len), "%s/%s: changed ciphertext accepted", name, gname);
          ref[pos] ^= 0x01;
        }
        if (aadLen > 0)
        {
          aad[0] ^= 0x80;
          rc = sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, ref, len, tag, work);
          CHECK(rc == AES_GCM_TAG_MISMATCH, "%s/%s: changed AAD accepted", name, gname);
          aad[0] ^= 0x80;
        }
        nonce[23] ^= 0x01;
        rc = sqlite3mcAesXaesOpen(&ctx, nonce, aad, aadLen, ref, len, tag, work);
        CHECK(rc == AES_GCM_TAG_MISMATCH, "%s/%s: changed nonce accepted", name, gname);
        nonce[23] ^= 0x01;
        sqlite3mcAesCbcWipe(&ctx);
      }
    }
  }
  sqlite3mcAesGhashSelect(AES_GHASH_AUTO);
}

/* AES-256-GCM-SIV: all backends and GHASH variants agree, tampering is detected */
static void testCrossGcmSiv(int rounds)
{
  unsigned char key[32], nonce[12], aad[40], tag[16], refTag[16], badTag[16];
  AesCtx ctx;
  int r, k;
  size_t g;
  for (r = 0; r < rounds; r++)
  {
    size_t len = rnd() % (MAX_LEN + 1);
    size_t aadLen = rnd() % sizeof(aad);
    int first = 1;
    rndFill(key, 32);
    rndFill(nonce, 12);
    rndFill(aad, aadLen);
    rndFill(data, len);
    for (k = 0; k < implCount; k++)
    {
      for (g = 0; g < sizeof(ghashIds) / sizeof(ghashIds[0]); g++)
      {
        const char* name = implNames[impls[k]];
        const char* gname = ghashNames[ghashIds[g]];
        int rc;
        if (sqlite3mcAesGhashSelect(ghashIds[g]) != 0) continue;
        sqlite3mcAesGcmSivInitImpl(&ctx, key, impls[k]);
        CHECK(sqlite3mcAesGcmSivSeal(&ctx, nonce, aad, aadLen, data, len, work, tag) == SQLITE_OK, "%s/%s: GCM-SIV seal", name, gname);
        if (first)
        {
          memcpy(ref, work, len);
          memcpy(refTag, tag, 16);
          first = 0;
        }
        else
        {
          CHECK(memcmp(ref, work, len) == 0 && memcmp(refTag, tag, 16) == 0,
                "%s/%s: GCM-SIV, %d bytes, AAD %d bytes differs", name, gname, (int) len, (int) aadLen);
        }
        CHECK(sqlite3mcAesGcmSivOpen(&ctx, nonce, aad, aadLen, work, len, tag, work) == SQLITE_OK && memcmp(work, data, len) == 0,
              "%s/%s: GCM-SIV open in place, %d bytes", name, gname, (int) len);

        memcpy(badTag, tag, 16);
        badTag[rnd() % 16] ^= (unsigned char) (1 << (rnd() % 8));
        memset(work, 0x55, len);
        rc = sqlite3mcAesGcmSivOpen(&ctx, nonce, aad, aadLen, ref, len, badTag, work);
        CHECK(rc == AES_GCM_TAG_MISMATCH && allZero(work, len), "%s/%s: GCM-SIV changed tag accepted", name, gname);
        if (len > 0)
        {
          size_t pos = rnd() % len;
          ref[pos] ^= 0x01;
          memset(work, 0x55, len);
          rc = sqlite3mcAesGcmSivOpen(&ctx, nonce, aad, aadLen, ref, len, tag, work);
          CHECK(rc == AES_GCM_TAG_MISMATCH && allZero(work, len), "%s/%s: GCM-SIV changed ciphertext accepted", name, gname);
          ref[pos] ^= 0x01;
        }
        if (aadLen > 0)
        {
          aad[0] ^= 0x80;
          rc = sqlite3mcAesGcmSivOpen(&ctx, nonce, aad, aadLen, ref, len, tag, work);
          CHECK(rc == AES_GCM_TAG_MISMATCH, "%s/%s: GCM-SIV changed AAD accepted", name, gname);
          aad[0] ^= 0x80;
        }
        nonce[11] ^= 0x01;
        rc = sqlite3mcAesGcmSivOpen(&ctx, nonce, aad, aadLen, ref, len, tag, work);
        CHECK(rc == AES_GCM_TAG_MISMATCH, "%s/%s: GCM-SIV changed nonce accepted", name, gname);
        nonce[11] ^= 0x01;
        sqlite3mcAesCbcWipe(&ctx);
      }
    }
  }
  sqlite3mcAesGhashSelect(AES_GHASH_AUTO);
}

/*
** Nonce reuse (the point of GCM-SIV): the same nonce with different plaintexts or AADs
** must still work and give different tags; identical input gives identical output.
*/
static void testGcmSivNonceReuse(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32], nonce[12], p1[64], p2[64], c1[64], c2[64], t1[16], t2[16], back[64];
  AesCtx ctx;
  rndFill(key, 32);
  rndFill(nonce, 12);
  rndFill(p1, 64);
  memcpy(p2, p1, 64);
  p2[63] ^= 1;
  sqlite3mcAesGcmSivInitImpl(&ctx, key, impl);
  CHECK(sqlite3mcAesGcmSivSeal(&ctx, nonce, NULL, 0, p1, 64, c1, t1) == SQLITE_OK &&
        sqlite3mcAesGcmSivSeal(&ctx, nonce, NULL, 0, p2, 64, c2, t2) == SQLITE_OK, "%s: nonce reuse seal", name);
  CHECK(memcmp(t1, t2, 16) != 0 && memcmp(c1, c2, 16) != 0, "%s: nonce reuse leaks equal prefix", name);
  CHECK(sqlite3mcAesGcmSivOpen(&ctx, nonce, NULL, 0, c1, 64, t1, back) == SQLITE_OK && memcmp(back, p1, 64) == 0 &&
        sqlite3mcAesGcmSivOpen(&ctx, nonce, NULL, 0, c2, 64, t2, back) == SQLITE_OK && memcmp(back, p2, 64) == 0,
        "%s: nonce reuse open", name);
  sqlite3mcAesCbcWipe(&ctx);
}

static void testPagesGcmSiv(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32], page[4096], enc[4096], reserve[AES_GCMSIV_RESERVE_SIZE];
  size_t len = sizeof(page) - AES_GCMSIV_RESERVE_SIZE;
  AesCtx ctx;
  rndFill(key, 32);
  rndFill(page, sizeof(page));
  rndFill(reserve, AES_GCMSIV_NONCE_SIZE);
  sqlite3mcAesGcmSivInitImpl(&ctx, key, impl);
  CHECK(sqlite3mcAesGcmSivPageSeal(&ctx, 7, page, len, enc, reserve) == SQLITE_OK, "%s: GCM-SIV page seal", name);
  CHECK(sqlite3mcAesGcmSivPageOpen(&ctx, 7, enc, len, work, reserve) == SQLITE_OK && memcmp(work, page, len) == 0,
        "%s: GCM-SIV page open", name);
  CHECK(sqlite3mcAesGcmSivPageOpen(&ctx, 8, enc, len, work, reserve) == AES_GCM_TAG_MISMATCH && allZero(work, len),
        "%s: GCM-SIV page with wrong page number accepted", name);
  sqlite3mcAesCbcWipe(&ctx);
}

/* SQLCipher 5 page functions: page number is authenticated */
static void testPages(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32], page[4096], enc[4096], reserve[AES_XAES_RESERVE_SIZE];
  size_t len = sizeof(page) - AES_XAES_RESERVE_SIZE;
  AesCtx ctx;
  rndFill(key, 32);
  rndFill(page, sizeof(page));
  rndFill(reserve, AES_XAES_NONCE_SIZE);
  sqlite3mcAesXaesInitImpl(&ctx, key, impl);
  CHECK(sqlite3mcAesXaesPageSeal(&ctx, 7, page, len, enc, reserve) == SQLITE_OK, "%s: page seal", name);
  CHECK(sqlite3mcAesXaesPageOpen(&ctx, 7, enc, len, work, reserve) == SQLITE_OK && memcmp(work, page, len) == 0,
        "%s: page open", name);
  CHECK(sqlite3mcAesXaesPageOpen(&ctx, 8, enc, len, work, reserve) == AES_GCM_TAG_MISMATCH, "%s: page with wrong page number accepted", name);
  sqlite3mcAesCbcWipe(&ctx);
}

/*
** 4. Invalid use
*/
static void testMisuse(int impl)
{
  const char* name = implNames[impl];
  unsigned char key[32] = { 1 }, iv[16] = { 2 }, buf[64] = { 0 }, nonce[24] = { 0 }, tag[16];
  AesCtx ctx;
  CHECK(sqlite3mcAesCbcInitImpl(&ctx, key, 24, AES_FOR_BOTH, impl) == SQLITE_MISUSE, "%s: 24-byte key accepted", name);
  CHECK(sqlite3mcAesCbcInitImpl(&ctx, key, 16, 0, impl) == SQLITE_MISUSE, "%s: no direction accepted", name);
  sqlite3mcAesCbcInitImpl(&ctx, key, 32, AES_FOR_ENCRYPT, impl);
  CHECK(sqlite3mcAesCbcDecrypt(&ctx, iv, buf, 32) == SQLITE_MISUSE, "%s: decryption with encryption context", name);
  CHECK(sqlite3mcAesCbcEncrypt(&ctx, iv, buf, 15) == SQLITE_MISUSE, "%s: 15 bytes accepted", name);
  CHECK(sqlite3mcAesXaesSeal(&ctx, nonce, NULL, 0, buf, 16, buf, tag) == SQLITE_MISUSE, "%s: XAES with plain AES context", name);
  CHECK(sqlite3mcAesGcmSivSeal(&ctx, nonce, NULL, 0, buf, 16, buf, tag) == SQLITE_MISUSE, "%s: GCM-SIV with plain AES context", name);
  sqlite3mcAesXaesInitImpl(&ctx, key, impl);
  CHECK(sqlite3mcAesGcmSivSeal(&ctx, nonce, NULL, 0, buf, 16, buf, tag) == SQLITE_MISUSE, "%s: GCM-SIV with XAES context", name);
  sqlite3mcAesGcmSivInitImpl(&ctx, key, impl);
  CHECK(sqlite3mcAesXaesSeal(&ctx, nonce, NULL, 0, buf, 16, buf, tag) == SQLITE_MISUSE, "%s: XAES with GCM-SIV context", name);
  sqlite3mcAesCbcInitImpl(&ctx, key, 32, AES_FOR_ENCRYPT, impl);
  sqlite3mcAesCbcInitImpl(&ctx, key, 32, AES_FOR_DECRYPT, impl);
  CHECK(sqlite3mcAesCbcEncrypt(&ctx, iv, buf, 32) == SQLITE_MISUSE, "%s: encryption with decryption context", name);
  CHECK(sqlite3mcAesEncryptBlocks(&ctx, buf, buf, 1) == SQLITE_MISUSE, "%s: block encryption with decryption context", name);
  sqlite3mcAesCbcWipe(&ctx);
}

/*
** 5. The cipher scheme aes256gcm on database level
*/
#define GCM_DBFILE "aestest-gcm.db"
#define GCM_MARKER "PLAINTEXT MARKER"
#define GCM_ROWS 200
#define GCM_RAWKEY "raw:hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

typedef struct GcmVariant
{
  const char* name;
  const char* config;    /* SQL that selects the cipher scheme and sets the key */
  int reserve;           /* reserved bytes per page */
  const char* wrong[3];  /* configurations that must not open the database */
} GcmVariant;

static const GcmVariant gcmVariants[] =
{
  { "GCM-SIV, Argon2id", "PRAGMA cipher='aes256gcm'; PRAGMA key='secret';", 28,
    { "PRAGMA cipher='aes256gcm'; PRAGMA key='wrong';",
      "PRAGMA cipher='aes256gcm{algorithm=xaes-256-gcm}'; PRAGMA key='secret';",
      "PRAGMA cipher='aes256gcm{tcost=3}'; PRAGMA key='secret';" } },
  { "XAES-256-GCM, Argon2id", "PRAGMA cipher='aes256gcm{algorithm=xaes-256-gcm}'; PRAGMA key='secret';", 40,
    { "PRAGMA cipher='aes256gcm{algorithm=xaes-256-gcm}'; PRAGMA key='wrong';",
      "PRAGMA cipher='aes256gcm'; PRAGMA key='secret';",
      "PRAGMA cipher='aes256gcm{algorithm=xaes-256-gcm,mcost=20000}'; PRAGMA key='secret';" } },
  { "GCM-SIV, PBKDF2", "PRAGMA cipher='aes256gcm{kdf=pbkdf2-hmac-sha512,kdf_iter=10000}'; PRAGMA key='secret';", 28,
    { "PRAGMA cipher='aes256gcm{kdf=pbkdf2-hmac-sha512,kdf_iter=10000}'; PRAGMA key='wrong';",
      "PRAGMA cipher='aes256gcm'; PRAGMA key='secret';",
      "PRAGMA cipher='aes256gcm{kdf=pbkdf2-hmac-sha512,kdf_iter=10001}'; PRAGMA key='secret';" } },
  { "XAES-256-GCM, raw key", "PRAGMA cipher='aes256gcm{algorithm=xaes-256-gcm}'; PRAGMA key='" GCM_RAWKEY "';", 40,
    { "PRAGMA cipher='aes256gcm{algorithm=xaes-256-gcm}'; PRAGMA key='secret';",
      "PRAGMA cipher='aes256gcm'; PRAGMA key='" GCM_RAWKEY "';",
      "PRAGMA cipher='chacha20'; PRAGMA key='" GCM_RAWKEY "';" } },
};

static long gcmFileSize(void)
{
  long size = -1;
  FILE* f = fopen(GCM_DBFILE, "rb");
  if (f != NULL)
  {
    if (fseek(f, 0, SEEK_END) == 0) size = ftell(f);
    fclose(f);
  }
  return size;
}

static int gcmFileIo(long offset, unsigned char* buf, int n, int write)
{
  int ok;
  FILE* f = fopen(GCM_DBFILE, write ? "r+b" : "rb");
  if (f == NULL) return 0;
  ok = fseek(f, offset, SEEK_SET) == 0 &&
       (write ? fwrite(buf, 1, n, f) : fread(buf, 1, n, f)) == (size_t) n;
  fclose(f);
  return ok;
}

static void gcmFlip(long offset)
{
  unsigned char b;
  if (gcmFileIo(offset, &b, 1, 0))
  {
    b ^= 0x01;
    gcmFileIo(offset, &b, 1, 1);
  }
}

static int gcmFileContains(const char* text)
{
  long size = gcmFileSize(), i;
  size_t n = strlen(text);
  int found = 0;
  unsigned char* buf = (size > 0) ? (unsigned char*) malloc(size) : NULL;
  if (buf != NULL && gcmFileIo(0, buf, (int) size, 0))
  {
    for (i = 0; i + (long) n <= size && !found; i++) found = memcmp(buf + i, text, n) == 0;
  }
  free(buf);
  return found;
}

/*
** Opens the test database, runs extra (if given) and config and reads all data.
** Returns SQLITE_OK if all rows are there and the integrity check passes,
** SQLITE_MISMATCH if the data is wrong, otherwise the error code.
*/
static int gcmCheck(const char* config, const char* extra)
{
  sqlite3* db = NULL;
  sqlite3_stmt* stmt = NULL;
  int rc = sqlite3_open(GCM_DBFILE, &db);
  if (rc == SQLITE_OK && extra != NULL) rc = sqlite3_exec(db, extra, NULL, NULL, NULL);
  if (rc == SQLITE_OK) rc = sqlite3_exec(db, config, NULL, NULL, NULL);
  if (rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(db, "SELECT (SELECT count(*) FROM t WHERE x = '" GCM_MARKER " ' || id AND length(y) = 200), "
                                "(SELECT v FROM s), (SELECT integrity_check FROM pragma_integrity_check)", -1, &stmt, NULL);
  if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW)
  {
    const char* v = (const char*) sqlite3_column_text(stmt, 1);
    const char* ic = (const char*) sqlite3_column_text(stmt, 2);
    rc = (sqlite3_column_int(stmt, 0) == GCM_ROWS && v != NULL && strcmp(v, "short") == 0 &&
          ic != NULL && strcmp(ic, "ok") == 0) ? SQLITE_OK : SQLITE_MISMATCH;
  }
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return rc;
}

/* Creates the test database; returns the page size and the root page of table s */
static int gcmCreate(const char* config, int* pageSize, int* pageS)
{
  sqlite3* db = NULL;
  sqlite3_stmt* stmt = NULL;
  int rc;
  remove(GCM_DBFILE);
  rc = sqlite3_open(GCM_DBFILE, &db);
  if (rc == SQLITE_OK) rc = sqlite3_exec(db, config, NULL, NULL, NULL);
  if (rc == SQLITE_OK)
    rc = sqlite3_exec(db, "CREATE TABLE t(id INTEGER PRIMARY KEY, x TEXT, y TEXT); CREATE TABLE s(v TEXT);"
                          "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 200) "
                          "INSERT INTO t SELECT n, '" GCM_MARKER " ' || n, hex(zeroblob(100)) FROM c;"
                          "INSERT INTO s VALUES ('short');", NULL, NULL, NULL);
  if (rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(db, "SELECT (SELECT page_size FROM pragma_page_size), "
                                "(SELECT rootpage FROM sqlite_schema WHERE name = 's')", -1, &stmt, NULL);
  if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW)
  {
    *pageSize = sqlite3_column_int(stmt, 0);
    *pageS = sqlite3_column_int(stmt, 1);
  }
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return rc;
}

static void testAes256GcmVariant(const GcmVariant* v)
{
  int pageSize = 0, pageS = 0, k, rc;
  long offS;
  unsigned char hdr[24], before[65536], after[65536], other[65536];
  sqlite3* db = NULL;

  rc = gcmCreate(v->config, &pageSize, &pageS);
  CHECK(rc == SQLITE_OK && pageSize >= 512 && pageSize <= 65536 && pageS > 2, "%s: create (rc=%d)", v->name, rc);
  if (rc != SQLITE_OK || pageSize < 512 || pageSize > 65536 || pageS <= 2) return;
  offS = (long) (pageS - 1) * pageSize;

  /* File: salt instead of the SQLite header, reserve in byte 20, no plaintext */
  CHECK(gcmFileIo(0, hdr, 24, 0) && memcmp(hdr, "SQLite format 3", 16) != 0, "%s: no salt at the start of the file", v->name);
  CHECK(hdr[20] == v->reserve, "%s: byte 20 is %d, expected %d", v->name, hdr[20], v->reserve);
  CHECK(!gcmFileContains(GCM_MARKER), "%s: plaintext in the database file", v->name);

  /* Readable with the same configuration only */
  CHECK(gcmCheck(v->config, NULL) == SQLITE_OK, "%s: reopen", v->name);
  for (k = 0; k < 3; k++)
  {
    rc = gcmCheck(v->wrong[k], NULL);
    CHECK(rc == SQLITE_NOTADB, "%s: opened with \"%s\" (rc=%d)", v->name, v->wrong[k], rc);
  }

  /* A changed byte in the data, in the nonce or in the tag of a page, or in page 1 */
  {
    long offsets[4];
    offsets[0] = offS + 100;
    offsets[1] = offS + pageSize - v->reserve;
    offsets[2] = offS + pageSize - 1;
    offsets[3] = 60;
    for (k = 0; k < 4; k++)
    {
      gcmFlip(offsets[k]);
      rc = gcmCheck(v->config, NULL);
      CHECK(rc == ((k == 3) ? SQLITE_NOTADB : SQLITE_CORRUPT), "%s: changed byte at offset %ld (rc=%d)", v->name, offsets[k], rc);
      gcmFlip(offsets[k]);
    }
  }

  /* A page at the place of another page */
  if (gcmFileIo(offS, before, pageSize, 0) && gcmFileIo(offS - pageSize, other, pageSize, 0))
  {
    gcmFileIo(offS, other, pageSize, 1);
    rc = gcmCheck(v->config, NULL);
    CHECK(rc == SQLITE_CORRUPT, "%s: page %d at the place of page %d (rc=%d)", v->name, pageS - 1, pageS, rc);
    gcmFileIo(offS, before, pageSize, 1);
  }

  /* Changed byte 20 (reserved bytes per page) */
  {
    unsigned char values[2], old = hdr[20];
    values[0] = (unsigned char) ((v->reserve == 28) ? 40 : 28);
    values[1] = 0;
    for (k = 0; k < 2; k++)
    {
      gcmFileIo(20, &values[k], 1, 1);
      rc = gcmCheck(v->config, NULL);
      CHECK(rc == SQLITE_NOTADB || rc == SQLITE_CORRUPT, "%s: byte 20 set to %d (rc=%d)", v->name, values[k], rc);
      gcmFileIo(20, &old, 1, 1);
    }
  }
  CHECK(gcmCheck(v->config, NULL) == SQLITE_OK, "%s: reopen after the changes were undone", v->name);

  /* hmac_check=0 gives the data of a page whose free space was changed */
  gcmFlip(offS + pageSize / 2);
  rc = gcmCheck(v->config, NULL);
  CHECK(rc == SQLITE_CORRUPT, "%s: changed free space (rc=%d)", v->name, rc);
  rc = gcmCheck(v->config, "PRAGMA hmac_check=0;");
  CHECK(rc == SQLITE_OK, "%s: changed free space with hmac_check=0 (rc=%d)", v->name, rc);
  gcmFlip(offS + pageSize / 2);

  /* A page written again with the same content gets a new nonce and a new ciphertext */
  gcmFileIo(offS, before, pageSize, 0);
  rc = sqlite3_open(GCM_DBFILE, &db);
  if (rc == SQLITE_OK) rc = sqlite3_exec(db, v->config, NULL, NULL, NULL);
  if (rc == SQLITE_OK) rc = sqlite3_exec(db, "UPDATE s SET v = 'other'; UPDATE s SET v = 'short';", NULL, NULL, NULL);
  sqlite3_close(db);
  CHECK(rc == SQLITE_OK && gcmFileIo(offS, after, pageSize, 0), "%s: update (rc=%d)", v->name, rc);
  CHECK(memcmp(before + pageSize - v->reserve, after + pageSize - v->reserve, v->reserve - 16) != 0,
        "%s: nonce not changed", v->name);
  CHECK(memcmp(before, after, pageSize - v->reserve) != 0, "%s: ciphertext not changed", v->name);
  CHECK(gcmCheck(v->config, NULL) == SQLITE_OK, "%s: reopen after the update", v->name);
  remove(GCM_DBFILE);
}

/* Plaintext header: the salt is not in the file and has to be given */
static void testAes256GcmPlaintextHeader(void)
{
  static const char* config =
    "PRAGMA cipher='aes256gcm{plaintext_header_size=32,kdf=pbkdf2-hmac-sha512,kdf_iter=10000}';"
    "PRAGMA cipher_salt='00112233445566778899aabbccddeeff'; PRAGMA key='secret';";
  static const char* noSalt =
    "PRAGMA cipher='aes256gcm{plaintext_header_size=32,kdf=pbkdf2-hmac-sha512,kdf_iter=10000}'; PRAGMA key='secret';";
  static const char* otherSalt =
    "PRAGMA cipher='aes256gcm{plaintext_header_size=32,kdf=pbkdf2-hmac-sha512,kdf_iter=10000}';"
    "PRAGMA cipher_salt='00112233445566778899aabbccddeefe'; PRAGMA key='secret';";
  int pageSize = 0, pageS = 0, rc;
  unsigned char hdr[32];

  rc = gcmCreate(config, &pageSize, &pageS);
  CHECK(rc == SQLITE_OK, "plaintext header: create (rc=%d)", rc);
  CHECK(gcmFileIo(0, hdr, 32, 0) && memcmp(hdr, "SQLite format 3", 16) == 0 &&
        ((hdr[16] << 8) | hdr[17]) == (pageSize & 0xffff) && hdr[20] == 28,
        "plaintext header: header not in plaintext");
  CHECK(!gcmFileContains(GCM_MARKER) && !gcmFileContains("CREATE TABLE"), "plaintext header: plaintext in the database file");
  CHECK(gcmCheck(config, NULL) == SQLITE_OK, "plaintext header: reopen");
  rc = gcmCheck(noSalt, NULL);
  CHECK(rc != SQLITE_OK, "plaintext header: opened without the salt (rc=%d)", rc);
  rc = gcmCheck(otherSalt, NULL);
  CHECK(rc == SQLITE_NOTADB, "plaintext header: opened with another salt (rc=%d)", rc);
  remove(GCM_DBFILE);
}

static void testAes256GcmDatabase(void)
{
  int before = failures;
  size_t i;
  for (i = 0; i < sizeof(gcmVariants) / sizeof(gcmVariants[0]); i++)
  {
    testAes256GcmVariant(&gcmVariants[i]);
  }
  testAes256GcmPlaintextHeader();
  printf("  aes256gcm on database level: %s\n", failures == before ? "ok" : "FAILED");
}

int main(int argc, char** argv)
{
  int rounds = (argc > 1) ? atoi(argv[1]) : 200;
  size_t i;

  printf("AES backends:");
  for (i = 0; i < sizeof(implIds) / sizeof(implIds[0]); i++)
  {
    if (sqlite3mcAesImplAvailable(implIds[i]))
    {
      impls[implCount++] = implIds[i];
      printf(" %s", implNames[implIds[i]]);
    }
  }
  printf("\nGHASH variants:");
  for (i = 0; i < sizeof(ghashIds) / sizeof(ghashIds[0]); i++)
  {
    if (sqlite3mcAesGhashGet(ghashIds[i]) != NULL) printf(" %s", ghashNames[ghashIds[i]]);
  }
  printf("\n");
  if (implCount == 0)
  {
    printf("No AES backend available\n");
    return 0;
  }

  for (i = 0; i < (size_t) implCount; i++)
  {
    int before = failures;
    testKnownAnswers(impls[i]);
    testKnownAnswersGcmSiv(impls[i]);
    testWycheproofGcmSiv(impls[i]);
    testGcmSivCounterWrap(impls[i]);
    testGcmSivNonceReuse(impls[i]);
    testPages(impls[i]);
    testPagesGcmSiv(impls[i]);
    testMisuse(impls[i]);
    printf("  %-9s known answers, pages, misuse: %s\n", implNames[impls[i]], failures == before ? "ok" : "FAILED");
  }
  testCrossCbc(rounds * 10);
  testCrossBlocks(rounds);
  testCrossXaes(rounds);
  testCrossGcmSiv(rounds);
  testAes256GcmDatabase();

  printf("%d checks, %d failures\n", checks, failures);
  return failures != 0;
}
