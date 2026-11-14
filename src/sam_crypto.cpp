#include "sam_crypto.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace scau {
namespace {

struct Algorithm {
    BCRYPT_ALG_HANDLE handle{};
    ~Algorithm() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
};
struct SymmetricKey {
    BCRYPT_KEY_HANDLE handle{};
    ~SymmetricKey() { if (handle) BCryptDestroyKey(handle); }
};
struct SecretBytes {
    Bytes bytes;
    ~SecretBytes() { sam_clear_secret(bytes); }
    Bytes release() noexcept {
        Bytes result;
        result.swap(bytes);
        return result;
    }
};
struct SecretBlock {
    SamBlock bytes;
    ~SecretBlock() { sam_clear_secret(bytes); }
};

ULONG cng_size(std::size_t size) {
    if (size > std::numeric_limits<ULONG>::max())
        throw std::runtime_error("SAM crypto input is too large");
    return static_cast<ULONG>(size);
}

Bytes des_cbc(const SamBlock& key, const SamBlock& iv,
              std::span<const Byte> input, bool encrypt) {
    if (input.size() % 8) throw std::runtime_error("SAM DES input is not block aligned");
    if (input.empty()) return {};
    const auto length = cng_size(input.size());
    Algorithm algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_DES_ALGORITHM, nullptr, 0) < 0 ||
        BCryptSetProperty(algorithm.handle, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
            sizeof(BCRYPT_CHAIN_MODE_CBC), 0) < 0)
        throw std::runtime_error("Windows CNG DES provider failed");
    DWORD object_length{}, returned{};
    if (BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &returned, 0) < 0 ||
        returned != sizeof(object_length))
        throw std::runtime_error("Windows CNG DES key size failed");
    SecretBytes object{Bytes(object_length)};
    SymmetricKey symmetric;
    if (BCryptGenerateSymmetricKey(algorithm.handle, &symmetric.handle,
            object.bytes.data(), object_length, const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()), 0) < 0)
        throw std::runtime_error("Windows CNG DES key failed");
    SecretBlock current_iv{iv};
    SecretBytes output{Bytes(input.size())};
    ULONG output_length{};
    const auto status = encrypt
        ? BCryptEncrypt(symmetric.handle, const_cast<PUCHAR>(input.data()), length, nullptr,
                        current_iv.bytes.data(), static_cast<ULONG>(current_iv.bytes.size()),
                        output.bytes.data(), length, &output_length, 0)
        : BCryptDecrypt(symmetric.handle, const_cast<PUCHAR>(input.data()), length, nullptr,
                        current_iv.bytes.data(), static_cast<ULONG>(current_iv.bytes.size()),
                        output.bytes.data(), length, &output_length, 0);
    if (status < 0 || output_length != length)
        throw std::runtime_error("Windows CNG DES operation failed");
    return output.release();
}

// Finite protocol constants: exhaustive offline evaluation of the native
// compiled 53-row domain, not user or session data. See integrity-oracle.json.
constexpr std::array<std::string_view, 53> integrity_rows{
    "ebbc97ce78655a7b26307b23304be37c3b9a2b41daf580c0f3840502d5e6dfb61dff5c5feadea9e13f7076c15d665109f15a1b5a3fe20ca8684e8d366f672b27",
    "17f284432ed67744a6207551eb3368e709c89c1cf4f7745abeeca077b909685c0db5243602c2d880325ebef65ebc76a77251d146e5e53134c5dddfb84424ad68",
    "ab9e9c4b752f04f40a39e770cd09b29477c5d8b999e7cf20801cbd9fb881d81a9d879772c7bbef855d7eb2cafa7ca0797c7e7186005d5463735daf448d0eaa76",
    "22851b828474a7d639da92be99d033be320c1e7addeffd6e58a54e50d80c8ecee049bed469b7dc29e4fabb225d4bb438b779002a9a75c604b96c35fcd8c394f4",
    "e75757ab4dbf3b9c4f9dfb2f8ac029727eceb3863ca98a3abe481ab1e5b3fd987a8ca46a3cf4fd6512b994bbb76a3fdcefcf024c3e7b53c9b80f5d11c0356a05",
    "fc9f260f07641e181c5aa90cf737e86a9521e774c2797ffd2467e43b271808f545bad51ec43b42ff1a45a4d83ee588d9e0a95dbb74b295fcbd998a3e90432a04",
    "a95aca6395b37f9881ecf9861c405012a1fd3b056519dca7f27a06ae2f954b177b257a7b4e325bbd1163cdcc463b1c134add2108be1cb095a20e350118ecf735",
    "a357870774790ceacf23ba5234e78aec0114c32f83522bded039d54a5c17b22344c0da2251d438e65f6c4aadf670bce447879e283f968253a016fecd70247331",
    "8e76dbbb195888df878b59db6c5bd1ac090377ecc39ca1ba956a247c6d9387921dca1821e574f0c6e8d27554ca79ee21f98815c2e1ef3596e13ae8e1cedc7e13",
    "b5eae6e80091bc21a7030c1173d777a35dbf498a35c30d977ba98a9f6a79dd8ef6a1abafcc49e7c7b6d70eb05eb86e829617b5142bd5857984254697d847d438",
    "0fa2b8f361db91b57d133e66648b1201e0bf835160235271463e8816e47f598d8c8c188208c3093c47ce65a0b1d326bc7f46046b32d794f1d11c2aa16bc62b16",
    "bb95632ba1a8851ee2c20601b9977b0bb4bec2b3af96318d9fb1df47c54880c3424e560b1a92260f8f6cee951bf43c7f3ec94191a3269bf1a41ae89ea1e0bbb2",
    "baa8fef6d8c77c08122d95703ceb5ee885cbb4a916adadf1b24e57f83752873e6cc975a309a838bc04d9aee53f3c6ffd45f2f9375ccc0e657a84f2857bae7d19",
    "864656113352644631478162cbffe6e3417a7c30bac3f6b31adac9bfbed091d3a3c64b1f321c2ff0a80e7e5409b141ca3541a4c9a89cbf2ed826b18ddd9cf5b7",
    "338cff8061922af7a9d6c455fc2d4b58c270e8aed0569a30abaa44a8d01d4c9dc4cc40e040e4b9637ec4e4ba917c8f0c5b473a779920cdeed1f85e7d2db373e9",
    "9c35b64b77e6260ff9ca7e6c7a806917ee19997d9b5055319eded39dad9e0d19f238f2997dfa348c38651aeffedf11df9fd1a321ddc0edde7cbf5dce04b15ea7",
    "fcb0a5cae1fc289d20a92320fb1deb659754886e5194a6feb95d5ed0b9ba7d9fa94d4d9b6fc343a93ae9879c767e2bce51f4549ee6dad1cff7d861b808b921c5",
    "1b28c6a13758c45af86008961b04303f671a14c080f13122271e95dc1d8a2ec33717ed9f541a63dac8e8568ab53defe3ae0c219b16dd527356b72f3ba65dfbda",
    "c1d8f739090562a721ed7a6e5cad3f1d638bbf919b5ebfd1ef818ecf31305ce808a289cac0d003a6ea133a7c262043a9e194a8c70866ed97b9fa2ae4f3f17ef4",
    "43320d82bbb199b0048e61725bca6c3163545cc17f8af5e5fa1f07dac8d4fe455353c530f87a8f21a22574f808d7b70abde8eaf8739ab00e3af4d08e45d1a15a",
    "f765ff004bce026cbd50ba5875f7a561ec40c20b6e591d8b3ac2d5c9791ad4ed1782719f51dee083d18245f44113593d718cdaf9824eba47672fd56525b5f90d",
    "a33ed52d0cda12514da6493084d95cce88f9d4d156d52de1a08a129a160594b415e0cff6a5d34cb86a9e572add31479fcc483524b737a9c5579eb27350b19af5",
    "aa97accbc966db3241033825128ebc2588ed7e473a597fa1236c7d146998369091864dfc46cd80d971eeb465f75078f8522b4033047d18ea228f8ad5e873c53a",
    "a266ad272a5830adc768b231e5ba9d9788b47a5ce3b1ba4ff46c9bf8803f60c00e7091cae48b6872997c7a4a0f1f85bf3cbff7875e015b8764d343a5e3a1fccb",
    "de0c1b30123ed72b6a5a685aae14b2c33be6c3f7fd4a269d72949d950674c2c9beaa273ad8e772f1da3cbbb14ca6c09ad04452008fe3d6ec49df185b7dc2bd74",
    "215fa2dbb24c1685c25715a1169dd4b576acd5482ed14d1aba9445d2183224eec69d39f71e5a0fcfdff1a55cd3f3108a21798893647a8da87c6f00c5be599ba9",
    "509f9e0b5cdc30f16f12bfba6768bf18ce53cd318d4eeedd0292e145999d7d3e6da04f10e0fc68647f6bb96f5450c1e4650de2529aecc051f35b86760a7f1992",
    "d878a6d7a6c7d3940a7dce237096f76e9fb3e46a09acff8ce71733b55c57116d8cf5a09bee32f4156a8733bdda26943f555372f89e5642197c8815a5fb32655e",
    "e59a8f07ae8600b30a3eacf74dcdaa3a47c4c507553c1b912fa6a75bd01218b2f3d6ad1b986ce125240338398a3db43f633094ee336e211cc185b34ac35f44fa",
    "84a790b7baa8474cc9fc398fc070ac74c6ff6eea945deed61a0ff5d8ff14429fd24e882d27df22c725f01a8af926e98ef25bc77faf09b9712df7fb8f1b6c71be",
    "5c837abecc2a850bd495301a0bd4597f6fa5a482f937211561845871fbf87ec5cbd5ad0d6703373462f17e25d15d4efb046aae0e7c2842c79a4203a3f4ab7caa",
    "d5e2faa6e748dea788894954ad5663b4f93e067fc84831bef50a5c2b1f304d4faf48df4db3d49238073178f7b352f0b4bb82cf7008449d2b7bb17425b2565265",
    "d45351f6a3c94cf2a2efee7b134997fbbf68701d35ccd43f375419dc40eb3e5bd6e3d831941d86c5ff14e47a923398a483b88328fbcf3ca5edea990f2e0f138b",
    "9ed6ceeb3394d55dd12628ca949e432713e193cb0810f10641240df5fb169364cec34ef3be8b27cdb2cbabc840ed15aef9c85fead30604a91a8c2cee616c6f91",
    "84e64d501e48732a7e9ed4a10e921f22dad37e5944848a04f79a15d0d08f8d7cb5bc04d1027e8609299c90546c4752391bfd88046ddc0788bcfcf1635ffbfe22",
    "9a5377bc6719a3e1faa733f5fee7f58fdd85c643717664bc08afa53a3b5cedbf025c9d63ab46d06b2375b7318094d8ad29d392c34e845b258d6b0c0f1a097729",
    "76128905817226a130787210a423448927d2e64f815ae3f63c23502fff67c872e1eef8a54bab98c9c9c194ec2492baa9c00492b13b3d8411d21838ec181e80ea",
    "fa341f5a6b595a81443e9dd31802c87aa7ca65f461b1ae953e5d0098152a02b96a96d155c27c801154c495b5f01d2e8e81a87df6f8aa27fc679dd3b3cab0b867",
    "2b8567f483bdc017a38d6a241dab341d1984dad2141fff79f5edbfb0a4e2adc905ca75e6ffaacc47ab48da4c993564b50fc453428c7a633f9245c0f5b5f1fe75",
    "e94bc7243538b23017aaf8f7039975545abb24bfdc62012e1eb3bc59a514340f4beb295ff7026d2a2448bf86c3ee1caa8f3650d4cc831838966ab15ee0d7ff8d",
    "527ca40d86c83a167e0bac25283e2c0ab04b6e60b5845fa3a473938cee5c8f281efa0c83d37af10547ea45b6419bfad785f3a44975eb850438e5a16108f9c8f3",
    "3661b6f9a681e43bcebf093a0fe26f8a805243f6cda153a872eb6107fc12bea68f25adc70ec88e861e8ed8a091cda3e3d7d8fa0e9e78906dd8a8cf27e376a19e",
    "30056ff6dfea63e1d3d5f5e4a362ac1c63e58bb50e234430bee92481f173687a53f974c014ff59a7d77ec2dd62f528bf67910f9560de6d3339ac0f1354520e74",
    "4e6750a3ca8ea06e5f39594ad95504675941997de3e2546dc6d0d3c59cf16ef0f596573d0667c41077b0437a7e9318c0617fd2f6220afd96565612a625a04d74",
    "c1a73a20d4327623e83e4e181f580fd8cd23993cdbaef04284d1bd784b45686976ff0e24feaf4570ed429beeea009131946b4b0596476eb38c915f47ce83756e",
    "81ece57f139100d28a9f64ddfc1f3a19e74ae412765b89969b3deb7d5a6dc55e3d029bc0a08e30fcd5041f12af311741254125d86b57280115d0da4aafa7c71e",
    "2e31bc8cd185573ca355f0de36a3b5afcda2ce5d5e83536acfd0a80f2b9799d743684bf1e1394920342c38ae3ef959a4ba06145fe65be62ccf06f76d1d587275",
    "4a6c8479760c06fa66ba6546c588470aabbb6409ac770f0ab9b06af556c0918a810e3d51cb556f213aa11d77535c616f5ca6058c93e23d30dcedfc3209739c3f",
    "8c2b1473696bd2da712c4cc838962417d760e5dc05d9b5345f69a11e511fa4d9806f8e8691aa65dc3fa3dc6acc0e590247a3326393bc4d274de79fc5e5473325",
    "0da5615b8f75e6a366d6f82ec74d60e93d829070b73262a2a10c6687329a1ae14188b40e814a7a0a14967a263de5b4030121a3ee134db74c71eb468fea291b20",
    "fef8681fea4367ecae0f919976df2cdbc6f06fe2cb197587058f008291096a8a11957073b86fd9dd67ba1f42e3452e8ff074d37c9bf68eed84355d103c400b61",
    "73dc7484a34040d6b55a69122cbe832ec55be625c846ed0c2d2f81e4b53906a4fdfd6cfaa430b728361c7882ca68a5f83f6e5c9b22e2282874d4a8ad31cf70a3",
    "424cc9c4cc70643b3cd67878c8538dba432d8da717ef21d259db6a9eab1f648b1602a812a897964994a813209ff5c05236dbd5b71fd28c978b36000b845f109e",
};
static_assert([] { for (const auto row : integrity_rows) if (row.size() != 128) return false; return true; }());

} // namespace

void sam_clear_secret(std::span<Byte> bytes) noexcept {
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
}

SamBlock unwrap_success_key(std::span<const Byte> wrapped) {
    if (wrapped.size() != 8) throw std::runtime_error("SAM wrapped field must contain 8 bytes");
    constexpr std::string_view wrapping_key = "com.ruijie.www";
    std::array<Byte, 256> state{};
    for (unsigned i = 0; i < state.size(); ++i) state[i] = static_cast<Byte>(i);
    unsigned j = 0;
    for (unsigned i = 0; i < state.size(); ++i) {
        j = (j + state[i] + static_cast<Byte>(wrapping_key[i % wrapping_key.size()])) & 255;
        std::swap(state[i], state[j]);
    }
    SamBlock output{};
    unsigned i = 0;
    j = 0;
    for (std::size_t offset = 0; offset < output.size(); ++offset) {
        i = (i + 1) & 255;
        j = (j + state[i]) & 255;
        std::swap(state[i], state[j]);
        output[offset] = wrapped[offset] ^ state[(unsigned(state[i]) + state[j]) & 255];
    }
    sam_clear_secret(state);
    return output;
}

SamSeed sam_seed_for_wired_md5(std::span<const Byte> challenge) {
    if (challenge.size() != 16) throw std::runtime_error("SAM MD5 seed must contain 16 bytes");
    SamSeed seed{};
    std::copy(challenge.begin(), challenge.end(), seed.begin());
    return seed;
}

Bytes sam_encrypt_body(const SamBlock& key, const SamBlock& iv,
                       std::span<const Byte> body) {
    if (body.size() > std::numeric_limits<ULONG>::max() - 7u)
        throw std::runtime_error("SAM body is too large");
    SecretBytes padded{Bytes((body.size() + 7) & ~std::size_t(7), 0)};
    std::copy(body.begin(), body.end(), padded.bytes.begin());
    return des_cbc(key, iv, padded.bytes, true);
}

Bytes sam_decrypt_body(const SamBlock& key, const SamBlock& iv,
                       std::span<const Byte> ciphertext) {
    return des_cbc(key, iv, ciphertext, false);
}

Digest sam_packet_authenticator(const SamBlock& key, const SamBlock& iv,
                                std::span<const Byte> packet) {
    if (packet.size() < 42) throw std::runtime_error("SAM packet header is truncated");
    if (packet.size() > std::numeric_limits<ULONG>::max() - 16u)
        throw std::runtime_error("SAM packet is too large");
    // Allocate the final size before copying session material; no vector
    // growth may release an older allocation containing a partial key/IV.
    SecretBytes input{Bytes(packet.size() + key.size() + iv.size())};
    std::copy(packet.begin(), packet.end(), input.bytes.begin());
    std::fill(input.bytes.begin() + 8, input.bytes.begin() + 24, Byte{});
    std::copy(key.begin(), key.end(), input.bytes.begin() + packet.size());
    std::copy(iv.begin(), iv.end(), input.bytes.begin() + packet.size() + key.size());
    Algorithm algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_MD5_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("Windows CNG SAM MD5 provider failed");
    Digest digest{};
    const auto status = BCryptHash(algorithm.handle, nullptr, 0, input.bytes.data(),
                                   cng_size(input.bytes.size()), digest.data(),
                                   static_cast<ULONG>(digest.size()));
    if (status < 0) throw std::runtime_error("Windows CNG SAM MD5 failed");
    return digest;
}

bool sam_verify_packet_authenticator(const SamBlock& key, const SamBlock& iv,
                                     std::span<const Byte> packet) {
    if (packet.size() < 42) return false;
    const auto expected = sam_packet_authenticator(key, iv, packet);
    unsigned difference = 0;
    for (std::size_t i = 0; i < expected.size(); ++i)
        difference |= unsigned(expected[i] ^ packet[8 + i]);
    return difference == 0;
}


SamIntegrity sam_integrity_attribute(std::uint32_t session_id,
                                     std::span<const Byte, 16> seed) {
    unsigned sum = 0;
    for (unsigned shift = 0; shift < 32; shift += 8) sum += (session_id >> shift) & 255;
    for (const auto byte : seed) sum += byte;
    const auto row = integrity_rows[(sum * 727u) % integrity_rows.size()];
    SamIntegrity output{};
    std::copy(row.begin(), row.end(), output.begin());
    return output;
}

} // namespace scau
