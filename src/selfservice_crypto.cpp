#include "selfservice_crypto.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <stdexcept>

namespace scau {
namespace {

struct WorkingBytes {
    std::array<UCHAR, selfservice_query_max_utf8_bytes> plaintext{};
    std::array<UCHAR, 20> hash_input{};
    std::array<UCHAR, 16> mask{};

    ~WorkingBytes() { SecureZeroMemory(this, sizeof(*this)); }
};

} // namespace

std::string selfservice_encode_query(std::wstring_view query) {
    if (query.empty()) return {};
    if (query.size() > selfservice_query_max_utf8_bytes)
        throw std::invalid_argument("Self-service query exceeds the original 240-byte limit");
    if (query.find(L'\0') != std::wstring_view::npos)
        throw std::invalid_argument("Self-service query contains an embedded NUL");

    const int utf8_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        query.data(), static_cast<int>(query.size()), nullptr, 0, nullptr, nullptr);
    if (utf8_length <= 0)
        throw std::invalid_argument("Self-service query contains invalid UTF-16");
    if (static_cast<std::size_t>(utf8_length) > selfservice_query_max_utf8_bytes)
        throw std::invalid_argument("Self-service query exceeds the original 240-byte limit");

    WorkingBytes work;
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, query.data(),
            static_cast<int>(query.size()), reinterpret_cast<char*>(work.plaintext.data()),
            utf8_length, nullptr, nullptr) != utf8_length)
        throw std::runtime_error("Self-service UTF-8 conversion failed");

    const auto padded_length = (static_cast<std::size_t>(utf8_length) + 15) & ~std::size_t(15);
    std::copy_n("hust", 4, work.hash_input.begin());
    std::fill(work.hash_input.begin() + 4, work.hash_input.end(), UCHAR('1'));
    constexpr char hex[] = "0123456789abcdef";
    std::string encoded(padded_length * 2, '\0');
    for (std::size_t offset = 0; offset < padded_length; offset += 16) {
        if (BCryptHash(BCRYPT_MD5_ALG_HANDLE, nullptr, 0,
                work.hash_input.data(), static_cast<ULONG>(work.hash_input.size()),
                work.mask.data(), static_cast<ULONG>(work.mask.size())) < 0) {
            SecureZeroMemory(encoded.data(), encoded.size());
            throw std::runtime_error("Windows CNG self-service transform failed");
        }
        for (std::size_t i = 0; i < work.mask.size(); ++i) {
            const auto byte = UCHAR(work.plaintext[offset + i] ^ work.mask[i]);
            work.hash_input[i + 4] = byte;
            encoded[(offset + i) * 2] = hex[byte >> 4];
            encoded[(offset + i) * 2 + 1] = hex[byte & 15];
        }
    }
    return encoded;
}

} // namespace scau
