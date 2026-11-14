#include "selfservice_crypto.hpp"

#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace scau;

namespace {

void require(bool value, const char* description) {
    if (!value) throw std::runtime_error(description);
}

void rejects(const std::function<void()>& operation) {
    try { operation(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("Malformed self-service input was accepted");
}

void test_original_instruction_vectors() {
    // Synthetic values only. Extracted pure x86 transform instructions were
    // emulated in isolation and compared with independent Python hashlib.
    // Evidence and reproducible oracle: captures/package-api-20261113/crypto/.
    struct Vector { std::wstring_view plain; std::string_view encoded; };
    const Vector vectors[] = {
        {L"", ""},
        {L"a", "9df0a39d52c9214fb67958b6fabffe9c"},
        {L"0123456789ABCDEF", "ccc191ae66fc17788e4019f4b9fbbbda"},
        {L"0123456789ABCDEFG", "ccc191ae66fc17788e4019f4b9fbbbdafe4e83be0abb7afc609055dde101fc1b"},
        {L"userid=synthetic&password=offline&userip=192.0.2.10&callBack=ballInfo&channel=su",
         "8983c6ef3bad1c3ccf172cde9fcb97ffa1447330b79412849aca406a4534fa5c"
         "760471fb8193a0bb373a8d374707ec93c9cb50b6b8c5e7adf3e7f19043a04203"
         "031671eb924d0f1231d525188b98e752"},
        {L"userid=\u6d4b\u8bd5&password=\u5408\u6210\u6837\u672c&channel=su",
         "8983c6ef3bad1ca903f2b0196f998efd4d001280519654daec97bbecb09526de"
         "f8cc448cb93b70d6708782117a24c79f"},
        {L"\U0001f517", "0c6f370a52c9214fb67958b6fabffe9c"},
    };
    for (const auto& vector : vectors) {
        const auto input = std::wstring(vector.plain);
        require(selfservice_encode_query(input) == vector.encoded,
                "Self-service original instruction oracle mismatch");
        require(selfservice_encode_query(input) == vector.encoded,
                "Self-service chain state leaked across requests");
        require(input == vector.plain, "Self-service encoding modified caller input");
    }
}

void test_boundaries() {
    for (const std::size_t size : {1u, 15u, 16u, 17u, 31u, 32u, 225u, 239u, 240u}) {
        const auto result = selfservice_encode_query(std::wstring(size, L'x'));
        require(result.size() == ((size + 15) & ~std::size_t(15)) * 2,
                "Self-service zero padding length mismatch");
        require(std::all_of(result.begin(), result.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        }), "Self-service output must be lowercase hexadecimal");
    }
    require(selfservice_encode_query(std::wstring(80, L'\u6d4b')).size() == 480,
            "Self-service exact UTF-8 limit rejected");
    rejects([] { selfservice_encode_query(std::wstring(241, L'x')); });
    rejects([] { selfservice_encode_query(std::wstring(81, L'\u6d4b')); });
    rejects([] { selfservice_encode_query(std::wstring_view(L"a\0b", 3)); });
    rejects([] { selfservice_encode_query(std::wstring(1, wchar_t(0xd800))); });
    rejects([] { selfservice_encode_query(std::wstring(1, wchar_t(0xdc00))); });
}

} // namespace

int main() {
    try {
        test_original_instruction_vectors();
        test_boundaries();
        std::cout << "Self-service crypto tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
