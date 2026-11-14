#include "failure.hpp"
#include <windows.h>
#include <cwctype>

namespace scau {
namespace {
std::wstring decode(std::string_view bytes, UINT page) {
    if (bytes.empty()) return {};
    const auto size = MultiByteToWideChar(page, MB_ERR_INVALID_CHARS, bytes.data(), int(bytes.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring text(size, L'\0');
    if (!MultiByteToWideChar(page, MB_ERR_INVALID_CHARS, bytes.data(), int(bytes.size()), text.data(), size)) return {};
    return text;
}
void redact(std::wstring& text, const std::wstring& secret) {
    if (secret.empty()) return;
    std::size_t at = 0;
    while ((at = text.find(secret, at)) != std::wstring::npos) {
        text.replace(at, secret.size(), L"***");
        at += 3;
    }
}
bool invisible(wchar_t ch) {
    return ch == 0xfeff || (ch >= 0x200b && ch <= 0x200f) ||
           (ch >= 0x202a && ch <= 0x202e) || (ch >= 0x2060 && ch <= 0x206f);
}
} // namespace

std::string failure_message(std::span<const Byte> eap, std::string_view username, std::string_view password) {
    if (failure_reason(eap) != FailureReason::present) return "unknown";
    const auto size = (std::size_t(eap[8]) << 8) | eap[9];
    // A UI diagnostic must remain bounded even when the server declares a very long body.
    if (size > 4096) return "unknown";
    const std::string_view bytes(reinterpret_cast<const char*>(eap.data() + 10), size);
    auto text = decode(bytes, CP_UTF8);
    if (text.empty()) text = decode(bytes, 936);
    if (text.empty()) return "unknown";
    const auto user = decode(username, 936), pass = decode(password, 936);
    redact(text, pass);
    redact(text, user);
    std::wstring clean;
    bool space = false;
    for (auto ch : text) {
        if (ch == L'\0') return "unknown";
        if (invisible(ch)) continue;
        if (ch < 32 || (ch >= 0x7f && ch < 0xa0) || std::iswspace(ch)) {
            space = !clean.empty();
            continue;
        }
        if (space) clean += L' ';
        clean += ch;
        space = false;
    }
    // Also redact after control/invisible-character normalization.
    redact(clean, pass);
    redact(clean, user);
    if (clean.empty()) return "unknown";
    const auto length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, clean.data(), int(clean.size()),
                                            nullptr, 0, nullptr, nullptr);
    if (length <= 0) return "unknown";
    std::string result(length, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, clean.data(), int(clean.size()), result.data(), length,
                            nullptr, nullptr)) return "unknown";
    if (result.size() > failure_message_limit) {
        auto end = failure_message_limit - 3;
        while (end && (static_cast<unsigned char>(result[end]) & 0xc0) == 0x80) --end;
        result.resize(end);
        result += "...";
    }
    return result;
}
} // namespace scau
