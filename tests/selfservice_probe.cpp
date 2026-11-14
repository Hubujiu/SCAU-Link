// Explicit research probe: own first saved account, public login + read-only
// pages only. Never calls pause/resume/offline or prints secrets/cookies.
#include "desktop/accounts.hpp"
#include "desktop/school_https.hpp"
#include <openssl/bn.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <regex>
#include <stdexcept>

using namespace scau::desktop;
using namespace scau::desktop::detail;
namespace {
struct Wipe { std::string& text; ~Wipe() { SecureZeroMemory(text.data(), text.size()); } };
std::string input(std::string_view page, const std::string& id) {
    const std::regex pattern("<input\\b[^>]*\\bid\\s*=\\s*['\"]" + id +
                             "['\"][^>]*\\bvalue\\s*=\\s*['\"]([^'\"]*)['\"]", std::regex::icase);
    std::match_results<std::string_view::const_iterator> match;
    if (!std::regex_search(page.begin(), page.end(), match, pattern)) throw std::runtime_error("Input unavailable");
    return match[1].str();
}
std::string form(std::string_view bytes) {
    std::string out; constexpr char hex[] = "0123456789ABCDEF";
    for (unsigned char ch : bytes) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
            ch == '-' || ch == '_' || ch == '.' || ch == '*') out += char(ch);
        else { out += '%'; out += hex[ch >> 4]; out += hex[ch & 15]; }
    }
    return out;
}
std::string encrypted(const Credential& credential, std::string key) {
    const auto entity = key.find("&amp;"); if (entity != key.npos) key.replace(entity, 5, "&");
    const auto separator = key.find('&'); if (separator == key.npos) throw std::runtime_error("No public key");
    const auto exponent = key.substr(0, separator), modulus = key.substr(separator + 1);
    for (const auto& text : {exponent, modulus})
        if (text.empty() || text.find_first_not_of("0123456789abcdefABCDEF") != text.npos) throw std::runtime_error("Invalid public key");
    BIGNUM *raw_n{}, *raw_e{};
    BN_hex2bn(&raw_n, modulus.c_str()); BN_hex2bn(&raw_e, exponent.c_str());
    std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> n(raw_n, BN_clear_free), e(raw_e, BN_clear_free);
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> context(BN_CTX_new(), BN_CTX_free);
    std::string password; Wipe wipe{password};
    for (auto ch : credential.password) {
        if (ch < 1 || ch > 127) throw std::runtime_error("Research ASCII password bound");
        password += char(ch);
    }
    if (!n || !e || !context || BN_num_bits(n.get()) < 1024 || BN_num_bits(n.get()) > 4096 ||
        password.empty() || password.size() > 126 || BN_get_word(e.get()) != 65537) throw std::runtime_error("Research RSA bound");
    // The public JS reverses the string, then packs little-endian bytes.
    // For one ASCII block that equals a big-endian password integer.
    std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> message(BN_bin2bn(
        reinterpret_cast<const unsigned char*>(password.data()), int(password.size()), nullptr), BN_clear_free);
    std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> result(BN_new(), BN_clear_free);
    if (!message || !result || !BN_mod_exp(result.get(), message.get(), e.get(), n.get(), context.get()))
        throw std::runtime_error("RSA failed");
    char* raw = BN_bn2hex(result.get()); if (!raw) throw std::runtime_error("RSA format failed");
    std::string hex(raw); OPENSSL_free(raw);
    std::transform(hex.begin(), hex.end(), hex.begin(), [](char ch) { return ch >= 'A' && ch <= 'F' ? char(ch + 32) : ch; });
    hex.insert(0, (4 - hex.size() % 4) % 4, '0'); return hex;
}
void save(const std::filesystem::path& root, const std::string& name, const HttpsResult& reply) {
    std::ofstream(root / (name + ".bin"), std::ios::binary).write(reply.response.body.data(), reply.response.body.size());
    std::ofstream(root / (name + "-type.txt")) << reply.response.content_type;
    std::ofstream(root / (name + "-location.txt")) << reply.response.location;
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2 || std::wstring_view(argv[1]) != L"--live-own-account-readonly") return 2;
    try {
        AccountStore store(data_directory()); const auto catalog = store.load(); Credential credential;
        if (!catalog.first_account()) return 3;
        auto public_page = school_https_request("GET", "/selfservice/module/scgroup/web/login_self.jsf", {});
        if (public_page.state != TransportState::Complete || public_page.response.status != 200) throw std::runtime_error("Public login unavailable");
        auto cookie = public_page.response.session_cookie; Wipe cookie_wipe{cookie};
        const auto destination = std::filesystem::current_path() / "captures/package-api-20261113/openssl-native/devices-pause-research";
        std::filesystem::create_directories(destination);
        auto captcha = school_https_request("GET", "/selfservice/common/web/verifycode.jsp", {}, nullptr, nullptr, cookie);
        if (captcha.state != TransportState::Complete || captcha.response.status != 200 ||
            !captcha.response.content_type.starts_with("image/")) throw std::runtime_error("Captcha unavailable");
        const auto captcha_file = destination / (captcha.response.content_type.starts_with("image/png") ? "captcha.png" : "captcha.jpg");
        std::ofstream(captcha_file, std::ios::binary).write(captcha.response.body.data(), captcha.response.body.size());
        std::cout << "{\"captchaRequired\":true,\"captchaFile\":\"" << captcha_file.generic_string() << "\"}\n" << std::flush;
        std::string verify;
        if (!std::getline(std::cin, verify) || verify.empty() || verify.size() > 12 ||
            verify.find_first_not_of("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != verify.npos) return 4;
        if (!store.read(*catalog.first_account(), credential)) return 3;
        auto cipher = encrypted(credential, input(public_page.response.body, "publicKey")); Wipe cipher_wipe{cipher};
        std::string username; Wipe username_wipe{username};
        for (auto ch : credential.username) { if (ch < 1 || ch > 127) throw std::runtime_error("Research username bound"); username += char(ch); }
        auto body = "from=rsa&name=" + form(username) + "&password=" + form(cipher) + "&verify=" + form(verify) + "&verifyMsg="; Wipe body_wipe{body};
        auto login = school_https_request("POST", "/selfservice/module/scgroup/web/login_judge.jsf", body, nullptr, nullptr, cookie);
        credential.clear();
        if (valid_school_session(login.response.session_cookie)) cookie = login.response.session_cookie;
        save(destination, "normal-login", login);
        const auto location_path = login.response.location.substr(0, login.response.location.find('?'));
        std::cout << "{\"loginHttpStatus\":" << login.response.status << ",\"sessionAvailable\":"
                  << (valid_school_session(cookie) ? "true" : "false") << ",\"locationPath\":\"" << location_path << "\"}\n";
        // Explicit observed read-only pages only. No generic user URL argument.
        for (const auto& [name, path] : {std::pair{"normal-entry", "/selfservice/entry.jsp"},
                                        {"normal-devices", "/selfservice/module/webcontent/web/portal_onlinedevice_list.jsf"}}) {
            auto reply = school_https_request("GET", path, {}, nullptr, nullptr, cookie);
            save(destination, name, reply);
            std::cout << "{\"page\":\"" << name << "\",\"httpStatus\":" << reply.response.status
                      << ",\"bodyBytes\":" << reply.response.body.size() << "}\n";
        }
        unsigned sequence = 0;
        std::cout << "{\"readOnlySessionReady\":true}\n" << std::flush;
        for (std::string path; std::getline(std::cin, path) && path != "quit";) {
            auto lower = path; std::transform(lower.begin(), lower.end(), lower.begin(), [](char ch) { return char(std::tolower(static_cast<unsigned char>(ch))); });
            bool allowed = path.starts_with("/selfservice/") && path.size() < 1024 &&
                           path.find_first_of("\r\n\\# ") == path.npos;
            for (auto denied : {"pause", "resume", "suspend", "offline", "logout", "destroy", "delete", "stop", "enable", "disable",
                                "save", "edit", "update", "add", "operation", "remove", "charge", "pay", "cancel", "freeze", "lock"})
                if (lower.find(denied) != lower.npos) allowed = false;
            // Static scripts are always read as data, never executed. A static
            // script's name may legitimately contain an operation keyword.
            if (path.starts_with("/selfservice/") && path.ends_with(".js") && path.find_first_of("?\r\n\\# ") == path.npos) allowed = true;
            if (!allowed) { std::cout << "{\"readDenied\":true}\n" << std::flush; continue; }
            auto reply = school_https_request("GET", path, {}, nullptr, nullptr, cookie);
            if (valid_school_session(reply.response.session_cookie)) cookie = reply.response.session_cookie;
            const auto name = "read-" + std::to_string(++sequence); save(destination, name, reply);
            std::cout << "{\"file\":\"" << name << "\",\"httpStatus\":" << reply.response.status
                      << ",\"bodyBytes\":" << reply.response.body.size() << "}\n" << std::flush;
        }
        return 0;
    } catch (...) { std::cout << "{\"researchProbeFailed\":true}\n"; return 1; }
}
