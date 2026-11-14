#include "password_change.hpp"
#include "selfservice_crypto.hpp"
#include <algorithm>
#include <optional>
#include <stdexcept>

namespace scau::desktop {
namespace {
template<class T> struct Wipe {
    T& value;
    ~Wipe() { if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(typename T::value_type)); }
};
bool unsafe_parameter(std::wstring_view text) {
    // The original inner query has no escaping: '&' and '=' separate query
    // fields and ':' separates modifyPwd arguments. Do not invent escaping.
    return std::any_of(text.begin(), text.end(), [](wchar_t ch) {
        return ch < 32 || ch == 127 || ch == L'&' || ch == L'=' || ch == L':';
    });
}
std::optional<unsigned> ansi_length(std::wstring_view text) {
    if (text.empty() || text.size() > 240) return std::nullopt;
    BOOL used_default = FALSE;
    const int count = WideCharToMultiByte(936, WC_NO_BEST_FIT_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, &used_default);
    if (count <= 0 || used_default) return std::nullopt;
    return static_cast<unsigned>(count);
}
bool spaces_only(std::wstring_view text) {
    return std::all_of(text.begin(), text.end(), [](wchar_t ch) { return ch == L' '; });
}
std::wstring plain_query(const Credential& credential, std::wstring_view old_password,
                         std::wstring_view new_password) {
    // Keep this ordering identical to FUN_004dd480. The transport path and
    // transformed value remain credential-equivalent and never leave submit.
    std::wstring plain;
    plain.reserve(240);
    plain += L"userid="; plain += credential.username;
    plain += L"&password="; plain += credential.password;
    plain += L"&callBack=modifyPwd:"; plain += old_password;
    plain += L":"; plain += new_password; plain += L"&channel=su";
    return plain;
}
bool marker_end(wchar_t ch) {
    return ch == L'&' || ch == L'\'' || ch == L'"' || ch == L'<' || ch == L'>' ||
           ch == L';' || ch == L'#' || ch == L' ' || ch == L'\r' || ch == L'\n' || ch == L'\t';
}
struct Marker { unsigned count = 0; std::optional<unsigned> code; };
Marker marker(std::wstring_view text, std::wstring_view key) {
    Marker result;
    for (std::size_t pos = 0; (pos = text.find(key, pos)) != text.npos; pos += key.size()) {
        ++result.count;
        const auto number = pos + key.size();
        if (number < text.size() && text[number] >= L'0' && text[number] <= L'2' &&
            (number + 1 == text.size() || marker_end(text[number + 1])))
            result.code = static_cast<unsigned>(text[number] - L'0');
        else result.code.reset();
    }
    return result;
}
PasswordChangeResult parse_result(std::wstring_view text) {
    PasswordChangeResult result{PasswordChangeOutcome::Unknown, PasswordChangeError::UnsupportedResponse, true};
    const auto success = marker(text, L"&success=");
    const auto error = marker(text, L"errorMsg=");
    // Ambiguous, malformed, duplicate and contradictory responses stay unknown.
    if (success.count == 1 && success.code && error.count == 0) {
        if (*success.code == 0) return {PasswordChangeOutcome::Success, PasswordChangeError::None, true};
        return {PasswordChangeOutcome::Rejected,
            *success.code == 2 ? PasswordChangeError::OldPasswordRejected : PasswordChangeError::ServerRejected, true};
    }
    if (error.count == 1 && error.code && success.count == 0) {
        const auto reason = *error.code == 0 ? PasswordChangeError::AuthenticationRejected :
            *error.code == 1 ? PasswordChangeError::PermissionDenied : PasswordChangeError::AccessDenied;
        return {PasswordChangeOutcome::Rejected, reason, true};
    }
    return result;
}
} // namespace

PasswordChangeError validate_password_change(const Credential& credential, std::wstring_view old_password,
    std::wstring_view new_password, std::wstring_view confirmation, PasswordChangePolicy policy) {
    if (credential.username.empty() || credential.password.empty() || old_password.empty() ||
        new_password.empty() || confirmation.empty() || spaces_only(old_password) || spaces_only(new_password))
        return PasswordChangeError::Empty;
    if (new_password != confirmation) return PasswordChangeError::ConfirmationMismatch;
    if (old_password != credential.password) return PasswordChangeError::OldPasswordMismatch;
    if (credential.username.size() > 240 || credential.password.size() > 240 || old_password.size() > 240 ||
        new_password.size() > 240) return PasswordChangeError::TooLong;
    if (unsafe_parameter(credential.username) || unsafe_parameter(credential.password) ||
        unsafe_parameter(old_password) || unsafe_parameter(new_password)) return PasswordChangeError::UnsupportedCharacters;
    const auto old_length = ansi_length(old_password), new_length = ansi_length(new_password);
    if (!old_length || !new_length) return PasswordChangeError::UnsupportedCharacters;
    const unsigned minimum = policy == PasswordChangePolicy::Hust ? 6u : 3u;
    const unsigned maximum = policy == PasswordChangePolicy::Hust ? 12u : 16u;
    if (*old_length > 16 || *new_length < minimum || *new_length > maximum)
        return PasswordChangeError::PasswordLength;
    auto plain = plain_query(credential, old_password, new_password); Wipe wipe{plain};
    const int utf8_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, plain.data(),
        static_cast<int>(plain.size()), nullptr, 0, nullptr, nullptr);
    if (utf8_length <= 0) return PasswordChangeError::UnsupportedCharacters;
    if (utf8_length > static_cast<int>(scau::selfservice_query_max_utf8_bytes)) return PasswordChangeError::TooLong;
    return PasswordChangeError::None;
}

std::wstring password_change_error_text(PasswordChangeError error) {
    switch (error) {
    case PasswordChangeError::None: return {};
    case PasswordChangeError::Empty: return L"请完整填写密码，密码不可全为空格";
    case PasswordChangeError::ConfirmationMismatch: return L"两次输入的新密码不一致";
    case PasswordChangeError::OldPasswordMismatch: return L"原密码与此账号保存的密码不一致";
    case PasswordChangeError::PasswordLength: return L"密码长度不符合原客户端的兼容范围，请使用学校自助页面";
    case PasswordChangeError::UnsupportedCharacters: return L"当前密码含兼容接口不支持的字符，请使用学校自助页面";
    case PasswordChangeError::TooLong: return L"账号或密码超过兼容接口长度，请使用学校自助页面";
    case PasswordChangeError::Cancelled: return L"已取消，尚未提交";
    case PasswordChangeError::Stale: return L"账号已变化，请重新打开修改密码";
    case PasswordChangeError::AlreadySubmitted: return L"本次请求已经提交，请勿重复操作";
    case PasswordChangeError::Network: return L"网络异常";
    case PasswordChangeError::Tls: return L"TLS 连接失败";
    case PasswordChangeError::ServerRejected: return L"学校服务器拒绝修改密码";
    case PasswordChangeError::OldPasswordRejected: return L"学校服务器提示原密码错误";
    case PasswordChangeError::AuthenticationRejected: return L"学校服务器提示账号不存在或密码错误";
    case PasswordChangeError::PermissionDenied: return L"学校服务器提示此账号无修改密码权限";
    case PasswordChangeError::AccessDenied: return L"学校服务器已禁止访问此接口";
    default: return L"学校服务器返回内容无法确认";
    }
}
std::wstring password_change_result_text(const PasswordChangeResult& result) {
    if (result.outcome == PasswordChangeOutcome::Success) return L"校园网密码已修改";
    if (result.outcome == PasswordChangeOutcome::Unknown)
        return L"修改结果未确认，请先通过学校自助页面核实，勿重复提交；本地保存的密码尚未更新";
    return password_change_error_text(result.error);
}

PasswordChangeSession::PasswordChangeSession(PasswordChangeSender sender, PasswordChangePolicy policy)
    : sender_(std::move(sender)), policy_(policy) {
    if (!sender_) sender_ = [](auto method, auto path, auto body, auto cancel) {
        return detail::school_https_request(method, path, body, nullptr, cancel);
    };
}
PasswordChangeResult PasswordChangeSession::submit(const Credential& credential, std::wstring_view old_password,
    std::wstring_view new_password, std::wstring_view confirmation, const std::atomic_bool* cancel,
    std::function<bool()> may_commit) {
    PasswordChangeResult result;
    if (submitted_.load()) { result.error = PasswordChangeError::AlreadySubmitted; return result; }
    try {
        result.error = validate_password_change(credential, old_password, new_password, confirmation, policy_);
        if (result.error != PasswordChangeError::None) return result;
        if (cancel && cancel->load()) { result.error = PasswordChangeError::Cancelled; return result; }
        auto plain = plain_query(credential, old_password, new_password); Wipe plain_wipe{plain};
        auto encoded = scau::selfservice_encode_query(plain); Wipe encoded_wipe{encoded};
        std::string path = "/selfservice/module/scgroup/web/login_judge.jsf?s=";
        path += encoded; Wipe path_wipe{path};
        if (may_commit && !may_commit()) { result.error = PasswordChangeError::Stale; return result; }
        if (cancel && cancel->load()) { result.error = PasswordChangeError::Cancelled; return result; }
        bool expected = false;
        if (!submitted_.compare_exchange_strong(expected, true)) {
            result.error = PasswordChangeError::AlreadySubmitted; return result;
        }
        result = {PasswordChangeOutcome::Unknown, PasswordChangeError::UnsupportedResponse, true};
        auto reply = sender_("GET", path, {}, cancel);
        Wipe body_wipe{reply.response.body}, cookie_wipe{reply.response.session_cookie}, location_wipe{reply.response.location};
        if (reply.state == detail::TransportState::NetworkError) { result.error = PasswordChangeError::Network; return result; }
        if (reply.state == detail::TransportState::TlsError) { result.error = PasswordChangeError::Tls; return result; }
        if (reply.state != detail::TransportState::Complete || !reply.response.complete || reply.response.invalid ||
            reply.response.body.size() > detail::maximum_http_body) return result;
        if (reply.response.status == 401 || reply.response.status == 403)
            return {PasswordChangeOutcome::Rejected, PasswordChangeError::AuthenticationRejected, true};
        if (reply.response.status != 200) return result;
        auto text = detail::decode_school_response(reply.response.body, reply.response.content_type);
        if (!text) return result;
        Wipe text_wipe{*text};
        return parse_result(*text);
    } catch (const std::invalid_argument&) {
        if (!result.request_sent) result.error = PasswordChangeError::UnsupportedCharacters;
    } catch (...) {
        // Once transport is entered, exceptions cannot establish whether the
        // server committed. Never retry and never expose exception/response text.
        if (!result.request_sent) result.error = PasswordChangeError::Stale;
    }
    return result;
}

} // namespace scau::desktop
