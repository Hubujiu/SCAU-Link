#pragma once
#include "platform.hpp"
#include "school_https.hpp"
#include <atomic>
#include <functional>

namespace scau::desktop {

enum class PasswordChangeOutcome { NotSent, Success, Rejected, Unknown };
enum class PasswordChangeError {
    None, Empty, ConfirmationMismatch, OldPasswordMismatch, PasswordLength,
    UnsupportedCharacters, TooLong, Cancelled, Stale, AlreadySubmitted,
    Network, Tls, ServerRejected, OldPasswordRejected, AuthenticationRejected,
    PermissionDenied, AccessDenied, UnsupportedResponse
};
struct PasswordChangeResult {
    PasswordChangeOutcome outcome = PasswordChangeOutcome::NotSent;
    PasswordChangeError error = PasswordChangeError::None;
    // Conservative: true once the transport is entered. A failure may occur
    // after the server committed; only Success authorizes saving a new secret.
    bool request_sent = false;
};
// The shipped client has a general 3..16-byte profile and a separate 6..12
// profile selected by institution == "hust". Server policy remains final.
enum class PasswordChangePolicy { General, Hust };

PasswordChangeError validate_password_change(const Credential& credential,
    std::wstring_view old_password, std::wstring_view new_password,
    std::wstring_view confirmation, PasswordChangePolicy policy = PasswordChangePolicy::General);
std::wstring password_change_error_text(PasswordChangeError error);
std::wstring password_change_result_text(const PasswordChangeResult& result);
inline constexpr std::wstring_view password_change_official_url = L"https://mavis.scau.edu.cn:8443/selfservice/";

// Injection is for offline fixtures. Production uses the fixed school origin,
// no browser cookies, redirects, retries, credential storage or EAP operations.
using PasswordChangeSender = std::function<detail::HttpsResult(std::string_view method,
    std::string_view path, std::string_view body, const std::atomic_bool* cancel)>;

class PasswordChangeSession {
    PasswordChangeSender sender_;
    std::atomic_bool submitted_ = false;
    PasswordChangePolicy policy_;
  public:
    explicit PasswordChangeSession(PasswordChangeSender sender = {},
        PasswordChangePolicy policy = PasswordChangePolicy::General);
    PasswordChangeSession(const PasswordChangeSession&) = delete;
    PasswordChangeSession& operator=(const PasswordChangeSession&) = delete;
    PasswordChangeResult submit(const Credential& credential,
        std::wstring_view old_password, std::wstring_view new_password,
        std::wstring_view confirmation, const std::atomic_bool* cancel = nullptr,
        std::function<bool()> may_commit = {});
    bool submitted() const noexcept { return submitted_.load(); }
};

} // namespace scau::desktop
