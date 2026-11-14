#include "desktop/password_change.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace scau::desktop;
using namespace scau::desktop::detail;
namespace {
void require(bool condition, const char* why) { if (!condition) throw std::runtime_error(why); }
void fixture_credential(Credential& value) { value.username = L"fixture"; value.password = L"fixture-only"; }
HttpsResult response(std::string body, unsigned status = 200) {
    HttpsResult result; result.state = TransportState::Complete;
    result.response.complete = true; result.response.status = status;
    result.response.content_type = "text/html; charset=utf-8";
    result.response.body = std::move(body); return result;
}
PasswordChangeResult submit(PasswordChangeSession& session, Credential& credential,
    const std::atomic_bool* cancel = nullptr, std::function<bool()> guard = {}) {
    return session.submit(credential, L"fixture-only", L"new-fixture-123", L"new-fixture-123", cancel, std::move(guard));
}
constexpr char expected_path[] = "/selfservice/module/scgroup/web/login_judge.jsf?s="
    // Independent Python hashlib oracle, synthetic inputs only. This fixes
    // original field ordering, both old-password occurrences and transform.
    "8983c6ef3bad1c29df012cc388dad8ec87a740c899a79f7ac2d0776eadee5b3f36be3"
    "2b807347f9859e3fda770201a0c784f4588d87de7f32de6df9e8604cdbaf750b87"
    "dad4618ebfa68525df916e490e2cd715a1469a25ea47112ea4aa0256b";
void validate() {
    Credential credential; fixture_credential(credential);
    const auto check = [&](std::wstring_view old, std::wstring_view next, std::wstring_view confirm,
                           PasswordChangePolicy policy = PasswordChangePolicy::General) {
        return validate_password_change(credential, old, next, confirm, policy);
    };
    require(check(L"fixture-only", L"abc", L"abc") == PasswordChangeError::None, "General minimum");
    require(check(L"fixture-only", L"1234567890123456", L"1234567890123456") == PasswordChangeError::None, "General maximum");
    require(check(L"fixture-only", L"ab", L"ab") == PasswordChangeError::PasswordLength, "General lower bound");
    require(check(L"fixture-only", L"12345678901234567", L"12345678901234567") == PasswordChangeError::PasswordLength, "General upper bound");
    require(check(L"fixture-only", L"abc", L"abc", PasswordChangePolicy::Hust) == PasswordChangeError::PasswordLength, "Hust separate lower bound");
    require(check(L"fixture-only", L"123456789012", L"123456789012", PasswordChangePolicy::Hust) == PasswordChangeError::None, "Hust maximum");
    require(check(L"fixture-only", L"1234567890123", L"1234567890123", PasswordChangePolicy::Hust) == PasswordChangeError::PasswordLength, "Hust upper bound");
    require(check({}, L"abc", L"abc") == PasswordChangeError::Empty, "Old password required");
    require(check(L"fixture-only", {}, {}) == PasswordChangeError::Empty, "New password required");
    require(check(L"fixture-only", L"   ", L"   ") == PasswordChangeError::Empty, "No all-space new password");
    require(check(L"wrong-password", L"abc", L"abc") == PasswordChangeError::OldPasswordMismatch, "Local old password must match");
    require(check(L"fixture-only", L"abc", L"abd") == PasswordChangeError::ConfirmationMismatch, "Confirmation exact match");
    for (wchar_t delimiter : {L'&', L'=', L':', L'\r', L'\n', L'\0'}) {
        std::wstring next = L"fixture"; next += delimiter; next += L"123";
        require(check(L"fixture-only", next, next) == PasswordChangeError::UnsupportedCharacters, "No invented callback escaping");
    }
    require(check(L"fixture-only", L" a ", L" a ") == PasswordChangeError::None, "Do not trim passwords");
    require(check(L"fixture-only", L"新密码", L"新密码") == PasswordChangeError::None, "Lossless GBK can be transformed");
    require(check(L"fixture-only", L"新新新新新新新新新", L"新新新新新新新新新") == PasswordChangeError::PasswordLength, "Length is original ANSI bytes");
    const std::wstring unpaired(1, wchar_t(0xd800));
    require(check(L"fixture-only", unpaired, unpaired) == PasswordChangeError::UnsupportedCharacters, "Reject lossy Unicode");
    credential.username = std::wstring(210, L'u');
    require(check(L"fixture-only", L"abc", L"abc") == PasswordChangeError::TooLong, "Original total query bound");
    credential.username = L"fixture&channel=other";
    require(check(L"fixture-only", L"abc", L"abc") == PasswordChangeError::UnsupportedCharacters, "No username query injection");
}
void success_and_replay() {
    Credential credential; fixture_credential(credential);
    unsigned calls = 0;
    PasswordChangeSession session([&](auto method, auto path, auto body, auto) {
        ++calls; require(method == "GET" && body.empty(), "Original empty-body GET");
        require(path == expected_path, "Frozen original request contract");
        require(path.find("fixture") == path.npos, "No plaintext query credentials");
        return response("<script>location='reply.jsf?item=modifyPwd&success=0';</script>");
    });
    auto result = submit(session, credential);
    require(result.outcome == PasswordChangeOutcome::Success && result.error == PasswordChangeError::None && result.request_sent, "Explicit original zero-success marker");
    require(credential.password == L"fixture-only", "Module never writes caller or persistent credentials");
    result = submit(session, credential);
    require(result.outcome == PasswordChangeOutcome::NotSent && result.error == PasswordChangeError::AlreadySubmitted && !result.request_sent && calls == 1, "Success ticket cannot replay");
}
void rejections() {
    Credential credential; fixture_credential(credential);
    const std::vector<std::pair<std::string, PasswordChangeError>> replies = {
        {"x&success=1", PasswordChangeError::ServerRejected},
        {"x&success=2", PasswordChangeError::OldPasswordRejected},
        {"reply.jsf?errorMsg=0", PasswordChangeError::AuthenticationRejected},
        {"reply.jsf?errorMsg=1", PasswordChangeError::PermissionDenied},
        {"reply.jsf?errorMsg=2", PasswordChangeError::AccessDenied},
    };
    for (const auto& [body, error] : replies) {
        unsigned calls = 0;
        PasswordChangeSession session([&](auto, auto, auto, auto) { ++calls; return response(body); });
        const auto result = submit(session, credential);
        require(result.outcome == PasswordChangeOutcome::Rejected && result.error == error && result.request_sent, "Original explicit rejection");
        require(submit(session, credential).error == PasswordChangeError::AlreadySubmitted && calls == 1, "Rejected request cannot replay");
    }
}
void unknowns() {
    Credential credential; fixture_credential(credential);
    for (const auto& body : {"", "<html>login form</html>", "true", "0", "&success=", "&success=3", "&success=00", "&success=0junk",
         "&success=0&success=0", "&success=0&success=2", "&success=0&errorMsg=1", "errorMsg=0&errorMsg=0", "success=0"}) {
        unsigned calls = 0;
        PasswordChangeSession session([&](auto, auto, auto, auto) { ++calls; return response(body); });
        const auto result = submit(session, credential);
        require(result.outcome == PasswordChangeOutcome::Unknown && result.request_sent, "No inferred or ambiguous success");
        require(submit(session, credential).error == PasswordChangeError::AlreadySubmitted && calls == 1, "Unknown request cannot replay");
        require(password_change_result_text(result).find(L"结果未确认") != std::wstring::npos, "Uncertain result tells user to verify");
    }
    for (unsigned status : {201u, 302u, 400u, 404u, 500u}) {
        PasswordChangeSession session([&](auto, auto, auto, auto) { return response("&success=0", status); });
        require(submit(session, credential).outcome == PasswordChangeOutcome::Unknown, "Non-200 cannot confirm success or follow redirects");
    }
    for (bool invalid : {false, true}) {
        PasswordChangeSession session([&](auto, auto, auto, auto) {
            auto result = response("&success=0"); result.response.complete = invalid; result.response.invalid = invalid; return result;
        });
        require(submit(session, credential).outcome == PasswordChangeOutcome::Unknown, "Incomplete or invalid framing cannot confirm success");
    }
    PasswordChangeSession oversized([](auto, auto, auto, auto) { return response(std::string(maximum_http_body + 1, 'a') + "&success=0"); });
    require(submit(oversized, credential).outcome == PasswordChangeOutcome::Unknown, "Bounded response");
}
void failures_and_guards() {
    Credential credential; fixture_credential(credential);
    for (auto state : {TransportState::NetworkError, TransportState::TlsError, TransportState::ProtocolError}) {
        unsigned calls = 0;
        PasswordChangeSession session([&](auto, auto, auto, auto) { ++calls; auto r = response("&success=0"); r.state = state; return r; });
        auto result = submit(session, credential);
        require(result.outcome == PasswordChangeOutcome::Unknown && result.request_sent, "Transport failure may follow a commit");
        require(submit(session, credential).error == PasswordChangeError::AlreadySubmitted && calls == 1, "Transport failure never retries");
    }
    unsigned calls = 0;
    PasswordChangeSession exception([&](auto, auto, auto, auto) -> HttpsResult { ++calls; throw std::runtime_error("synthetic-private-response"); });
    const auto ambiguous = submit(exception, credential);
    require(ambiguous.outcome == PasswordChangeOutcome::Unknown && ambiguous.request_sent && calls == 1, "Thrown transport remains unknown");
    require(password_change_result_text(ambiguous).find(L"synthetic") == std::wstring::npos, "No exception disclosure");
    PasswordChangeSession guarded([&](auto, auto, auto, auto) { ++calls; return response("&success=0"); });
    std::atomic_bool cancelled = true;
    auto result = submit(guarded, credential, &cancelled);
    require(result.outcome == PasswordChangeOutcome::NotSent && result.error == PasswordChangeError::Cancelled && calls == 1 && !guarded.submitted(), "Pre-send cancel does no I/O");
    cancelled = false;
    result = submit(guarded, credential, &cancelled, [] { return false; });
    require(result.outcome == PasswordChangeOutcome::NotSent && result.error == PasswordChangeError::Stale && calls == 1 && !guarded.submitted(), "Credential generation guard precedes mutation");
    result = submit(guarded, credential, &cancelled, [&] { cancelled = true; return true; });
    require(result.error == PasswordChangeError::Cancelled && calls == 1, "Cancellation after guard still prevents transport");
    cancelled = false;
    result = submit(guarded, credential, &cancelled, [] { return true; });
    require(result.outcome == PasswordChangeOutcome::Success && calls == 2, "Unsent validation failures need not consume the session");
    PasswordChangeSession validation([&](auto, auto, auto, auto) { ++calls; return response("&success=0"); });
    result = validation.submit(credential, L"fixture-only", L"next-one", L"different");
    require(result.error == PasswordChangeError::ConfirmationMismatch && !result.request_sent && calls == 2, "Invalid fields never reach transport");
}
void simultaneous_submit() {
    Credential credential; fixture_credential(credential);
    std::atomic_uint calls = 0;
    PasswordChangeSession session([&](auto, auto, auto, auto) { ++calls; return response("&success=0"); });
    PasswordChangeResult first, second;
    std::thread one([&] { first = submit(session, credential); });
    std::thread two([&] { second = submit(session, credential); });
    one.join(); two.join();
    require(calls.load() == 1, "Concurrent confirm enters transport once");
    require((first.outcome == PasswordChangeOutcome::Success && second.error == PasswordChangeError::AlreadySubmitted) ||
            (second.outcome == PasswordChangeOutcome::Success && first.error == PasswordChangeError::AlreadySubmitted), "Concurrent loser receives a consumed-session result");
}
} // namespace
int main() {
    try {
        validate(); success_and_replay(); rejections(); unknowns(); failures_and_guards(); simultaneous_submit();
        std::cout << "Password change offline contract, single-submit and ambiguity checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
