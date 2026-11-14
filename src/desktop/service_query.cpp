#include "service_query.hpp"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <algorithm>
#include <cwctype>
#include <map>
#include <stdexcept>

namespace scau::desktop {
namespace {
template<class T> void wipe(T& value) { if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(typename T::value_type)); }
template<class T> struct Wipe { T& value; ~Wipe() { wipe(value); } };
struct Failure { CampusError error; unsigned detail = 0; };
using Attributes = std::map<std::wstring, std::wstring>;
std::wstring lower(std::wstring_view text) {
    std::wstring out(text);
    for (auto& ch : out) if (ch >= L'A' && ch <= L'Z') ch += L'a' - L'A';
    return out;
}
std::wstring unescape(std::wstring_view text) {
    std::wstring out;
    for (std::size_t p = 0; p < text.size();) {
        if (text[p] != L'&') { out += text[p++]; continue; }
        bool matched = false;
        for (const auto& [entity, ch] : {std::pair{L"&amp;", L'&'}, {L"&quot;", L'"'}, {L"&#39;", L'\''},
                                        {L"&lt;", L'<'}, {L"&gt;", L'>'}, {L"&nbsp;", L' '}}) {
            const std::wstring_view token(entity);
            if (text.substr(p).starts_with(token)) { out += ch; p += token.size(); matched = true; break; }
        }
        if (!matched) out += text[p++]; // HTML permits a literal, non-entity ampersand.
    }
    return out;
}
// Bounded attribute parsing, not script/HTML execution. Ignore commented and
// script/style input lookalikes. A duplicate ID/attribute is never accepted.
std::vector<Attributes> inputs(std::wstring_view html) {
    if (html.size() > 524288) throw Failure{CampusError::Data, 101};
    auto folded = lower(html); Wipe folded_wipe{folded};
    // The school's shared head contains malformed translation attributes
    // (literal quote characters). Only the actual service form body contains
    // authoritative permission/target controls; never parse the shared head.
    const auto body = folded.find(L"<body"), body_end = folded.rfind(L"</body");
    if (body == folded.npos || body_end == folded.npos || body_end <= body) throw Failure{CampusError::Data};
    html = html.substr(body, body_end - body);
    folded = folded.substr(body, body_end - body);
    std::vector<Attributes> result;
    for (std::size_t p = 0; (p = html.find(L'<', p)) != html.npos;) {
        if (html.substr(p).starts_with(L"<!--")) {
            const auto end = html.find(L"-->", p + 4); if (end == html.npos) break;
            p = end + 3; continue;
        }
        auto i = p + 1;
        while (i < html.size() && std::iswalpha(html[i])) ++i;
        const auto name = std::wstring_view(folded).substr(p + 1, i - p - 1);
        if (name == L"script" || name == L"style") {
            const auto end = folded.find(name == L"script" ? L"</script" : L"</style", i);
            if (end == folded.npos) break;
            p = end + 2; continue;
        }
        auto end = i; wchar_t quote = 0;
        bool awaiting_value = false, unquoted_value = false;
        for (; end < html.size(); ++end) {
            const auto ch = html[end];
            if (quote) { if (ch == quote) quote = 0; }
            else if (unquoted_value) {
                if (ch == L'>') break;
                if (std::iswspace(ch)) unquoted_value = false;
            } else if (awaiting_value) {
                if (std::iswspace(ch)) continue;
                if (ch == L'>') break;
                awaiting_value = false;
                if (ch == L'\'' || ch == L'"') quote = ch;
                else unquoted_value = true;
            } else if (ch == L'>') break;
            else if (ch == L'=') awaiting_value = true;
        }
        if (end == html.size()) break;
        p = end + 1;
        if (name != L"input") continue;
        Attributes attributes;
        while (i < end) {
            while (i < end && (std::iswspace(html[i]) || html[i] == L'/')) ++i;
            const auto start = i;
            while (i < end && !std::iswspace(html[i]) && html[i] != L'=') ++i;
            if (start == i) break;
            const auto key = lower(html.substr(start, i - start));
            while (i < end && std::iswspace(html[i])) ++i;
            std::wstring value;
            if (i < end && html[i] == L'=') {
                ++i; while (i < end && std::iswspace(html[i])) ++i;
                const auto delimiter = i < end && (html[i] == L'\'' || html[i] == L'"') ? html[i++] : 0;
                const auto value_start = i;
                while (i < end && (delimiter ? html[i] != delimiter : !std::iswspace(html[i]))) ++i;
                value = unescape(html.substr(value_start, i - value_start));
                if (delimiter && i < end) ++i;
            }
            if (!attributes.emplace(key, std::move(value)).second) throw Failure{CampusError::Data, 102};
            if (attributes.size() > 32) throw Failure{CampusError::Data, 103};
        }
        result.push_back(std::move(attributes));
        if (result.size() > 1024) throw Failure{CampusError::Data, 104};
    }
    return result;
}
std::optional<Attributes> field(const std::vector<Attributes>& source, std::wstring_view id) {
    std::optional<Attributes> result;
    for (const auto& attributes : source) {
        const auto found = attributes.find(L"id");
        if (found != attributes.end() && found->second == id) {
            if (result) throw Failure{CampusError::Data};
            result = attributes;
        }
    }
    return result;
}
std::wstring value(const std::optional<Attributes>& input) {
    if (!input || !input->contains(L"value") || input->contains(L"disabled")) throw Failure{CampusError::Data};
    return input->at(L"value");
}
bool permission(const std::vector<Attributes>& source, std::wstring_view id) {
    const auto text = value(field(source, id));
    if (text != L"true" && text != L"false") throw Failure{CampusError::Data};
    return text == L"true";
}
std::string form_user(std::wstring_view user) {
    auto utf8 = winrt::to_string(user); Wipe utf8_wipe{utf8};
    std::string out; constexpr char hex[] = "0123456789ABCDEF";
    for (unsigned char ch : utf8) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.') out += char(ch);
        else { out += '%'; out += hex[ch >> 4]; out += hex[ch & 15]; }
    }
    return out;
}
constexpr char refresh_path[] = "/selfservice/module/userself/web/userself_ajax.jsf?methodName=indexBean.refreshSelfIndexData";
} // namespace

std::wstring campus_state_text(CampusState state) {
    return state == CampusState::Normal ? L"正常" : state == CampusState::Paused ? L"已暂停" : L"未知";
}
std::wstring campus_error_text(CampusError error) {
    switch (error) {
    case CampusError::Network: return L"网络异常";
    case CampusError::Tls: return L"TLS 连接失败";
    case CampusError::Auth: return L"查询登录未通过";
    case CampusError::Data: return L"查询失败";
    case CampusError::Stale: return L"状态已变化，请刷新";
    case CampusError::Permission: return L"当前账号不支持此操作";
    default: return {};
    }
}
CampusSession::CampusSession(CampusSender sender, std::function<std::uint64_t()> clock)
    : sender_(std::move(sender)), clock_(std::move(clock)) {
    if (!sender_) sender_ = [](auto method, auto path, auto body, auto cookie, auto cancel) {
        return detail::school_https_request(method, path, body, nullptr, cancel, cookie);
    };
    if (!clock_) clock_ = [] { return GetTickCount64(); };
}
void CampusSession::erase() noexcept {
    wipe(cookie_); cookie_.clear(); wipe(expected_user_); expected_user_.clear();
    wipe(target_user_); target_user_.clear(); prepared_ = false; valid_until_ = 0;
}
CampusSession::~CampusSession() { erase(); }
std::wstring CampusSession::read(std::string_view method, std::string_view path, std::string_view body,
                                const std::atomic_bool* cancel) {
    if (cancel && cancel->load()) throw Failure{CampusError::Network};
    auto reply = sender_(method, path, body, cookie_, cancel);
    Wipe body_wipe{reply.response.body}, cookie_wipe{reply.response.session_cookie};
    if (reply.state == detail::TransportState::TlsError) throw Failure{CampusError::Tls};
    if (reply.state == detail::TransportState::NetworkError) throw Failure{CampusError::Network};
    if (reply.state != detail::TransportState::Complete) throw Failure{CampusError::Data};
    if (reply.response.status == 401 || reply.response.status == 403 || reply.response.status == 302) throw Failure{CampusError::Auth};
    if (reply.response.status != 200) throw Failure{CampusError::Data};
    if (detail::valid_school_session(reply.response.session_cookie)) {
        wipe(cookie_); cookie_ = std::move(reply.response.session_cookie);
    }
    auto decoded = detail::decode_school_response(reply.response.body, reply.response.content_type);
    if (!decoded) throw Failure{CampusError::Data};
    return std::move(*decoded);
}
void CampusSession::load_view(const std::atomic_bool* cancel) {
    using namespace winrt::Windows::Data::Json;
    prepared_ = false; wipe(target_user_); target_user_.clear();
    if (!detail::valid_school_session(cookie_) || expected_user_.empty()) throw Failure{CampusError::Auth};
    stage_ = 3;
    auto home = read("GET", "/selfservice/module/webcontent/web/index_self.jsf", {}, cancel); Wipe home_wipe{home};
    stage_ = 4;
    const auto fields = inputs(home);
    stage_ = 41;
    const auto pause_permission = permission(fields, L"canSuspend");
    stage_ = 42;
    const auto resume_permission = permission(fields, L"canResume");
    stage_ = 5;
    auto status = read("POST", refresh_path, {}, cancel); Wipe status_wipe{status};
    stage_ = 6;
    const auto json = JsonObject::Parse(status);
    if (std::wstring(json.GetNamedString(L"userId")) != expected_user_) throw Failure{CampusError::Auth};
    const auto state = json.GetNamedValue(L"userState");
    if (state.ValueType() != JsonValueType::Number) throw Failure{CampusError::Data};
    const auto number = state.GetNumber();
    view_.state = number == 2 ? CampusState::Normal : number == 1 ? CampusState::Paused : CampusState::Unknown;
    view_.online_devices.reset();
    if (json.HasKey(L"onlineNum") && json.GetNamedValue(L"onlineNum").ValueType() == JsonValueType::String)
        view_.online_devices = parse_device_count(std::wstring(json.GetNamedString(L"onlineNum")));
    view_.can_pause = view_.state == CampusState::Normal && pause_permission;
    view_.can_resume = view_.state == CampusState::Paused && resume_permission;
    view_.error = CampusError::None;
    if (!view_.can_pause && !view_.can_resume) return;
    const auto action = view_.can_pause ? CampusAction::Pause : CampusAction::Resume;
    stage_ = 7;
    auto form = read("GET", action == CampusAction::Pause ? "/selfservice/module/userself/web/self_suspend.jsf"
                                                         : "/selfservice/module/userself/web/self_resume.jsf", {}, cancel);
    Wipe form_wipe{form};
    stage_ = 8;
    const auto form_fields = inputs(form);
    const auto target_field = field(form_fields, L"targetUserId");
    auto target = value(target_field); Wipe target_wipe{target};
    const auto confirm = field(form_fields, L"confirm");
    if (target != expected_user_ || !target_field->contains(L"type") || lower(target_field->at(L"type")) != L"hidden" ||
        !confirm || confirm->contains(L"disabled") ||
        !confirm->contains(L"type") || lower(confirm->at(L"type")) != L"button" || value(confirm).empty())
        throw Failure{CampusError::Data};
    target_user_ = target; valid_until_ = clock_() + 120000; prepared_ = true; stage_ = 9;
}
CampusView CampusSession::prepare(const Credential& credential, const std::array<unsigned char, 6>& mac,
                                  const std::atomic_bool* cancel) {
    erase(); view_ = {}; expected_user_ = credential.username;
    try {
        stage_ = 1;
        auto path = account_query_path(credential, mac); Wipe path_wipe{path};
        auto summary = read("GET", path, {}, cancel); Wipe summary_wipe{summary};
        view_.online_devices = parse_package_response(summary).online_devices;
        auto route = package_detail_login_path(summary); Wipe route_wipe{route};
        if (route.empty()) throw Failure{CampusError::Data};
        // The original client's information-query session is separate from
        // the web session established by its business-detail link.
        wipe(cookie_); cookie_.clear();
        stage_ = 2;
        auto login = read("GET", route, {}, cancel); Wipe login_wipe{login};
        load_view(cancel);
    } catch (const Failure& error) { view_.error = error.error; prepared_ = false; if (error.detail) stage_ = 1000 + error.detail; }
    catch (const std::out_of_range&) { view_.error = CampusError::Data; prepared_ = false; stage_ = 2001; }
    catch (...) { view_.error = CampusError::Data; prepared_ = false; }
    return view_;
}
CampusView CampusSession::refresh(const std::atomic_bool* cancel) {
    view_.can_pause = view_.can_resume = false;
    try { load_view(cancel); }
    catch (const Failure& error) { view_.error = error.error; prepared_ = false; }
    catch (...) { view_.error = CampusError::Data; prepared_ = false; }
    return view_;
}
CampusResult CampusSession::apply(CampusAction action, const std::atomic_bool* cancel, std::function<bool()> may_commit) {
    CampusResult result; result.view = view_;
    if (!prepared_ || clock_() >= valid_until_ || (may_commit && !may_commit())) {
        prepared_ = false; result.outcome = CampusOutcome::Expired; result.view.error = CampusError::Stale; return result;
    }
    const auto desired = action == CampusAction::Pause ? CampusState::Paused : CampusState::Normal;
    const auto approval_deadline = valid_until_;
    // Re-read identity, permissions, state and form immediately before the
    // single mutation. An edit/removed account guard is checked after all I/O.
    refresh(cancel);
    if (!prepared_ || (action == CampusAction::Pause ? !view_.can_pause : !view_.can_resume) ||
        clock_() >= approval_deadline || (may_commit && !may_commit()) || (cancel && cancel->load())) {
        prepared_ = false; result.outcome = CampusOutcome::Expired; result.view = view_;
        if (result.view.error == CampusError::None) result.view.error = CampusError::Stale;
        return result;
    }
    prepared_ = false;
    bool explicit_success = false, explicit_rejection = false;
    try {
        auto body = "targetUserId=" + form_user(target_user_); Wipe body_wipe{body};
        const auto path = action == CampusAction::Pause
            ? "/selfservice/module/userself/web/userself_ajax.jsf?methodName=userSelfOperationBean.newConfirmSuspend"
            : "/selfservice/module/userself/web/userself_ajax.jsf?methodName=userSelfOperationBean.newConfirmResume";
        result.request_sent = true;
        auto reply = read("POST", path, body, cancel); Wipe reply_wipe{reply};
        using namespace winrt::Windows::Data::Json;
        const auto json = JsonObject::Parse(reply);
        const auto marker = std::wstring(json.GetNamedString(L"data"));
        explicit_success = marker == (action == CampusAction::Pause ? L"toSelfPause" : L"toSelfResume");
        explicit_rejection = !marker.empty() && !explicit_success;
    } catch (...) { /* The request may have committed: never retry it. */ }
    refresh(cancel); // Read-only reconciliation, including timeout/unknown.
    if ((view_.error == CampusError::None && view_.state == desired) || explicit_success) {
        result.outcome = CampusOutcome::Success;
        if (view_.error != CampusError::None || view_.state != desired) {
            view_.state = desired; view_.error = CampusError::None;
            view_.can_pause = view_.can_resume = false; prepared_ = false;
        }
    } else if (explicit_rejection && view_.error == CampusError::None) result.outcome = CampusOutcome::Rejected;
    else { result.outcome = CampusOutcome::Unknown; prepared_ = false; }
    result.view = view_; return result;
}
} // namespace scau::desktop
