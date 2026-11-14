#include <winsock2.h>
#include "package_query.hpp"
#include "selfservice_crypto.hpp"
#include "school_https.hpp"
#include "connection_setup.hpp"
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <algorithm>
#include <cwctype>
#include <limits>
#include <map>
#include <stdexcept>

namespace scau::desktop {
namespace {
std::wstring trim(std::wstring_view value) {
    while (!value.empty() && std::iswspace(value.front())) value.remove_prefix(1);
    while (!value.empty() && std::iswspace(value.back())) value.remove_suffix(1);
    return std::wstring(value);
}
std::wstring scalar(const winrt::Windows::Data::Json::IJsonValue& value) {
    using winrt::Windows::Data::Json::JsonValueType;
    if (!value) return {};
    if (value.ValueType() == JsonValueType::String) return std::wstring(value.GetString());
    if (value.ValueType() == JsonValueType::Number) return std::wstring(value.Stringify());
    return {};
}
std::wstring string_field(const winrt::Windows::Data::Json::JsonObject& item, std::wstring_view name) {
    return item.HasKey(name) ? scalar(item.GetNamedValue(name)) : std::wstring{};
}
std::wstring label_key(std::wstring_view text) {
    std::wstring key;
    for (auto ch : text) if (!std::iswspace(ch) && ch != L':' && ch != L'：') key += ch;
    return key;
}
void set_label(PackageInfo& info, std::wstring_view label, std::wstring_view value) {
    const auto key = label_key(label);
    // These are semantic display labels, not invented JSON schema aliases.
    if (key == L"余额" || key == L"账户余额" || key == L"账号余额" || key == L"剩余金额")
        info.balance = parse_money(value);
    else if (key == L"月费" || key == L"每月扣费" || key == L"月扣费" || key == L"套餐月费")
        info.monthly_fee = parse_money(value);
    else if (key == L"到期时间" || key == L"到期日期" || key == L"失效时间" || key == L"账户到期时间")
        info.expires = parse_billing_date(value);
    else if (key == L"下次扣费时间" || key == L"下次扣费日期" || key == L"下次结算时间")
        info.next_charge = parse_billing_date(value);
}
void read_items(PackageInfo& info, const winrt::Windows::Data::Json::IJsonValue& value, unsigned depth) {
    using namespace winrt::Windows::Data::Json;
    if (!value || depth > 6) return;
    if (value.ValueType() == JsonValueType::Array) {
        const auto array = value.GetArray();
        if (array.Size() > 128) return;
        for (const auto& item : array) read_items(info, item, depth + 1);
    } else if (value.ValueType() == JsonValueType::Object) {
        const auto item = value.GetObject();
        const auto label = string_field(item, L"displayName"), text = string_field(item, L"value");
        if (label.size() <= 80 && text.size() <= 128) set_label(info, label, text);
        const auto id = string_field(item, L"id");
        // Confirmed against the school's own response and its account-balance
        // detail page. The ID alone is deliberately insufficient.
        if (id == L"packageandfee" && string_field(item, L"type") == L"money" && label == L"套餐&余额")
            info.balance = parse_money(text);
        if (id == L"onlinedevice" && string_field(item, L"type") == L"deviceNum" && label == L"在线设备")
            info.online_devices = parse_device_count(text);
        if (id == L"myPackage" || id == L"myFee" || id == L"packageandfee") {
            JsonObject details{nullptr};
            const auto raw = string_field(item, L"jsonValue");
            if (!raw.empty() && raw.size() <= 65536 && JsonObject::TryParse(raw, details)) {
                const auto name = string_field(details, L"packageName");
                if (!name.empty() && name.size() <= 80) info.name = name;
                // The original parser establishes packageName/desc, but does
                // not establish balance/charge/expiry keys inside this object.
                for (const auto& field : details) read_items(info, field.Value(), depth + 1);
            }
        }
    }
}
struct Wipe {
    std::wstring& text;
    ~Wipe() { SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t)); }
};
struct WipeBytes {
    std::string& text;
    ~WipeBytes() { SecureZeroMemory(text.data(), text.size()); }
};
PackageInfo failed(PackageState state) { PackageInfo info; info.state = state; return info; }
std::wstring adapter_ip(const std::array<unsigned char, 6>& mac) {
    // A fresh wireless installation has no wired connection.scau. Prefer the
    // requested live physical interface, then another usable physical adapter.
    const auto live = connection_adapters();
    const ConnectionAdapter* chosen = nullptr;
    for (const auto& adapter : live) {
        const auto& ip = adapter.address;
        if (!adapter.physical || !adapter.link_up || !adapter.ipv4 || !ip[0] || ip[0] == 127 ||
            ip[0] >= 224 || (ip[0] == 169 && ip[1] == 254)) continue;
        if (!chosen || (adapter.mac == mac && chosen->mac != mac) ||
            ((adapter.mac == mac) == (chosen->mac == mac) && adapter.metric < chosen->metric)) chosen = &adapter;
    }
    if (chosen) {
        wchar_t text[INET_ADDRSTRLEN]{};
        if (InetNtopW(AF_INET,const_cast<unsigned char*>(chosen->address.data()),text,INET_ADDRSTRLEN)) return text;
    }
    ULONG size = 16384;
    std::vector<unsigned char> buffer(size);
    auto adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    auto result = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                      GAA_FLAG_SKIP_DNS_SERVER, nullptr, adapters, &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size); adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                     GAA_FLAG_SKIP_DNS_SERVER, nullptr, adapters, &size);
    }
    if (result != NO_ERROR) return L"255.255.255.255";
    for (auto p = adapters; p; p = p->Next) {
        if (p->PhysicalAddressLength != mac.size() || !std::equal(mac.begin(), mac.end(), p->PhysicalAddress)) continue;
        for (auto u = p->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
            const auto address = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr)->sin_addr;
            wchar_t text[INET_ADDRSTRLEN]{};
            if (InetNtopW(AF_INET, const_cast<IN_ADDR*>(&address), text, INET_ADDRSTRLEN)) return text;
        }
    }
    return L"255.255.255.255";
}
} // namespace

std::optional<unsigned> parse_device_count(std::wstring_view text) {
    if (text.empty() || text.size() > 5) return {};
    unsigned count = 0;
    for (auto ch : text) {
        if (ch < L'0' || ch > L'9') return {};
        count = count * 10 + unsigned(ch - L'0');
    }
    return count <= 65535 ? std::optional(count) : std::nullopt;
}
std::wstring device_count_text(const std::optional<unsigned>& count) {
    return count ? std::to_wstring(*count) + L" 台" : L"未知";
}

std::optional<std::int64_t> parse_money(std::wstring_view source) {
    auto value = trim(source);
    if (value.starts_with(L"¥") || value.starts_with(L"￥")) value.erase(0, 1);
    if (value.ends_with(L"元")) value.pop_back();
    value = trim(value);
    if (value.empty() || value.size() > 18) return {};
    bool negative = value.front() == L'-';
    std::size_t i = negative ? 1 : 0, digits = 0;
    std::int64_t whole = 0, fraction = 0;
    while (i < value.size() && value[i] >= L'0' && value[i] <= L'9') {
        if (++digits > 12) return {};
        whole = whole * 10 + value[i++] - L'0';
    }
    if (!digits) return {};
    if (i < value.size() && value[i] == L'.') {
        ++i;
        unsigned decimals = 0;
        while (i < value.size() && value[i] >= L'0' && value[i] <= L'9') {
            if (++decimals > 2) return {};
            fraction = fraction * 10 + value[i++] - L'0';
        }
        if (!decimals) return {};
        if (decimals == 1) fraction *= 10;
    }
    if (i != value.size()) return {};
    return (whole * 100 + fraction) * (negative ? -1 : 1);
}
std::optional<BillingDate> parse_billing_date(std::wstring_view source) {
    const auto text = trim(source);
    if (text.size() != 10 && text.size() != 16 && text.size() != 19) return {};
    auto number = [&](std::size_t at, std::size_t count) {
        int n = 0;
        for (std::size_t i = at; i < at + count; ++i) {
            if (text[i] < L'0' || text[i] > L'9') return -1;
            n = n * 10 + text[i] - L'0';
        }
        return n;
    };
    if ((text[4] != L'-' && text[4] != L'/') || text[7] != text[4]) return {};
    BillingDate value{number(0, 4), number(5, 2), number(8, 2), {}};
    const std::chrono::year_month_day day{std::chrono::year{value.year}, std::chrono::month(unsigned(value.month)),
                                         std::chrono::day(unsigned(value.day))};
    if (value.year < 1970 || value.year > 2199 || !day.ok()) return {};
    if (text.size() > 10) {
        if ((text[10] != L' ' && text[10] != L'T') || text[13] != L':') return {};
        const int h = number(11, 2), m = number(14, 2), s = text.size() == 19 ? number(17, 2) : 0;
        if (h < 0 || h > 23 || m < 0 || m > 59 || s < 0 || s > 59 || (text.size() == 19 && text[16] != L':')) return {};
        value.seconds = h * 3600 + m * 60 + s;
    }
    return value;
}
std::wstring money_text(const std::optional<std::int64_t>& amount) {
    if (!amount) return L"未知";
    const std::uint64_t n = *amount < 0 ? std::uint64_t(-(*amount + 1)) + 1 : std::uint64_t(*amount);
    return (*amount < 0 ? L"-¥" : L"¥") + std::to_wstring(n / 100) + L"." +
           (n % 100 < 10 ? L"0" : L"") + std::to_wstring(n % 100);
}
std::wstring billing_date_text(const std::optional<BillingDate>& date, bool time) {
    if (!date) return time ? L"" : L"未知";
    wchar_t out[32]{};
    if (time) {
        if (!date->seconds) return {};
        swprintf_s(out, L"%02d:%02d", *date->seconds / 3600, *date->seconds / 60 % 60);
    } else swprintf_s(out, L"%04d-%02d-%02d", date->year, date->month, date->day);
    return out;
}
std::wstring expiry_text(const std::optional<BillingDate>& date, std::chrono::year_month_day today) {
    if (!date || !today.ok()) return L"到期时间 未知";
    const std::chrono::year_month_day target{std::chrono::year(date->year), std::chrono::month(unsigned(date->month)),
                                            std::chrono::day(unsigned(date->day))};
    if (!target.ok()) return L"到期时间 未知";
    const auto days = (std::chrono::sys_days(target) - std::chrono::sys_days(today)).count();
    return days < 0 ? L"已到期" : days == 0 ? L"今日到期" : std::to_wstring(days) + L" 天后到期";
}
std::wstring package_expiry_text(const PackageInfo& info, std::chrono::year_month_day today) {
    if (info.expires || !info.cycle_end || !today.ok()) return expiry_text(info.expires, today);
    const auto& date = *info.cycle_end;
    const std::chrono::year_month_day target{std::chrono::year{date.year}, std::chrono::month(unsigned(date.month)),
                                            std::chrono::day(unsigned(date.day))};
    if (!target.ok()) return L"到期时间 未知";
    const auto days = (std::chrono::sys_days(target) - std::chrono::sys_days(today)).count();
    return days < 0 ? L"本期已结束" : days == 0 ? L"本期今日到期" : L"本期剩余 " + std::to_wstring(days) + L" 天";
}
std::wstring package_status_text(PackageState state) {
    switch (state) {
    case PackageState::Loading: return L"套餐查询中";
    case PackageState::CertificateError: return L"套餐查询：证书校验失败";
    case PackageState::TlsError: return L"套餐查询：TLS 连接失败";
    case PackageState::NetworkError: return L"套餐查询：网络异常";
    case PackageState::AuthError: return L"套餐查询：登录未通过";
    case PackageState::Unsupported: return L"套餐查询：数据不可用";
    case PackageState::Partial: return L"套餐查询：部分信息未提供";
    default: return {};
    }
}
PackageInfo parse_package_response(std::wstring_view text) {
    using namespace winrt::Windows::Data::Json;
    PackageInfo info;
    info.state = PackageState::Unsupported;
    if (text.empty() || text.size() > 524288) return info;
    const auto cleaned = trim(text);
    text = cleaned;
    if (text.starts_with(L"ballInfo(") && (text.ends_with(L");") || text.ends_with(L")"))) {
        const auto suffix = text.ends_with(L");") ? 2u : 1u;
        text = text.substr(9, text.size() - 9 - suffix);
    }
    try {
        JsonObject root{nullptr};
        // JSONP leaves a non-null-terminated view. WinRT's string-reference
        // parameter requires a terminator; use an owning HSTRING here.
        if (!JsonObject::TryParse(winrt::hstring{text}, root) || !root.HasKey(L"getNewLoginInfo")) return info;
        const auto login = root.GetNamedObject(L"getNewLoginInfo");
        if (!login.HasKey(L"ballInfo")) return info;
        read_items(info, login.GetNamedValue(L"ballInfo"), 0);
        if (info.balance || info.monthly_fee || info.expires || info.next_charge || info.online_devices || !info.name.empty())
            info.state = info.balance && info.monthly_fee && info.expires && info.next_charge
                             ? PackageState::Ready : PackageState::Partial;
    } catch (const winrt::hresult_error&) { return failed(PackageState::Unsupported); }
    return info;
}
std::string package_detail_login_path(std::wstring_view text) {
    using namespace winrt::Windows::Data::Json;
    if (text.empty() || text.size() > 524288) return {};
    const auto cleaned = trim(text); text = cleaned;
    if (text.starts_with(L"ballInfo(") && (text.ends_with(L");") || text.ends_with(L")")))
        text = text.substr(9, text.size() - 9 - (text.ends_with(L");") ? 2u : 1u));
    try {
        JsonObject root{nullptr};
        if (!JsonObject::TryParse(winrt::hstring{text}, root)) return {};
        const auto items = root.GetNamedObject(L"getNewLoginInfo").GetNamedArray(L"ballInfo");
        if (items.Size() > 128) return {};
        for (const auto& value : items) {
            if (value.ValueType() != JsonValueType::Object) continue;
            const auto item = value.GetObject();
            if (string_field(item, L"id") != L"packageandfee") continue;
            auto url = string_field(item, L"url"); Wipe url_wipe{url};
            constexpr std::wstring_view prefix = L"selfserviceurl/module/scgroup/web/login_judge2.jsf?";
            if (!url.starts_with(prefix) || url.size() > 1800) return {};
            for (auto ch : url) if (ch < 33 || ch > 126 || ch == L'#' || ch == L'\\') return {};
            std::map<std::wstring_view, std::wstring_view> parameters;
            auto query = std::wstring_view(url).substr(prefix.size());
            while (!query.empty()) {
                const auto end = query.find(L'&');
                const auto part = query.substr(0, end);
                const auto equals = part.find(L'=');
                if (equals == part.npos || !parameters.emplace(part.substr(0, equals), part.substr(equals + 1)).second) return {};
                if (end == query.npos) break;
                query.remove_prefix(end + 1);
            }
            if (parameters.size() != 6 || !parameters.contains(L"userid") || !parameters.contains(L"password") ||
                !parameters.contains(L"userIp") || parameters[L"userid"].empty() || parameters[L"password"].empty() ||
                parameters[L"callBack"] != L"su_business_detail" ||
                parameters[L"channel"] != L"su" || parameters[L"index"] != L"1") return {};
            return "/selfservice" + winrt::to_string(std::wstring_view(url).substr(std::wstring_view(L"selfserviceurl").size()));
        }
    } catch (const winrt::hresult_error&) {}
    return {};
}
std::string account_query_path(const Credential& credential, const std::array<unsigned char, 6>& mac) {
    if (credential.username.empty() || credential.password.empty() ||
        credential.username.find_first_of(L"&=\r\n") != std::wstring::npos ||
        credential.password.find_first_of(L"&=\r\n") != std::wstring::npos) throw std::invalid_argument("Unsupported account query");
    std::wstring plain = L"userid=" + credential.username + L"&password=" + credential.password +
                         L"&userip=" + adapter_ip(mac) + L"&callBack=ballInfo&channel=su";
    Wipe wipe{plain};
    auto encoded = scau::selfservice_encode_query(plain);
    WipeBytes encoded_wipe{encoded};
    return "/selfservice/module/scgroup/web/login_judge2.jsf?s=" + encoded;
}
PackageInfo query_package(const Credential& credential, const std::array<unsigned char, 6>& mac,
                          PackageDiagnostics* diagnostics, std::string* private_response, const std::atomic_bool* cancel,
                          PackageSender sender, unsigned interface_index) {
    auto effective_mac=mac;
    if (!sender) {
        const auto adapters=connection_adapters();const ConnectionAdapter* chosen=nullptr;
        for(const auto& adapter:adapters) {
            const auto& ip=adapter.address;
            if(!adapter.physical || !adapter.link_up || !adapter.ipv4 || !ip[0] || ip[0]==127 || ip[0]>=224 ||
                (ip[0]==169 && ip[1]==254) || (interface_index && adapter.index!=interface_index))continue;
            if(!chosen || (adapter.mac==mac && chosen->mac!=mac) ||
                ((adapter.mac==mac)==(chosen->mac==mac) && adapter.metric<chosen->metric))chosen=&adapter;
        }
        if(!chosen)return failed(PackageState::NetworkError);
        effective_mac=chosen->mac;interface_index=chosen->index;
        sender=[interface_index](auto method,auto path,auto body,auto diagnostics,auto cancel,auto cookie){
            return detail::school_https_request_on_interface(interface_index,method,path,body,diagnostics,cancel,cookie);
        };
    }
    if (diagnostics) *diagnostics = {};
    if (private_response) private_response->clear();
    std::string path; WipeBytes path_wipe{path};
    try { path = account_query_path(credential, effective_mac); }
    catch (const std::exception&) { return failed(PackageState::Unsupported); }
    detail::TlsDiagnostics tls;
    auto reply = sender("GET", path, {}, &tls, cancel, {});
    WipeBytes response_wipe{reply.response.body};
    WipeBytes response_cookie_wipe{reply.response.session_cookie};
    if (diagnostics) {
        diagnostics->transport_error = tls.socket_error;
        diagnostics->tls_library_error = tls.tls_error;
        diagnostics->http_status = reply.response.status;
        diagnostics->tls_connected = tls.connected;
        diagnostics->certificate_checks_disabled = tls.connected;
        diagnostics->legacy_tls_used = true;
        diagnostics->content_type = reply.response.content_type;
    }
    if (private_response) *private_response = reply.response.body;
    if (reply.state == detail::TransportState::TlsError) return failed(PackageState::TlsError);
    if (reply.state == detail::TransportState::NetworkError) return failed(PackageState::NetworkError);
    if (reply.state != detail::TransportState::Complete) return failed(PackageState::Unsupported);
    if (reply.response.status == 401 || reply.response.status == 403) return failed(PackageState::AuthError);
    if (reply.response.status != 200) return failed(PackageState::Unsupported);
    auto decoded = detail::decode_school_response(reply.response.body, reply.response.content_type);
    if (!decoded) return failed(PackageState::Unsupported);
    Wipe decoded_wipe{*decoded};
    auto info = parse_package_response(*decoded);
    if (info.state != PackageState::Ready && info.state != PackageState::Partial) return info;
    if (cancel && cancel->load()) return info;

    // The server's observed index=1 link establishes an isolated web session.
    // Returned JavaScript is never executed or followed.
    // Only the two observed read-only package overview pages are requested.
    try {
        auto login_path = package_detail_login_path(*decoded);
        WipeBytes login_path_wipe{login_path};
        if (login_path.empty()) return info;
        SecureZeroMemory(path.data(), path.size());
        path = std::move(login_path);
        auto login = sender("GET", path, {}, nullptr, cancel, {});
        WipeBytes login_body_wipe{login.response.body}, login_cookie_wipe{login.response.session_cookie};
        if (diagnostics) {
            diagnostics->detail_login_status = login.response.status;
            diagnostics->detail_session_available = detail::valid_school_session(login.response.session_cookie);
            diagnostics->detail_redirect_recognized = login.response.body.find(
                "/selfservice/module/userself/web/portal_business_detail.jsf?") != std::string::npos;
        }
        if (login.state != detail::TransportState::Complete || login.response.status != 200 ||
            !detail::valid_school_session(login.response.session_cookie)) return info;
        if (cancel && cancel->load()) return info;
        if (diagnostics) diagnostics->detail_requested = true;
        auto page = sender("GET", "/selfservice/module/userself/web/portal_packagemoney.jsf", {},
                           nullptr, cancel, login.response.session_cookie);
        WipeBytes page_body_wipe{page.response.body}, page_cookie_wipe{page.response.session_cookie};
        if (diagnostics) diagnostics->detail_http_status = page.response.status;
        if (page.state != detail::TransportState::Complete || page.response.status != 200) return info;
        auto html = detail::decode_school_response(page.response.body, page.response.content_type);
        if (!html) return info;
        Wipe html_wipe{*html};
        const auto more = parse_package_detail(*html);
        if ((more.balance && info.balance && more.balance != info.balance) ||
            (!more.name.empty() && !info.name.empty() && more.name != info.name)) return info;
        if (!info.balance) info.balance = more.balance;
        if (!info.monthly_fee) info.monthly_fee = more.monthly_fee;
        if (!info.expires) info.expires = more.expires;
        if (!info.next_charge) info.next_charge = more.next_charge;
        info.cycle_end = more.cycle_end;
        info.cycle_start = more.cycle_start;
        if (info.name.empty()) info.name = more.name;
        if ((!info.monthly_fee || !info.next_charge) && !(cancel && cancel->load())) {
            if (diagnostics) diagnostics->billing_requested = true;
            const auto cookie = detail::valid_school_session(page.response.session_cookie)
                ? std::string_view(page.response.session_cookie) : std::string_view(login.response.session_cookie);
            auto billing_page = sender("GET", "/selfservice/module/userself/web/consume.jsf", {}, nullptr, cancel, cookie);
            WipeBytes billing_body_wipe{billing_page.response.body}, billing_cookie_wipe{billing_page.response.session_cookie};
            if (diagnostics) diagnostics->billing_http_status = billing_page.response.status;
            if (billing_page.state == detail::TransportState::Complete && billing_page.response.status == 200) {
                auto billing_html = detail::decode_school_response(billing_page.response.body, billing_page.response.content_type);
                if (billing_html) {
                    Wipe billing_html_wipe{*billing_html};
                    const auto billing = parse_package_detail(*billing_html);
                    // A policy from an inconsistent or stale overview must not be
                    // attached to this account. Require both known account
                    // values and exactly the same complete cycle range.
                    const auto date_equal = [](const auto& a, const auto& b) {
                        return a && b && a->year == b->year && a->month == b->month && a->day == b->day;
                    };
                    if (info.balance && billing.balance && info.balance == billing.balance &&
                        !info.name.empty() && info.name == billing.name &&
                        date_equal(info.cycle_start, billing.cycle_start) && date_equal(info.cycle_end, billing.cycle_end)) {
                        if (diagnostics) diagnostics->billing_detail_matched = true;
                        info.cycle_fee = billing.cycle_fee; info.cycle_days = billing.cycle_days;
                        info.service_normal = billing.service_normal;
                        if (!info.monthly_fee) info.monthly_fee = billing.monthly_fee;
                        if (!info.next_charge) info.next_charge = billing.next_charge;
                    }
                }
            }
        }
        info.state = info.balance && info.monthly_fee && info.expires && info.next_charge
                         ? PackageState::Ready : PackageState::Partial;
    } catch (const std::exception&) { /* Keep the already verified summary. */ }
    return info;
}
} // namespace scau::desktop
