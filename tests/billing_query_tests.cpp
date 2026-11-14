#include "desktop/package_query.hpp"
#include <winrt/base.h>
#include <iostream>
#include <stdexcept>

using namespace scau::desktop;
using namespace scau::desktop::detail;
void require(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
namespace {
std::wstring overview(std::wstring policy = L"周期31天24.50元", std::wstring range = L"2026-11-01 至 2026-12-01",
                      std::wstring state = L"正常", std::wstring balance = L"123.45元", std::wstring name = L"合成套餐") {
    return L"<html><body><table id='totalTable'><tr><td>余额</td><td>" + balance +
        L"</td></tr><tr><td>当前套餐</td><td>" + name + L"</td></tr><tr><td>计费策略</td><td>" + policy +
        L"</td></tr><tr><td>周期时间范围</td><td>" + range + L"</td></tr><tr><td>用户状态</td><td>" + state +
        L"</td></tr><tr><td>消费</td><td>99.99元</td></tr><tr><td>待扣款</td><td>0元</td></tr></table></body></html>";
}
struct Fixture {
    unsigned requests = 0;
    bool fail = false, redirect = false, rotate_cookie = false, cancel_after_detail = false;
    std::wstring billing = overview();
    std::atomic_bool cancel = false;
    static HttpsResult response(std::wstring_view text, std::string cookie = {}) {
        HttpsResult out; out.state = TransportState::Complete; out.response.complete = true; out.response.status = 200;
        out.response.body = winrt::to_string(text); out.response.content_type = "text/html; charset=utf-8";
        out.response.session_cookie = std::move(cookie); return out;
    }
    PackageInfo query(PackageDiagnostics* diagnostic = nullptr) {
        Credential own; own.username = L"fixture"; own.password = L"fixture-only";
        return query_package(own, {}, diagnostic, nullptr, &cancel,
            [this](auto method, auto path, auto body, auto, auto cancelled, auto cookie) {
                require(method == "GET" && body.empty(), "Billing must only use empty-body GET requests");
                require(cancelled == &cancel, "Every request honors the same cancellation token");
                ++requests;
                if (requests == 1) {
                    require(path.starts_with("/selfservice/module/scgroup/web/login_judge2.jsf?s=") && cookie.empty(),
                        "Information query has no other session cookie");
                    return response(LR"({"getNewLoginInfo":{"ballInfo":[
                        {"id":"packageandfee","type":"money","displayName":"套餐&余额","value":"123.45",
                         "jsonValue":"{\"packageName\":\"合成套餐\"}",
                         "url":"selfserviceurl/module/scgroup/web/login_judge2.jsf?userid=fixture&password=fixture-only&callBack=su_business_detail&channel=su&index=1&userIp=192.0.2.1"}
                    ]}})", "JSESSIONID=information-fixture");
                }
                if (requests == 2) {
                    require(path.starts_with("/selfservice/module/scgroup/web/login_judge2.jsf?userid=") && cookie.empty(),
                        "Business login starts with a fresh session");
                    return response({}, "JSESSIONID=web-fixture");
                }
                if (requests == 3) {
                    require(path == "/selfservice/module/userself/web/portal_packagemoney.jsf" && cookie == "JSESSIONID=web-fixture",
                        "Only the fixed package page uses its own business cookie");
                    if (cancel_after_detail) cancel = true;
                    return response(LR"(<body><table id='totalTable'>
                        <tr><td>账户余额</td><td>123.45元</td></tr><tr><td>当前套餐</td><td>合成套餐</td></tr>
                        <tr><td>周期范围</td><td>2026-11-01 至 2026-12-01</td></tr></table></body>)",
                        rotate_cookie ? "JSESSIONID=rotated-fixture" : "");
                }
                require(requests == 4 && path == "/selfservice/module/userself/web/consume.jsf" &&
                    cookie == (rotate_cookie ? "JSESSIONID=rotated-fixture" : "JSESSIONID=web-fixture"),
                    "Only the observed read-only overview can supply the policy, with the current session");
                if (fail) return HttpsResult{};
                auto out = response(billing);
                if (redirect) { out.response.status = 302; out.response.location = "https://untrusted.invalid/"; }
                return out;
            });
    }
};
}
int main() {
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        const auto today = std::chrono::year{2026}/11/14;
        const auto parsed = parse_package_detail(overview());
        require(parsed.cycle_fee == 2450 && parsed.cycle_days == 31 && !parsed.monthly_fee && !parsed.next_charge &&
                parsed.service_normal && package_fee_label(parsed) == L"每 31 天扣费" && package_fee(parsed) == 2450,
                "A fixed-day billing policy never becomes a calendar-month fee or an authoritative scheduled debit");
        require(billing_date_text(estimate_next_charge(parsed, today)) == L"2026-12-02" &&
                billing_date_text(estimate_next_charge(parsed, today), true).empty(),
                "The estimate starts after the inclusive cycle, without manufacturing a time");
        for (const auto& policy : {L"周期30天24.50元", L"31天24.50元", L"套餐31天24.50元", L"周期0天24.50元",
                L"周期367天24.50元", L"周期31天-1元", L"周期31天1.001元", L"周期31天24.50元另计", L"周期31天未知元"})
            require(!parse_package_detail(overview(policy)).cycle_fee, "Unknown policy or contradictory range must not supply a fee");
        const auto free = parse_package_detail(overview(L"周期31天0元"));
        require(package_fee(free) == 0 && package_fee_label(free) == L"每 31 天扣费", "A zero-priced policy is known, not missing");
        require(!parse_package_detail(overview(L"周期31天24.50元", L"2026-12-01 至 2026-11-01")).cycle_fee,
                "Reversed cycle cannot supply a policy");
        require(!estimate_next_charge(parsed, std::chrono::year{2026}/10/31) &&
                !estimate_next_charge(parsed, std::chrono::year{2026}/12/2), "A stale or future cycle cannot produce an estimate");
        for (auto state : {L"暂停", L"未知", L""})
            require(!estimate_next_charge(parse_package_detail(overview(L"周期31天24.50元", L"2026-11-01 至 2026-12-01", state)), today),
                    "A non-normal service cannot receive a renewal estimate");
        require(!estimate_next_charge(parse_package_detail(overview(L"周期31天24.50元", L"2026-11-01 至 2026-12-01", L"正常", L"24.49元")), today),
                "Insufficient balance cannot receive a successful-renewal estimate");
        const auto leap = parse_package_detail(overview(L"周期31天24.50元", L"2028-01-30 至 2028-02-29"));
        require(billing_date_text(estimate_next_charge(leap, std::chrono::year{2028}/2/29)) == L"2028-03-01", "Leap-day rollover");
        const auto year = parse_package_detail(overview(L"周期31天24.50元", L"2026-12-02 至 2027-01-01"));
        require(billing_date_text(estimate_next_charge(year, std::chrono::year{2026}/12/31)) == L"2027-01-02", "Year rollover");
        auto duplicate = overview(); duplicate.insert(duplicate.find(L"</table>"), L"<tr><td>计费策略</td><td>周期31天1元</td></tr>");
        require(!parse_package_detail(duplicate).cycle_fee, "Conflicting duplicate policy cannot supply a fee");
        auto monthly = parsed; monthly.monthly_fee = 3000;
        require(package_fee_label(monthly) == L"每月扣费" && package_fee(monthly) == 3000, "Explicit monthly contract remains distinct");
        require(!estimate_next_charge(monthly, today), "Monthly and fixed-day contracts cannot be combined into an estimate");
        {
            Fixture f; f.rotate_cookie = true; PackageDiagnostics d; const auto info = f.query(&d);
            require(f.requests == 4 && d.billing_requested && d.billing_detail_matched && d.billing_http_status == 200 &&
                info.balance == 12345 && info.cycle_fee == 2450 && info.cycle_days == 31 && !info.monthly_fee && !info.next_charge,
                "Only corroborated overview supplies its policy; no mutation, external URL or invented scheduled debit");
        }
        for (unsigned failure = 0; failure < 6; ++failure) {
            Fixture f;
            if (failure == 0) f.fail = true;
            if (failure == 1) f.redirect = true;
            if (failure == 2) f.billing = overview(L"周期31天24.50元", L"2026-11-01 至 2026-12-01", L"正常", L"124.45元");
            if (failure == 3) f.billing = overview(L"周期31天24.50元", L"2026-11-01 至 2026-12-01", L"正常", L"123.45元", L"其他套餐");
            if (failure == 4) f.billing = overview(L"周期31天24.50元", L"2026-12-02 至 2027-01-01");
            if (failure == 5) f.billing = L"<html>login required</html>";
            const auto info = f.query();
            require(info.balance == 12345 && info.cycle_end && !info.cycle_fee && !info.next_charge,
                    "Failure or inconsistent overview preserves known balance/cycle and leaves billing unknown");
        }
        { Fixture f; f.cancel_after_detail = true; const auto info = f.query();
          require(f.requests == 3 && info.balance == 12345 && !info.cycle_fee, "Cancellation prevents the additional overview request"); }
        std::cout << "PASS: fixed-day policy, exact/estimated separation, calendar/funding/state limits, isolated read-only request flow and fallback\n";
        winrt::uninit_apartment(); return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n'; winrt::uninit_apartment(); return 1;
    }
}
