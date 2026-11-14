#include "desktop/package_query.hpp"
#include <winrt/base.h>
#include <iostream>
#include <stdexcept>

using namespace scau::desktop;
void require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
int main() {
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        require(parse_device_count(L"0") == 0 && parse_device_count(L"2") == 2 &&
                    parse_device_count(L"65535") == 65535 && device_count_text(0) == L"0 台" &&
                    device_count_text({}) == L"未知", "Device count preserves zero and unknown independently");
        for (auto bad : {L"", L"未知", L"-1", L"1.0", L"2台", L" 2", L"2 ", L"65536", L"100000"})
            require(!parse_device_count(bad), "Malformed device count remains unknown");
        const auto devices = parse_package_response(LR"({"getNewLoginInfo":{"ballInfo":[
            {"id":"onlinedevice","type":"deviceNum","displayName":"在线设备","value":"2"}
        ]}})");
        require(devices.state == PackageState::Partial && devices.online_devices == 2 && !devices.balance,
                "The observed device item supplies a count without inventing financial fields");
        for (auto item : {LR"({"id":"onlinedevice","type":"text","displayName":"在线设备","value":"2"})",
                          LR"({"id":"other","type":"deviceNum","displayName":"在线设备","value":"2"})",
                          LR"({"id":"onlinedevice","type":"deviceNum","displayName":"最大设备数","value":"2"})",
                          LR"({"id":"onlinedevice","type":"deviceNum","displayName":"在线设备","value":"unknown"})"})
            require(!parse_package_response(L"{\"getNewLoginInfo\":{\"ballInfo\":[" + std::wstring(item) + L"]}}").online_devices,
                    "Count requires the exact observed item contract");
        require(parse_money(L"¥136.50") == 13650 && parse_money(L"0元") == 0 && parse_money(L"-0.01") == -1,
                "Money must preserve cents, zero and debt");
        for (auto text : {L"", L"未知", L"1.001", L"1e3", L"1,000", L"NaN", L"1.2.3", L"USD 10", L"1元/月"})
            require(!parse_money(text), "Ambiguous money/unit must remain unknown");
        require(money_text(0) == L"¥0.00" && money_text(-1) == L"-¥0.01" && money_text({}) == L"未知",
                "Missing money must not be formatted as zero");
        require(parse_billing_date(L"2028-02-29").has_value() && !parse_billing_date(L"2026-02-29"),
                "Billing dates must obey calendar rules");
        require(!parse_billing_date(L"2026-12-01 24:00") && !parse_billing_date(L"2026-12-01 00:60"),
                "Invalid charge time must be rejected");
        const auto charge = parse_billing_date(L"2026-12-01 06:45:00");
        require(billing_date_text(charge) == L"2026-12-01" && billing_date_text(charge, true) == L"06:45",
                "Charge date and supplied time must both survive parsing");
        require(billing_date_text({}) == L"未知" && billing_date_text({}, true).empty(),
                "Missing charge date must not duplicate the unknown label on its time line");
        const std::chrono::year_month_day today{std::chrono::year{2026}, std::chrono::month{11}, std::chrono::day{13}};
        require(expiry_text(parse_billing_date(L"2026-12-10"), today) == L"27 天后到期" &&
                expiry_text(parse_billing_date(L"2026-11-13"), today) == L"今日到期" &&
                expiry_text(parse_billing_date(L"2026-11-12"), today) == L"已到期",
                "Remaining days must use supplied expiry and calendar dates");
        const auto complete = parse_package_response(LR"({"getNewLoginInfo":{"ballInfo":[
            {"id":"myFee","displayName":"账户余额","value":"136.50元"},
            {"displayName":"每月扣费","value":"30元"},
            {"displayName":"到期日期","value":"2026-12-10"},
            {"displayName":"下次扣费时间","value":"2026-12-01 06:45:00"},
            {"id":"myPackage","jsonValue":"{\"packageName\":\"测试套餐\"}"}
        ]}})");
        require(complete.state == PackageState::Ready && complete.balance == 13650 && complete.monthly_fee == 3000 &&
                complete.expires && complete.next_charge && complete.name == L"测试套餐", "Known label-value contract");
        const auto partial = parse_package_response(LR"({"getNewLoginInfo":{"ballInfo":[
            {"displayName":"账户余额","value":"0元"},{"displayName":"每月扣费","value":"30元"}
        ]}})");
        require(partial.state == PackageState::Partial && partial.balance == 0 && !partial.expires && !partial.next_charge,
                "Never manufacture expiry or charge date from balance/monthly fee");
        const auto generic_fee = parse_package_response(LR"({"getNewLoginInfo":{"ballInfo":[
            {"id":"myFee","displayName":"我的费用","value":"88.00"}
        ]}})");
        require(!generic_fee.balance, "The myFee ID alone must not be relabelled as balance");
        const auto school = parse_package_response(LR"({"getNewLoginInfo":{"ballInfo":[
            {"id":"packageandfee","type":"money","displayName":"套餐&余额","value":"123.45","jsonValue":"{\"packageName\":\"合成套餐\"}"},
            {"id":"flow","type":"periodtime","displayName":"到期时间","value":"1800000000","jsonValue":"{\"time\":\"11/13 12:00\"}"}
        ]}})");
        require(school.balance == 12345 && !school.expires && !school.monthly_fee && !school.next_charge,
                "Observed school balance contract; ambiguous numeric period value is not an epoch date");
        require(!parse_package_response(LR"({"getNewLoginInfo":{"ballInfo":[
            {"id":"packageandfee","type":"text","displayName":"套餐&余额","value":"123.45"}
        ]}})").balance, "Balance mapping also requires the observed money type");
        const auto detail = parse_package_detail(LR"(<html><body><table id="totalTable">
            <tr><td class="contextTitle">账户余额</td><td><div>123.45元</div></td></tr>
            <tr><td>当前套餐</td><td>合成&amp;套餐</td></tr>
            <tr><td>周期范围</td><td>2026-11-01 至 2026-12-01</td></tr>
        </table></body></html>)");
        require(detail.balance == 12345 && detail.name == L"合成&套餐" && detail.cycle_end && !detail.expires &&
                    !detail.monthly_fee && !detail.next_charge, "Observed package table; billing cycle is distinct from expiry/charge");
        require(package_expiry_text(detail, today) == L"本期剩余 18 天", "Home identifies the billing period honestly");
        require(!parse_package_detail(LR"(<body><table id="totalTable"><tr><td>周期范围</td>
                    <td>2026-12-01 至 2026-11-01</td></tr></table></body>)").cycle_end,
                "Reversed billing period cannot produce a date");
        require(parse_package_detail(L"<body><table><tr><td>账户余额</td><td>9元</td></tr></table></body>").state == PackageState::Unsupported,
                "Unrecognized HTML table cannot supply financial fields");
        const std::wstring route_prefix = LR"({"getNewLoginInfo":{"ballInfo":[{"id":"packageandfee","url":")";
        const std::wstring route_suffix = LR"("}]}})";
        const std::wstring route = L"selfserviceurl/module/scgroup/web/login_judge2.jsf?userid=fixture&password=fixture&callBack=su_business_detail&channel=su&index=1&userIp=192.0.2.1";
        require(package_detail_login_path(route_prefix + route + route_suffix).starts_with("/selfservice/module/scgroup/web/login_judge2.jsf?"),
                "Only the observed read-only login route can establish the detail session");
        for (auto bad : {L"https://elsewhere.invalid/", L"selfserviceurl/other?userid=fixture", L"selfserviceurl/module/scgroup/web/login_judge2.jsf?index=2"})
            require(package_detail_login_path(route_prefix + bad + route_suffix).empty(), "External or unknown routes must never be followed");
        require(package_detail_login_path(route_prefix + route + L"&index=2" + route_suffix).empty(), "Duplicate route parameters must be rejected");
        require(parse_package_response(L"ballInfo({\"getNewLoginInfo\":{\"ballInfo\":[]}});").state == PackageState::Unsupported,
                "Empty known JSONP is data without inventing money");
        for (auto text : {L"<html>login</html>", L"{bad}", L"{\"balance\":0}", L"evil({});", L"{}"})
            require(parse_package_response(text).state == PackageState::Unsupported, "Unknown schema must fail closed");
        require(parse_package_response(std::wstring(524289, L'x')).state == PackageState::Unsupported, "Response size bound");
        std::cout << "PASS: exact money/calendar formats, known billing envelope, missing fields, unknown schema, no inferred expiry\n";
        winrt::uninit_apartment(); return 0;
    } catch (const winrt::hresult_error& e) {
        std::cerr << "WinRT error: " << std::hex << static_cast<unsigned>(e.code()) << '\n';
        return 1;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n'; winrt::uninit_apartment(); return 1;
    }
}
