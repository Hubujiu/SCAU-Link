#include "package_query.hpp"
#include <cwctype>
#include <set>
#include <utility>

namespace scau::desktop {
namespace {
std::wstring trim(std::wstring_view text) {
    while (!text.empty() && std::iswspace(text.front())) text.remove_prefix(1);
    while (!text.empty() && std::iswspace(text.back())) text.remove_suffix(1);
    return std::wstring(text);
}
std::wstring lower_ascii(std::wstring_view text) {
    std::wstring out(text);
    for (auto& ch : out) if (ch >= L'A' && ch <= L'Z') ch += L'a' - L'A';
    return out;
}
// Extract only bounded text from known table cells. No script/DOM execution,
// image loading, URL following, or interpretation of free-form descriptions.
std::wstring cell_text(std::wstring_view text) {
    std::wstring out;
    for (std::size_t p = 0; p < text.size();) {
        if (text.substr(p).starts_with(L"<!--")) {
            const auto end = text.find(L"-->", p + 4);
            if (end == text.npos) return {};
            p = end + 3; continue;
        }
        if (text[p] == L'<') {
            const auto end = text.find(L'>', p + 1);
            if (end == text.npos) return {};
            const auto tag = lower_ascii(text.substr(p, end - p + 1));
            if (tag.starts_with(L"<script") || tag.starts_with(L"<style")) return {};
            p = end + 1; continue;
        }
        if (text[p] == L'&') {
            bool found = false;
            for (const auto& [entity, ch] : {std::pair{L"&nbsp;", L' '}, {L"&#160;", L' '},
                    {L"&amp;", L'&'}, {L"&lt;", L'<'}, {L"&gt;", L'>'}, {L"&quot;", L'"'}, {L"&#39;", L'\''}}) {
                const std::wstring_view token(entity);
                if (text.substr(p).starts_with(token)) { out += ch; p += token.size(); found = true; break; }
            }
            if (found) continue;
            return {};
        }
        out += text[p++];
        if (out.size() > 1024) return {};
    }
    return trim(out);
}
std::optional<std::chrono::sys_days> billing_day(const std::optional<BillingDate>& date) {
    if (!date || date->year < 1970 || date->year > 2199 || date->month < 1 || date->month > 12 ||
        date->day < 1 || date->day > 31) return {};
    const std::chrono::year_month_day value{std::chrono::year(date->year),
        std::chrono::month(unsigned(date->month)), std::chrono::day(unsigned(date->day))};
    if (!value.ok()) return {};
    return std::chrono::sys_days(value);
}
std::optional<std::pair<std::chrono::sys_days, std::chrono::sys_days>> current_cycle(
    const PackageInfo& info, std::chrono::year_month_day today) {
    const auto start = billing_day(info.cycle_start), end = billing_day(info.cycle_end);
    if (!today.ok() || !start || !end || info.cycle_start->seconds || info.cycle_end->seconds ||
        *start > std::chrono::sys_days(today) || *end < std::chrono::sys_days(today)) return {};
    return std::pair{*start, *end};
}
std::optional<std::chrono::sys_days> add_months(std::chrono::sys_days anchor, std::int64_t count) {
    const std::chrono::year_month_day date{anchor};
    const auto available = (2199 - int(date.year())) * 12 + 12 - int(unsigned(date.month()));
    if (count < 0 || count > available) return {};
    const auto month = date.year() / date.month() + std::chrono::months{int(count)};
    const auto target = month / date.day();
    // Clamp a month-end anniversary once, preserving the original anchor day.
    return std::chrono::sys_days(target.ok() ? target : std::chrono::year_month_day{month / std::chrono::last});
}
std::optional<BillingDate> forecast_date(std::chrono::sys_days day) {
    const std::chrono::year_month_day date{day};
    if (!date.ok() || int(date.year()) < 1970 || int(date.year()) > 2199) return {};
    return BillingDate{int(date.year()), int(unsigned(date.month())), int(unsigned(date.day())), {}};
}
} // namespace

PackageInfo parse_package_detail(std::wstring_view html) {
    PackageInfo info; info.state = PackageState::Unsupported;
    if (html.empty() || html.size() > 524288) return info;
    const auto lower = lower_ascii(html);
    const auto body = lower.find(L"<body");
    if (body == lower.npos) return info;
    std::size_t table = body, head_end = 0;
    for (;;) {
        table = lower.find(L"<table", table);
        if (table == lower.npos) return info;
        head_end = lower.find(L'>', table);
        if (head_end == lower.npos) return info;
        const auto header = std::wstring_view(lower).substr(table, head_end - table);
        if (header.find(L"id=\"totaltable\"") != header.npos || header.find(L"id='totaltable'") != header.npos) break;
        table = head_end + 1;
    }
    const auto table_end = lower.find(L"</table>", head_end);
    if (table_end == lower.npos) return info;
    std::set<std::wstring> seen;
    std::wstring policy;
    for (auto row = head_end; (row = lower.find(L"<tr", row)) < table_end;) {
        const auto row_end = lower.find(L"</tr>", row);
        if (row_end == lower.npos || row_end > table_end) break;
        std::wstring cells[2];
        auto p = row;
        for (auto& cell : cells) {
            const auto open = lower.find(L"<td", p), start = lower.find(L'>', open), end = lower.find(L"</td>", start);
            if (open == lower.npos || start == lower.npos || end == lower.npos || end > row_end) break;
            cell = cell_text(html.substr(start + 1, end - start - 1)); p = end + 5;
        }
        const auto& label = cells[0]; const auto& value = cells[1];
        const bool recognized = label == L"账户余额" || label == L"余额" || label == L"当前套餐" ||
            label == L"每月扣费" || label == L"月费" || label == L"下次扣费时间" || label == L"到期时间" ||
            label == L"周期范围" || label == L"周期时间范围" || label == L"计费策略" || label == L"用户状态";
        if (recognized && !seen.insert(label == L"余额" ? L"账户余额" :
                label == L"周期时间范围" ? L"周期范围" : label).second) return PackageInfo{PackageState::Unsupported};
        if (label == L"账户余额" || label == L"余额") info.balance = parse_money(value);
        else if (label == L"当前套餐" && value.size() <= 80) info.name = value;
        else if (label == L"计费策略") policy = value;
        else if (label == L"用户状态") info.service_normal = value == L"正常";
        else if (label == L"每月扣费" || label == L"月费") info.monthly_fee = parse_money(value);
        else if (label == L"下次扣费时间") info.next_charge = parse_billing_date(value);
        else if (label == L"到期时间") info.expires = parse_billing_date(value);
        else if (label == L"周期范围" || label == L"周期时间范围") {
            const auto separator = value.find(L'至');
            if (separator != value.npos) {
                const auto from = parse_billing_date(std::wstring_view(value).substr(0, separator));
                const auto to = parse_billing_date(std::wstring_view(value).substr(separator + 1));
                auto day = [](const BillingDate& d) { return std::chrono::sys_days(std::chrono::year(d.year) /
                                                         std::chrono::month(unsigned(d.month)) / unsigned(d.day)); };
                if (from && to && !from->seconds && !to->seconds && day(*from) <= day(*to)) {
                    info.cycle_start = from; info.cycle_end = to;
                }
            }
        }
        row = row_end + 5;
    }
    // Observed consume.jsf contract: a dedicated 计费策略 cell, e.g.
    // 周期31天20元, independently corroborated by the inclusive cycle range.
    // Do not parse the package's arbitrary name, generic 消费 or free-form text.
    if (policy.starts_with(L"周期") && policy.ends_with(L"元") && info.cycle_start && info.cycle_end) {
        const auto separator = policy.find(L'天', 2);
        if (separator != policy.npos) {
            const auto days = parse_device_count(std::wstring_view(policy).substr(2, separator - 2));
            const auto fee = parse_money(std::wstring_view(policy).substr(separator + 1));
            const auto& from = *info.cycle_start; const auto& to = *info.cycle_end;
            const auto start = std::chrono::sys_days(std::chrono::year(from.year) / unsigned(from.month) / unsigned(from.day));
            const auto end = std::chrono::sys_days(std::chrono::year(to.year) / unsigned(to.month) / unsigned(to.day));
            if (days && *days >= 1 && *days <= 366 && fee && *fee >= 0 && (end - start).count() + 1 == std::int64_t(*days)) {
                info.cycle_days = days; info.cycle_fee = fee;
            }
        }
    }
    if (info.balance || !info.name.empty() || info.expires || info.cycle_end)
        info.state = info.balance && package_fee(info) ? PackageState::Ready : PackageState::Partial;
    return info;
}

std::wstring package_fee_label(const PackageInfo& info) {
    return !info.monthly_fee && info.cycle_fee && info.cycle_days
        ? L"每 " + std::to_wstring(*info.cycle_days) + L" 天扣费" : L"每月扣费";
}
std::optional<std::int64_t> package_fee(const PackageInfo& info) {
    return info.monthly_fee ? info.monthly_fee : info.cycle_fee;
}
std::optional<BillingDate> estimate_next_charge(const PackageInfo& info, std::chrono::year_month_day today) {
    const auto cycle = current_cycle(info, today);
    if (!today.ok() || info.monthly_fee || info.service_normal != true || !info.balance || !info.cycle_fee || !info.cycle_days ||
        !cycle || *info.cycle_fee < 0 || *info.balance < *info.cycle_fee || *info.cycle_days < 1 || *info.cycle_days > 366 ||
        (cycle->second - cycle->first).count() + 1 != std::int64_t(*info.cycle_days)) return {};
    return forecast_date(cycle->second + std::chrono::days(1));
}
std::optional<BillingDate> estimate_package_expiry(const PackageInfo& info, std::chrono::year_month_day today) {
    if (!today.ok() || int(today.year()) < 1970 || int(today.year()) > 2199 || info.expires ||
        !info.balance || *info.balance < 0 || info.service_normal == false) return {};
    const auto fee = package_fee(info);
    if (!fee || *fee <= 0) return {}; // A free plan has no finite balance-based expiry.
    const auto periods = *info.balance / *fee; // Unspent change cannot buy a fraction of a billing period.
    const auto cycle = current_cycle(info, today);
    if (info.monthly_fee) {
        auto anchor = std::chrono::sys_days(today);
        bool paid_period = false;
        if (info.next_charge) {
            const auto next = billing_day(info.next_charge);
            if (!next || *next < anchor) return {};
            anchor = *next;
            paid_period = true;
        } else if (cycle) {
            anchor = cycle->second + std::chrono::days(1);
            paid_period = true;
        } else if (info.cycle_start || info.cycle_end) return {};
        if (!periods && paid_period) return forecast_date(anchor - std::chrono::days(1));
        const auto next_unfunded = add_months(anchor, periods);
        if (!next_unfunded) return {};
        return forecast_date(*next_unfunded - std::chrono::days(paid_period ? 1 : 0));
    }
    if (info.service_normal != true || !cycle || !info.cycle_days || *info.cycle_days < 1 || *info.cycle_days > 366 ||
        (cycle->second - cycle->first).count() + 1 != std::int64_t(*info.cycle_days)) return {};
    const auto last = std::chrono::sys_days(std::chrono::year{2199} / 12 / 31);
    if (periods > (last - cycle->second).count() / *info.cycle_days) return {};
    return forecast_date(cycle->second + std::chrono::days(periods * *info.cycle_days));
}
} // namespace scau::desktop
