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
    if (info.balance || !info.name.empty() || info.expires || info.cycle_end) info.state = PackageState::Partial;
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
    if (!today.ok() || info.monthly_fee || !info.service_normal || !info.balance || !info.cycle_fee || !info.cycle_days ||
        !info.cycle_start || !info.cycle_end || *info.cycle_fee < 0 || *info.balance < *info.cycle_fee) return {};
    const auto& from = *info.cycle_start; const auto& to = *info.cycle_end;
    const std::chrono::year_month_day start{std::chrono::year(from.year), std::chrono::month(unsigned(from.month)),
                                           std::chrono::day(unsigned(from.day))};
    const std::chrono::year_month_day end{std::chrono::year(to.year), std::chrono::month(unsigned(to.month)),
                                         std::chrono::day(unsigned(to.day))};
    if (!start.ok() || !end.ok() || from.seconds || to.seconds || *info.cycle_days < 1 || *info.cycle_days > 366 ||
        (std::chrono::sys_days(end) - std::chrono::sys_days(start)).count() + 1 != std::int64_t(*info.cycle_days) ||
        std::chrono::sys_days(today) < std::chrono::sys_days(start) || std::chrono::sys_days(today) > std::chrono::sys_days(end)) return {};
    const std::chrono::year_month_day next{std::chrono::sys_days(end) + std::chrono::days(1)};
    if (!next.ok() || int(next.year()) > 2199) return {};
    return BillingDate{int(next.year()), int(unsigned(next.month())), int(unsigned(next.day())), {}};
}
} // namespace scau::desktop
