#include "logs.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <windows.h>

namespace scau::desktop {
namespace {
constexpr std::uint64_t epoch_ms = 11644473600000ULL;
std::wstring folded(std::wstring value) {
    if (!value.empty())
        CharLowerBuffW(value.data(), DWORD(value.size()));
    return value;
}
std::uint64_t system_ms(const SYSTEMTIME &value) {
    FILETIME file{};
    if (!SystemTimeToFileTime(&value, &file))
        return 0;
    const ULARGE_INTEGER number{{file.dwLowDateTime, file.dwHighDateTime}};
    return number.QuadPart / 10000 >= epoch_ms ? number.QuadPart / 10000 - epoch_ms : 0;
}
SYSTEMTIME utc_system(std::uint64_t milliseconds) {
    ULARGE_INTEGER number{};
    number.QuadPart = (milliseconds + epoch_ms) * 10000;
    FILETIME file{number.LowPart, number.HighPart};
    SYSTEMTIME value{};
    FileTimeToSystemTime(&file, &value);
    return value;
}
int priority(LogLevel level) {
    return level == LogLevel::Error ? 0 : level == LogLevel::Warning ? 1
                                    : level == LogLevel::Success ? 2 : 3;
}
} // namespace
std::uint64_t log_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}
std::uint64_t parse_log_time(std::string_view text) {
    if (text.size() < 20 || text.size() > 40 || text.back() != 'Z')
        return 0;
    const std::string value(text);
    SYSTEMTIME utc{};
    if (sscanf_s(value.c_str(), "%hu-%hu-%huT%hu:%hu:%hu", &utc.wYear, &utc.wMonth, &utc.wDay,
                 &utc.wHour, &utc.wMinute, &utc.wSecond) != 6)
        return 0;
    if (value[19] == '.') {
        unsigned fraction = 0;
        std::size_t digits = 0;
        for (std::size_t i = 20; i + 1 < value.size(); ++i) {
            if (value[i] < '0' || value[i] > '9')
                return 0;
            if (digits < 3)
                fraction = fraction * 10 + unsigned(value[i] - '0');
            ++digits;
        }
        if (!digits)
            return 0;
        for (; digits < 3; ++digits)
            fraction *= 10;
        utc.wMilliseconds = WORD(fraction);
    } else if (value.size() != 20)
        return 0;
    return system_ms(utc);
}
std::wstring format_log_time(std::uint64_t milliseconds) {
    auto utc = utc_system(milliseconds);
    SYSTEMTIME local{};
    if (!SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local))
        local = utc;
    wchar_t label[32]{};
    swprintf_s(label, L"%04u-%02u-%02u %02u:%02u:%02u", local.wYear, local.wMonth, local.wDay,
               local.wHour, local.wMinute, local.wSecond);
    return label;
}
const wchar_t *log_level_label(LogLevel level) {
    switch (level) {
    case LogLevel::Success: return L"成功";
    case LogLevel::Warning: return L"提醒";
    case LogLevel::Error: return L"失败";
    case LogLevel::Info: return L"其他";
    default: return L"全部状态";
    }
}
LogSelection::LogSelection(LogQuery query, std::size_t limit)
    : query_(std::move(query)), search_(folded(query_.search)), limit_(std::clamp(limit, std::size_t(1), std::size_t(2000))) {
    if (!query_.now_ms)
        query_.now_ms = log_now_ms();
    const auto period = query_.range == LogRange::Hour ? 3600000ULL
                        : query_.range == LogRange::Day ? 86400000ULL
                        : query_.range == LogRange::Week ? 604800000ULL : 0ULL;
    since_ = query_.now_ms > period ? query_.now_ms - period : 0;
    if (query_.range == LogRange::All)
        since_ = 0;
    if (query_.range == LogRange::Today) {
        auto utc = utc_system(query_.now_ms);
        SYSTEMTIME local{}, midnight{};
        if (SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local)) {
            local.wHour = local.wMinute = local.wSecond = local.wMilliseconds = 0;
            if (TzSpecificLocalTimeToSystemTime(nullptr, &local, &midnight))
                since_ = system_ms(midnight);
        }
    }
    heap_.reserve(limit_);
}
bool LogSelection::before(const LogRecord &a, const LogRecord &b) const {
    if (query_.order == LogOrder::ErrorsFirst && a.level != b.level)
        return priority(a.level) < priority(b.level);
    if (a.timestamp_ms != b.timestamp_ms)
        return query_.order == LogOrder::Oldest ? a.timestamp_ms < b.timestamp_ms
                                               : a.timestamp_ms > b.timestamp_ms;
    return a.sequence < b.sequence;
}
void LogSelection::consider(LogRecord record) {
    record.sequence = ++total_;
    if (query_.level != LogLevel::All && record.level != query_.level)
        return;
    if (record.timestamp_ms < since_ || (query_.range != LogRange::All && record.timestamp_ms > query_.now_ms))
        return;
    if (!search_.empty() && folded(record.title).find(search_) == std::wstring::npos &&
        folded(std::wstring(record.event.begin(), record.event.end())).find(search_) == std::wstring::npos)
        return;
    ++matching_;
    auto compare = [this](const auto &a, const auto &b) { return before(a, b); };
    if (heap_.size() < limit_) {
        heap_.push_back(std::move(record));
        std::push_heap(heap_.begin(), heap_.end(), compare);
    } else if (before(record, heap_.front())) {
        std::pop_heap(heap_.begin(), heap_.end(), compare);
        heap_.back() = std::move(record);
        std::push_heap(heap_.begin(), heap_.end(), compare);
    }
}
LogResult LogSelection::finish() {
    std::sort(heap_.begin(), heap_.end(), [this](const auto &a, const auto &b) { return before(a, b); });
    for (auto &record : heap_)
        record.time_label = format_log_time(record.timestamp_ms);
    return {std::move(heap_), matching_, total_};
}
} // namespace scau::desktop
