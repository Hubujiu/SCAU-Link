#include "desktop/platform.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace scau::desktop;
namespace {
void require(bool value, const char *why) { if (!value) throw std::runtime_error(why); }
LogRecord record(std::uint64_t time, LogLevel level, const wchar_t *title, const char *event) {
    return {time, level, title, {}, event};
}
}
int wmain() {
    try {
        const auto now = parse_log_time("2026-11-13T12:00:00.125Z");
        require(now && now - parse_log_time("2026-11-13T12:00:00Z") == 125, "UTC milliseconds must survive parsing");
        require(!parse_log_time("2026-19-13T12:00:00Z") && !parse_log_time("bad"), "Malformed timestamps cannot enter time filters");
        LogQuery query; query.now_ms = now;
        LogSelection newest(query, 3);
        for (unsigned i = 0; i < 700; ++i)
            newest.consider(record(now - i * 1000, LogLevel::Success, L"互联网检查通过", "internet_probe_ok"));
        auto result = newest.finish();
        require(result.entries.size() == 3 && result.matching_count == 700 && result.entries[0].timestamp_ms == now,
                "The display limit must retain globally newest records and a complete match count");
        query.order = LogOrder::Oldest;
        LogSelection oldest(query, 2);
        for (unsigned i = 0; i < 700; ++i)
            oldest.consider(record(now - i * 1000, LogLevel::Success, L"互联网检查通过", "internet_probe_ok"));
        result = oldest.finish();
        require(result.entries[0].timestamp_ms == now - 699000 && result.entries[1].timestamp_ms == now - 698000,
                "Ascending order must select old records before applying the display limit");
        query = {}; query.now_ms = now; query.level = LogLevel::Error; query.range = LogRange::Hour; query.search = L"失败";
        LogSelection combined(query);
        combined.consider(record(now - 3600000, LogLevel::Error, L"登录失败", "desktop_authentication_error"));
        combined.consider(record(now - 3600001, LogLevel::Error, L"登录失败", "desktop_authentication_error"));
        combined.consider(record(now - 1000, LogLevel::Success, L"连接成功", "worker_authenticated"));
        combined.consider(record(now - 1000, LogLevel::Error, L"认证核心异常退出", "worker_crashed"));
        result = combined.finish();
        require(result.entries.size() == 1 && result.total_count == 4, "Status, time boundary and search must combine with AND semantics");
        query = {}; query.now_ms = now; query.search = L"INTERNET_PROBE";
        LogSelection insensitive(query);
        insensitive.consider(record(now, LogLevel::Warning, L"互联网检查未通过", "internet_probe_failed"));
        require(insensitive.finish().entries.size() == 1, "Safe event-name search must ignore ASCII case");
        query = {}; query.now_ms = now; query.order = LogOrder::ErrorsFirst;
        LogSelection priorities(query);
        priorities.consider(record(now, LogLevel::Success, L"连接成功", "worker_authenticated"));
        priorities.consider(record(now - 2000, LogLevel::Error, L"登录失败", "desktop_authentication_error"));
        priorities.consider(record(now - 1000, LogLevel::Warning, L"互联网检查未通过", "internet_probe_failed"));
        result = priorities.finish();
        require(result.entries[0].level == LogLevel::Error && result.entries[1].level == LogLevel::Warning,
                "Errors-first must prioritize severity over timestamp");
        query = {}; query.now_ms = now; query.range = LogRange::Today;
        LogSelection today(query);
        today.consider(record(now, LogLevel::Info, L"开始登录", "account_attempt"));
        today.consider(record(now - 86400000, LogLevel::Info, L"开始登录", "account_attempt"));
        require(today.finish().entries.size() == 1, "Today must use the local calendar boundary");

        wchar_t temp[MAX_PATH]{}; GetTempPathW(MAX_PATH, temp);
        const auto folder = std::filesystem::path(temp) / (L"scau-log-query-" + std::to_wstring(GetCurrentProcessId()));
        std::filesystem::create_directories(folder);
        struct Cleanup { std::filesystem::path path; ~Cleanup() {
            std::error_code error;
            for (int i = 0; i < 5; ++i) std::filesystem::remove(path / (L"session-" + std::to_wstring(i) + L".jsonl"), error);
            std::filesystem::remove(path, error);
        }} cleanup{folder};
        for (int i = 0; i < 5; ++i) {
            std::ofstream file(folder / (L"session-" + std::to_wstring(i) + L".jsonl"));
            file << "{\"time\":\"2026-11-13T11:59:00Z\",\"event\":\""
                 << (i == 0 ? "internet_probe_failed" : "internet_probe_ok")
                 << "\",\"password\":\"MUST-NOT-RENDER\",\"detail\":\"MUST-NOT-RENDER\"}\n";
            file << "{\"time\":\"2026-11-13T11:59:01Z\",\"event\":\"unknown\",\"detail\":\"MUST-NOT-RENDER\"}\n";
        }
        query = {}; query.now_ms = now; query.level = LogLevel::Warning;
        result = read_log_records(folder, query, 1);
        require(result.total_count == 5 && result.matching_count == 1 && result.entries.size() == 1,
                "Filters must search beyond the newest three files and run before limiting");
        require(result.entries[0].title == L"互联网检查未通过" && result.entries[0].event == "internet_probe_failed",
                "Event classification cannot depend on a translated failure substring");
        require(result.entries[0].title.find(L"MUST-NOT-RENDER") == std::wstring::npos,
                "Raw diagnostic payloads must never be displayed or searched");
        std::cout << "PASS: structured log filters, local date, ordering, bounded selection and private-payload exclusion\n";
        return 0;
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
