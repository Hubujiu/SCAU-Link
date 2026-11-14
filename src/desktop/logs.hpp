#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace scau::desktop {
enum class LogLevel { All, Success, Warning, Error, Info };
enum class LogRange { All, Hour, Day, Today, Week };
enum class LogOrder { Newest, Oldest, ErrorsFirst };
struct LogRecord {
    std::uint64_t timestamp_ms{};
    LogLevel level = LogLevel::Info;
    std::wstring title, time_label;
    std::string event;
    std::uint64_t sequence{};
};
struct LogQuery {
    LogLevel level = LogLevel::All;
    LogRange range = LogRange::All;
    LogOrder order = LogOrder::Newest;
    std::wstring search;
    std::uint64_t now_ms{};
};
struct LogResult {
    std::vector<LogRecord> entries;
    std::size_t matching_count{}, total_count{};
};

// Filtering precedes the display limit. The heap keeps only the best matches,
// so old files remain searchable without retaining all history in memory.
class LogSelection {
    LogQuery query_;
    std::wstring search_;
    std::uint64_t since_{};
    std::size_t limit_, matching_{}, total_{};
    std::vector<LogRecord> heap_;
    bool before(const LogRecord &, const LogRecord &) const;

  public:
    explicit LogSelection(LogQuery query, std::size_t limit = 500);
    void consider(LogRecord record);
    LogResult finish();
};
std::uint64_t log_now_ms();
std::uint64_t parse_log_time(std::string_view utc);
std::wstring format_log_time(std::uint64_t utc_ms);
const wchar_t *log_level_label(LogLevel level);
LogResult read_log_records(const std::filesystem::path &, const LogQuery &, std::size_t limit = 500);
} // namespace scau::desktop
