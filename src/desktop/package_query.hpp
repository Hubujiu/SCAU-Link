#pragma once
#include "platform.hpp"
#include "school_https.hpp"
#include "connection_setup.hpp"
#include <chrono>
#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>

namespace scau::desktop {
enum class PackageState { Idle, Loading, Ready, Partial, CertificateError, NetworkError, AuthError, Unsupported, TlsError,
                          MissingPortalCredential };
enum class PackageSummaryResult {
    NotInspected, Empty, DecodeError, Html, InvalidJson, MissingEnvelope,
    InvalidEnvelope, MissingItems, InvalidItems, EmptyItems, TooManyItems,
    UnrecognizedItems, Parsed, TooLarge, InvalidHttp, LegacyRejected
};
struct PackageDiagnostics;
struct BillingDate {
    int year{}, month{}, day{};
    std::optional<int> seconds;
};
struct PackageInfo {
    PackageState state = PackageState::Idle;
    std::optional<std::int64_t> balance, monthly_fee; // CNY minor units; missing is never zero.
    std::optional<BillingDate> expires, next_charge, cycle_end;
    std::optional<BillingDate> cycle_start;
    std::optional<std::int64_t> cycle_fee;
    std::optional<unsigned> cycle_days;
    std::optional<bool> service_normal; // Unknown is distinct from an explicitly paused/abnormal service.
    std::optional<unsigned> online_devices;
    std::optional<unsigned> query_rejection_code; // Bounded legacy error code; never server text.
    std::wstring name;
};
std::optional<std::int64_t> parse_money(std::wstring_view text);
std::optional<unsigned> parse_device_count(std::wstring_view text);
std::wstring device_count_text(const std::optional<unsigned>& count);
std::optional<BillingDate> parse_billing_date(std::wstring_view text);
std::wstring money_text(const std::optional<std::int64_t>& amount);
std::wstring billing_date_text(const std::optional<BillingDate>& date, bool time = false);
std::wstring expiry_text(const std::optional<BillingDate>& date, std::chrono::year_month_day today);
std::wstring package_expiry_text(const PackageInfo& info, std::chrono::year_month_day today);
std::wstring package_fee_label(const PackageInfo& info);
std::optional<std::int64_t> package_fee(const PackageInfo& info);
// An estimate from a corroborated, normal, funded, current fixed-day cycle.
// Kept separate from the server's authoritative next_charge; never supplies a time.
std::optional<BillingDate> estimate_next_charge(const PackageInfo& info, std::chrono::year_month_day today);
// Balance funds complete future billing periods, after any current paid period.
// Calendar-month plans without a billing anchor use today as an approximate base.
// This display-only forecast never overwrites the server's expires field.
std::optional<BillingDate> estimate_package_expiry(const PackageInfo& info, std::chrono::year_month_day today);
std::wstring package_status_text(PackageState state);
std::wstring package_status_text(const PackageInfo& info);
// Only the observed legacy envelope/label-value items are mapped. No guessed
// API fields; server dates remain separate from display-only forecasts.
PackageInfo parse_package_response(std::wstring_view json, PackageDiagnostics* diagnostics = nullptr);
PackageInfo parse_package_detail(std::wstring_view html);
// Private, credential-bearing route from the known server item. The caller
// must wipe it; never put it in UI state, persistence, diagnostics or logs.
std::string package_detail_login_path(std::wstring_view json);
std::optional<std::size_t> choose_package_adapter(std::span<const ConnectionAdapter> adapters,
    const std::array<unsigned char, 6>& mac = {}, unsigned interface_index = 0);
std::string account_query_path(const Credential& credential, const std::array<unsigned char, 6>& mac,
    std::wstring_view source_ipv4 = {});
enum class PackageStage { Interface, Encoding, Summary, DetailRoute, DetailLogin, Overview, Billing, Complete };
struct PackageDiagnostics {
    PackageStage stage = PackageStage::Interface;
    unsigned interface_index = 0;
    unsigned long transport_error{}, http_status{}, tls_library_error{}, detail_http_status{};
    unsigned long response_bytes{};
    detail::TransportState transport_state = detail::TransportState::NetworkError;
    bool http_complete = false;
    PackageSummaryResult summary_result = PackageSummaryResult::NotInspected;
    unsigned summary_items{};
    std::optional<unsigned> legacy_error_code;
    bool detail_route_available = false;
    bool tls_connected = false, legacy_tls_used = false;
    std::string content_type;
    bool certificate_checks_disabled = false;
    bool detail_requested = false;
    unsigned long detail_login_status{};
    bool detail_session_available = false, detail_redirect_recognized = false;
    bool billing_requested = false, billing_detail_matched = false;
    unsigned long billing_http_status{};
};
using PackageSender = std::function<detail::HttpsResult(std::string_view, std::string_view, std::string_view,
    detail::TlsDiagnostics*, const std::atomic_bool*, std::string_view)>;
PackageInfo query_package(const Credential& credential, const std::array<unsigned char, 6>& mac,
                          PackageDiagnostics* diagnostics = nullptr, std::string* private_response = nullptr,
                          const std::atomic_bool* cancel = nullptr, PackageSender sender = {}, unsigned interface_index = 0);
} // namespace scau::desktop
