#pragma once
#include "package_query.hpp"
#include "school_https.hpp"
#include <functional>

namespace scau::desktop {
enum class CampusState { Unknown, Normal, Paused };
enum class CampusAction { Pause, Resume };
enum class CampusError { None, Network, Tls, Auth, Data, Stale, Permission };
enum class CampusOutcome { None, Success, Rejected, Unknown, Expired };
struct CampusView {
    CampusState state = CampusState::Unknown;
    CampusError error = CampusError::None;
    bool can_pause = false, can_resume = false;
    std::optional<unsigned> online_devices;
};
struct CampusResult {
    CampusOutcome outcome = CampusOutcome::None;
    CampusView view;
    bool request_sent = false;
};
std::wstring campus_state_text(CampusState state);
std::wstring campus_error_text(CampusError error);
// Injectable only for offline fixtures. Production always uses the fixed
// school TLS origin; this interface never accepts browser cookies.
using CampusSender = std::function<detail::HttpsResult(std::string_view, std::string_view, std::string_view,
                                                       std::string_view, const std::atomic_bool*)>;
class CampusSession {
    CampusSender sender_;
    std::function<std::uint64_t()> clock_;
    std::string cookie_;
    std::wstring expected_user_, target_user_;
    CampusView view_;
    bool prepared_ = false;
    std::uint64_t valid_until_ = 0;
    unsigned stage_ = 0;
    std::wstring read(std::string_view method, std::string_view path, std::string_view body,
                      const std::atomic_bool* cancel);
    void load_view(const std::atomic_bool* cancel);
    void erase() noexcept;
  public:
    explicit CampusSession(CampusSender sender = {}, std::function<std::uint64_t()> clock = {});
    ~CampusSession();
    CampusSession(const CampusSession&) = delete;
    CampusSession& operator=(const CampusSession&) = delete;
    CampusView prepare(const Credential& credential, const std::array<unsigned char, 6>& mac,
                       const std::atomic_bool* cancel = nullptr);
    CampusView refresh(const std::atomic_bool* cancel = nullptr);
    CampusResult apply(CampusAction action, const std::atomic_bool* cancel = nullptr,
                       std::function<bool()> may_commit = {});
    bool prepared() const noexcept { return prepared_; }
    const CampusView& view() const noexcept { return view_; }
    unsigned diagnostic_stage() const noexcept { return stage_; }
};
} // namespace scau::desktop
