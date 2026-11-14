#pragma once
#include "wireless_connection.hpp"
#include "interface_dns.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace scau::desktop {
class CampusWifi {
  public:
    virtual ~CampusWifi() = default;
    // Connects only SCAUNET. A later external network switch cancels ownership.
    virtual bool connect(const std::atomic_bool* cancel, std::string& reason) = 0;
    virtual unsigned interface_index() const noexcept = 0;
};
std::unique_ptr<CampusWifi> make_scau_web_wifi();
} // namespace scau::desktop
