#pragma once
#include "package_query.hpp"

namespace scau::desktop {
// Site cooldown advances only after a real request, never after a cache hit.
class PackageCooldown {
    std::uint64_t network_until_ = 0, tls_until_ = 0;
    PackageState tls_failure_ = PackageState::TlsError;
public:
    std::optional<PackageState> failure(std::uint64_t now) const {
        if (now < tls_until_) return tls_failure_;
        if (now < network_until_) return PackageState::NetworkError;
        return {};
    }
    void record(PackageState state, std::uint64_t now) {
        if (state == PackageState::CertificateError || state == PackageState::TlsError) {
            tls_failure_ = state; tls_until_ = now + 300000;
        } else if (state == PackageState::NetworkError) network_until_ = now + 5000;
    }
    void reset() { network_until_ = tls_until_ = 0; }
};
} // namespace scau::desktop
