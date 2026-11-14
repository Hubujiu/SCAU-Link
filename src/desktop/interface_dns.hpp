#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace scau::desktop {
std::vector<std::string> resolve_interface_ipv4(std::string_view host, unsigned index,
    std::chrono::milliseconds timeout, const std::atomic_bool* cancel = nullptr);
bool bind_interface_ipv4_socket(std::uintptr_t socket, unsigned index);
}

