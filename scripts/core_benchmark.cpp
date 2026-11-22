#include "protocol.hpp"
#include "recovery.hpp"
#include <chrono>
#include <iostream>
#include <string_view>

bool has_action(const auto& result) {
    if constexpr (requires { result.has_value(); }) return result.has_value();
    else return !result.empty();
}

int main(int argc, char** argv) {
    using namespace scau;
    using Clock = std::chrono::steady_clock;
    constexpr std::size_t iterations = 1'000'000;
    std::uint64_t checksum = 0;
    if (argc != 2) return 2;
    const std::string_view mode = argv[1];
    const auto begin = Clock::now();
    if (mode == "parse") {
        Bytes packet{1, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2,
                     0x81, 0, 0, 1, 0x88, 0x8e, 1, 0, 0, 6, 1, 0, 0, 6, 4, 0};
        for (std::size_t i = 0; i < iterations; ++i) {
            packet[23] = static_cast<Byte>(i);
            const auto frame = parse_frame(packet);
            checksum += frame.identifier + frame.method + frame.eap.size();
        }
    } else if (mode == "recovery") {
        RecoveryController recovery;
        recovery.start(0, true);
        for (std::size_t i = 0; i < iterations; ++i) {
            const auto now = i * 4000;
            recovery.request(now + 1, false);
            recovery.request(now + 2, true);
            checksum += has_action(recovery.success(now + 3, 3000));
            recovery.tick(now + 4, 0);
            checksum += has_action(recovery.tick(now + 3003, 0));
        }
        checksum += recovery.successful_exchanges() + recovery.exchange_generation();
    } else {
        return 2;
    }
    const auto elapsed = std::chrono::duration<double, std::nano>(Clock::now() - begin).count();
    std::cout << "{\"nsPerIteration\":" << elapsed / iterations << ",\"checksum\":" << checksum << "}\n";
}
