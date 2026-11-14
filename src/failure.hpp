#pragma once
#include "protocol.hpp"
#include <algorithm>
#include <string>
#include <string_view>

namespace scau {
enum class FailureReason { empty, present, unrecognized, malformed };

// Inspect only the declared EAP body. Unknown/malformed extensions stop
// automatic credential retries; they are not labelled as a password error.
inline FailureReason failure_reason(std::span<const Byte> eap) {
    if(eap.size()<4 || eap[0]!=4)return FailureReason::malformed;
    const auto length=(std::size_t(eap[2])<<8)|eap[3];
    if(length<4 || length>eap.size())return FailureReason::malformed;
    const auto extension=eap.subspan(4,length-4);
    if(extension.empty())return FailureReason::empty;
    constexpr std::array<Byte,4> vendor{0,0,0x13,0x11};
    if(extension.size()<4 || !std::equal(vendor.begin(),vendor.end(),extension.begin()))return FailureReason::unrecognized;
    if(extension.size()<6)return FailureReason::malformed;
    const auto text_length=(std::size_t(extension[4])<<8)|extension[5];
    if(text_length>extension.size()-6)return FailureReason::malformed;
    return text_length?FailureReason::present:FailureReason::empty;
}

// UTF-8 for the local UI/private IPC only; never send raw server text to logs.
// The supplied credential strings use the same GBK encoding as authentication.
// Missing, malformed, binary or undecodable reasons become "unknown".
inline constexpr std::size_t failure_message_limit = 768;
std::string failure_message(std::span<const Byte> eap, std::string_view username = {},
                            std::string_view password = {});
}
