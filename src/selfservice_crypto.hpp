#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace scau {

inline constexpr std::size_t selfservice_query_max_utf8_bytes = 240;

// Reproduce the original client's login_judge2.jsf `s` value: Unicode -> UTF-8,
// zero-pad to 16 bytes, MD5("hust" || previous ciphertext) XOR each block,
// with sixteen ASCII '1' bytes as the initial chain, then lowercase hex.
// Already aligned/empty input gains no block. The original helper admits at
// most 240 padded bytes; longer input, embedded NUL and invalid UTF-16 throw.
// The caller owns the input and returned credential-equivalent value and must
// keep both out of logs and clear them when the request has finished.
std::string selfservice_encode_query(std::wstring_view query);

} // namespace scau
