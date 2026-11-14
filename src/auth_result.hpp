#pragma once

namespace scau {
// Explicit worker outcomes. Only a completed, failed authentication may
// advance the desktop account rotation. Infrastructure and server logout
// must never be treated as another account's chance to authenticate.
inline constexpr int auth_rejected = 1;
inline constexpr int auth_environment_error = 4;
inline constexpr int auth_server_terminated = 5;
inline constexpr int auth_protocol_unsupported = 6;
inline constexpr bool allows_account_retry(int result) noexcept { return result == auth_rejected; }
} // namespace scau
