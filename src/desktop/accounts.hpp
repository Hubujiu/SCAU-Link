#pragma once
#include "platform.hpp"
#include <optional>
#include <string>
#include <vector>

namespace scau::desktop {
struct AccountInfo {
    std::string id, secret_id;
    std::wstring username;
    std::string portal_secret_id;
};
struct AccountCatalog {
    std::vector<AccountInfo> entries;
    const AccountInfo *find(std::string_view id) const noexcept;
    const AccountInfo *first_account() const noexcept;
};
inline constexpr std::size_t maximum_accounts = 32;
std::string new_account_id();
void reorder_accounts(AccountCatalog &catalog, const std::vector<std::string> &order);
void pin_account(AccountCatalog &catalog, std::string_view id);
void remove_account_entry(AccountCatalog &catalog, std::string_view id);
void validate_account_edit(const AccountCatalog &catalog, std::string_view id, const Credential &value);

// The disk catalog stores opaque identifiers and list order only.
// Each password version is an immutable Windows credential. Catalog replace
// commits before the old secret can be removed, so a failed save is recoverable.
class AccountStore {
    std::filesystem::path directory_;
    std::wstring prefix_, legacy_;
    std::wstring target(std::string_view secret) const;
    void commit(const AccountCatalog &catalog) const;

  public:
    explicit AccountStore(std::filesystem::path directory, std::wstring prefix = L"SCAULink/Accounts/v1",
                          std::wstring legacy = L"SCAULink/Authentication/v1")
        : directory_(std::move(directory)), prefix_(std::move(prefix)), legacy_(std::move(legacy)) {}
    AccountCatalog load();
    bool read(const AccountInfo &entry, Credential &value) const;
    bool read_portal(const AccountInfo &entry, Credential &value) const;
    // An absent edit keeps the portal password for the same username. An empty
    // edit removes it. Both Windows credentials are bound to the catalog username.
    std::string save(AccountCatalog &catalog, std::string_view id, const Credential &value,
                     std::optional<std::wstring_view> portal_password = {});
    void pin(AccountCatalog &catalog, std::string_view id);
    void reorder(AccountCatalog &catalog, const std::vector<std::string> &ids);
    void remove(AccountCatalog &catalog, std::string_view id);
};

// One finite pass from the first row down. Two failures per account:
// original + one retry. Success resets recovery around the active account.
class AccountRotation {
    std::vector<std::string> order_;
    std::size_t index_ = 0;
    unsigned failures_ = 0;

  public:
    explicit AccountRotation(const AccountCatalog &catalog);
    bool finished() const noexcept { return index_ >= order_.size(); }
    std::string_view current() const noexcept { return finished() ? std::string_view{} : order_[index_]; }
    unsigned attempt() const noexcept { return failures_ + 1; }
    bool failed(int worker_result);
    void authenticated();
};
} // namespace scau::desktop
