#include "accounts.hpp"
#include "auth_result.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <objbase.h>
#include <set>
#include <stdexcept>

namespace scau::desktop {
namespace {
bool valid_id(std::string_view id) {
    return id.size() == 32 && std::all_of(id.begin(), id.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}
void validate_catalog(const AccountCatalog &catalog) {
    if (catalog.entries.size() > maximum_accounts)
        throw std::runtime_error("Too many accounts");
    std::set<std::string> ids, secrets;
    for (const auto &entry : catalog.entries)
        if (!valid_id(entry.id) || !valid_id(entry.secret_id) || !ids.insert(entry.id).second ||
            !secrets.insert(entry.secret_id).second)
            throw std::runtime_error("Invalid account catalog");
}
void erase_after_commit(const std::wstring &target) noexcept {
    try {
        CredentialStore(target).erase();
    } catch (...) { /* An encrypted orphan is safer than losing a committed secret. */
    }
}
} // namespace
const AccountInfo *AccountCatalog::find(std::string_view id) const noexcept {
    for (const auto &entry : entries)
        if (entry.id == id)
            return &entry;
    return nullptr;
}
const AccountInfo *AccountCatalog::first_account() const noexcept {
    return entries.empty() ? nullptr : &entries.front();
}
std::string new_account_id() {
    GUID id{};
    if (FAILED(CoCreateGuid(&id)))
        throw std::runtime_error("Cannot generate account identifier");
    const auto *bytes = reinterpret_cast<const unsigned char *>(&id);
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (std::size_t n = 0; n < sizeof(id); ++n) {
        out.push_back(hex[bytes[n] >> 4]);
        out.push_back(hex[bytes[n] & 15]);
    }
    return out;
}
void reorder_accounts(AccountCatalog &catalog, const std::vector<std::string> &order) {
    if (order.size() != catalog.entries.size())
        throw std::runtime_error("Invalid account order");
    std::vector<AccountInfo> sorted;
    std::set<std::string> seen;
    for (const auto &id : order) {
        auto *entry = catalog.find(id);
        if (!entry || !seen.insert(id).second)
            throw std::runtime_error("Invalid account order");
        sorted.push_back(*entry);
    }
    catalog.entries = std::move(sorted);
}
void pin_account(AccountCatalog &catalog, std::string_view id) {
    const auto entry = std::find_if(catalog.entries.begin(), catalog.entries.end(),
                                    [&](const auto &row) { return row.id == id; });
    if (entry == catalog.entries.end())
        throw std::runtime_error("Account not found");
    std::rotate(catalog.entries.begin(), entry, entry + 1);
}
void remove_account_entry(AccountCatalog &catalog, std::string_view id) {
    const auto found = std::find_if(catalog.entries.begin(), catalog.entries.end(),
                                    [&](const auto &entry) { return entry.id == id; });
    if (found == catalog.entries.end())
        throw std::runtime_error("Account not found");
    catalog.entries.erase(found);
}
void validate_account_edit(const AccountCatalog &catalog, std::string_view id, const Credential &value) {
    if (value.username.empty() || value.username.size() > 256 || value.password.size() > 256 ||
        value.username.find(L'\0') != std::wstring::npos || value.password.find(L'\0') != std::wstring::npos)
        throw std::runtime_error("Invalid account fields");
    if (!id.empty() && !catalog.find(id))
        throw std::runtime_error("Account not found");
    if (id.empty() && catalog.entries.size() >= maximum_accounts)
        throw std::runtime_error("Too many accounts");
    for (const auto &entry : catalog.entries)
        if (entry.id != id && entry.username == value.username)
            throw std::runtime_error("Account already exists");
    if (value.password.empty() && (id.empty() || catalog.find(id)->username != value.username))
        throw std::runtime_error("Password required");
    struct Encoded {
        std::string username, password;
        ~Encoded() {
            if (!username.empty())
                SecureZeroMemory(username.data(), username.size());
            if (!password.empty())
                SecureZeroMemory(password.data(), password.size());
        }
    } encoded;
    encoded.username = to_gbk(value.username);
    if (!value.password.empty())
        encoded.password = to_gbk(value.password);
}
std::wstring AccountStore::target(std::string_view secret) const {
    if (!valid_id(secret))
        throw std::runtime_error("Invalid credential identifier");
    return prefix_ + L"/" + std::wstring(secret.begin(), secret.end());
}
void AccountStore::commit(const AccountCatalog &catalog) const {
    validate_catalog(catalog);
    std::filesystem::create_directories(directory_);
    const auto path = directory_ / L"accounts.dat";
    const auto temp = directory_ / (L"accounts-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                    std::to_wstring(GetTickCount64()) + L".tmp");
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code e;
            std::filesystem::remove(path, e);
        }
    } cleanup{temp};
    std::ofstream file(temp, std::ios::binary | std::ios::trunc);
    if (!file)
        throw std::runtime_error("Cannot write account catalog");
    file.write("SCAUAC02", 8);
    const auto count = static_cast<unsigned>(catalog.entries.size());
    for (unsigned n = 0; n < 4; ++n)
        file.put(char((count >> (8 * n)) & 255));
    for (const auto &entry : catalog.entries) {
        file.write(entry.id.data(), 32);
        file.write(entry.secret_id.data(), 32);
    }
    file.flush();
    if (!file)
        throw std::runtime_error("Cannot save account catalog");
    file.close();
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("Cannot commit account catalog");
}
AccountCatalog AccountStore::load() {
    const auto path = directory_ / L"accounts.dat";
    if (!std::filesystem::exists(path)) {
        AccountCatalog catalog;
        if (!legacy_.empty()) {
            Credential old;
            if (CredentialStore(legacy_).read(old))
                save(catalog, {}, old);
        }
        return catalog;
    }
    if (std::filesystem::file_size(path) > 44 + 64 * maximum_accounts)
        throw std::runtime_error("Invalid account catalog size");
    std::ifstream file(path, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(file)), {});
    const bool legacy = data.starts_with("SCAUAC01");
    const std::size_t header = legacy ? 44 : 12;
    if (data.size() < header || (!legacy && !data.starts_with("SCAUAC02")))
        throw std::runtime_error("Invalid account catalog header");
    unsigned count = 0;
    for (unsigned n = 0; n < 4; ++n)
        count |= static_cast<unsigned char>(data[8 + n]) << (8 * n);
    if (count > maximum_accounts || data.size() != header + 64 * count)
        throw std::runtime_error("Invalid account catalog length");
    AccountCatalog catalog;
    for (unsigned n = 0; n < count; ++n)
        catalog.entries.push_back(
            {data.substr(header + 64 * n, 32), data.substr(header + 32 + 64 * n, 32), {}});
    validate_catalog(catalog);
    AccountCatalog available;
    for (auto &entry : catalog.entries) {
        Credential saved;
        if (read(entry, saved)) {
            entry.username = saved.username;
            available.entries.push_back(std::move(entry));
        }
    }
    return available;
}
bool AccountStore::read(const AccountInfo &entry, Credential &value) const {
    return CredentialStore(target(entry.secret_id)).read(value);
}
std::string AccountStore::save(AccountCatalog &catalog, std::string_view id, const Credential &value) {
    validate_account_edit(catalog, id, value);
    const auto *previous = catalog.find(id);
    Credential saved;
    if (value.password.empty()) {
        if (!previous || !read(*previous, saved))
            throw std::runtime_error("Saved password not available");
    } else
        saved.password = value.password;
    saved.username = value.username;
    AccountInfo entry{previous ? previous->id : new_account_id(), new_account_id(), saved.username};
    AccountCatalog next = catalog;
    if (previous)
        for (auto &old : next.entries)
            if (old.id == id)
                old = entry;
    if (!previous)
        next.entries.push_back(entry);
    CredentialStore(target(entry.secret_id)).write(saved);
    const auto old_target = previous ? target(previous->secret_id) : std::wstring{};
    try {
        commit(next);
    } catch (...) {
        erase_after_commit(target(entry.secret_id));
        throw;
    }
    catalog = std::move(next);
    if (!old_target.empty())
        erase_after_commit(old_target);
    return entry.id;
}
void AccountStore::pin(AccountCatalog &catalog, std::string_view id) {
    auto next = catalog;
    pin_account(next, id);
    commit(next);
    catalog = std::move(next);
}
void AccountStore::reorder(AccountCatalog &catalog, const std::vector<std::string> &ids) {
    auto next = catalog;
    reorder_accounts(next, ids);
    commit(next);
    catalog = std::move(next);
}
void AccountStore::remove(AccountCatalog &catalog, std::string_view id) {
    const auto *previous = catalog.find(id);
    if (!previous)
        throw std::runtime_error("Account not found");
    const auto old_target = target(previous->secret_id);
    auto next = catalog;
    remove_account_entry(next, id);
    commit(next);
    catalog = std::move(next);
    erase_after_commit(old_target);
}
AccountRotation::AccountRotation(const AccountCatalog &catalog) {
    for (const auto &entry : catalog.entries)
        order_.push_back(entry.id);
}
bool AccountRotation::failed(int worker_result) {
    if (finished())
        return false;
    if (!scau::allows_account_retry(worker_result)) {
        index_ = order_.size();
        return false;
    }
    if (++failures_ == 2) {
        ++index_;
        failures_ = 0;
    }
    return !finished();
}
void AccountRotation::authenticated() {
    if (finished())
        return;
    std::rotate(order_.begin(), order_.begin() + index_, order_.end());
    index_ = 0;
    failures_ = 0;
}
} // namespace scau::desktop
