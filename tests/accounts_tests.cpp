#include "auth_result.hpp"
#include "desktop/accounts.hpp"
#include <fstream>
#include <iostream>
#include <objbase.h>
#include <stdexcept>
#include <wincred.h>
#include <windows.h>

using namespace scau::desktop;
void require(bool value, const char *why) {
    if (!value)
        throw std::runtime_error(why);
}
template <class F> void rejects(F f, const char *why) {
    bool failed = false;
    try {
        f();
    } catch (const std::exception &) {
        failed = true;
    }
    require(failed, why);
}
unsigned vault_count(const std::wstring &prefix) {
    DWORD count = 0;
    PCREDENTIALW *values = nullptr;
    if (!CredEnumerateW((prefix + L"/*").c_str(), 0, &count, &values)) {
        if (GetLastError() == ERROR_NOT_FOUND)
            return 0;
        throw std::runtime_error("Cannot inspect isolated test credential namespace");
    }
    for (DWORD i = 0; i < count; ++i)
        if (values[i]->CredentialBlob)
            SecureZeroMemory(values[i]->CredentialBlob, values[i]->CredentialBlobSize);
    CredFree(values);
    return count;
}
int wmain() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    try {
        wchar_t temp[MAX_PATH]{};
        GetTempPathW(MAX_PATH, temp);
        const auto unique = new_account_id();
        const auto directory = std::filesystem::path(temp) /
                               (L"ScauLinkAccountsTest-" + std::wstring(unique.begin(), unique.end()));
        const auto migration = directory / L"migration";
        const auto prefix = L"SCAULink/Tests/" + std::wstring(unique.begin(), unique.end());
        AccountStore store(directory, prefix, L"");
        AccountCatalog catalog;
        struct Cleanup {
            AccountStore &store;
            AccountCatalog &catalog;
            std::filesystem::path directory;
            std::wstring prefix;
            ~Cleanup() {
                try {
                    while (!catalog.entries.empty())
                        store.remove(catalog, catalog.entries.back().id);
                } catch (...) {
                }
                try {
                    CredentialStore(prefix + L"/legacy").erase();
                } catch (...) {
                }
                std::error_code e;
                std::filesystem::remove(directory / L"accounts.dat", e);
                std::filesystem::remove(directory / L"blocked", e);
                std::filesystem::remove(directory / L"migration" / L"accounts.dat", e);
                std::filesystem::remove(directory / L"migration", e);
                std::filesystem::remove(directory, e);
            }
        } cleanup{store, catalog, directory, prefix};
        require(store.load().entries.empty(), "A new catalog must be empty");
        Credential first;
        first.username = L"account-test-one";
        first.password = L"VERY-PRIVATE-CREDENTIAL-1";
        const auto a = store.save(catalog, {}, first);
        const auto old_secret = catalog.find(a)->secret_id;
        Credential second;
        second.username = L"account-test-two";
        second.password = L"VERY-PRIVATE-CREDENTIAL-2";
        const auto b = store.save(catalog, {}, second);
        require(catalog.first_account()->id == a, "New accounts append without changing the first row");
        store.pin(catalog, b);
        require(catalog.first_account()->id == b, "Pin must move the selected account to the first row");
        store.pin(catalog, b);
        store.reorder(catalog, {b, a});
        auto loaded = store.load();
        require(loaded.first_account()->id == b && loaded.entries.back().id == a,
                "Pin and drag order must survive reload without a separate preference");
        {
            std::ifstream file(directory / L"accounts.dat", std::ios::binary);
            std::string bytes((std::istreambuf_iterator<char>(file)), {});
            require(bytes.size() == 12 + 64 * 2 && bytes.starts_with("SCAUAC02"),
                    "Catalog must contain order and opaque identifiers only");
            require(bytes.find("account-test") == std::string::npos &&
                        bytes.find("PRIVATE") == std::string::npos,
                    "Catalog cannot contain usernames or passwords");
        }
        {
            // A 0.5 catalog can name a different default; the new behavior must
            // preserve row order and ignore that retired preference.
            std::ofstream old_catalog(directory / L"accounts.dat", std::ios::binary | std::ios::trunc);
            old_catalog.write("SCAUAC01", 8);
            const char count[4]{2, 0, 0, 0};
            old_catalog.write(count, 4);
            old_catalog.write(a.data(), 32);
            for (const auto &entry : catalog.entries) {
                old_catalog.write(entry.id.data(), 32);
                old_catalog.write(entry.secret_id.data(), 32);
            }
            old_catalog.close();
            auto legacy_order = store.load();
            require(legacy_order.first_account()->id == b && legacy_order.entries.back().id == a,
                    "Legacy default must not override existing top-to-bottom row order");
            store.pin(legacy_order, b);
        }
        const auto before = vault_count(prefix);
        rejects([&] { store.save(catalog, {}, first); },
                "Duplicate account names must not create credentials");
        rejects([&] { store.reorder(catalog, {a, a}); }, "Reordering must be an exact permutation");
        rejects([&] { store.pin(catalog, std::string(32, 'f')); }, "Pinning an unknown account must fail");
        require(vault_count(prefix) == before && catalog.entries.front().id == b &&
                    store.load().first_account()->id == b,
                "Rejected edits must preserve catalog and vault state");
        Credential unchanged;
        unchanged.username = first.username;
        store.save(catalog, a, unchanged);
        Credential restored;
        require(store.read(*catalog.find(a), restored) && restored.password == first.password,
                "Empty password on an existing account must retain its saved password");
        require(catalog.find(a)->secret_id != old_secret,
                "Credential replacement must use a fresh immutable vault record");
        Credential old;
        require(
            !CredentialStore(prefix + L"/" + std::wstring(old_secret.begin(), old_secret.end())).read(old),
            "Old secret should be retired only after commit");
        unchanged.username = L"renamed-account";
        rejects([&] { store.save(catalog, a, unchanged); }, "Changing a username requires its password");
        {
            std::ofstream blocked(directory / L"blocked");
            blocked << "test";
        }
        AccountStore blocked(directory / L"blocked", prefix, L"");
        AccountCatalog empty;
        rejects([&] { blocked.save(empty, {}, second); },
                "Catalog failure must roll back a staged credential");
        require(empty.entries.empty() && vault_count(prefix) == before,
                "A failed catalog commit must not leave a new credential");
        const auto good = [&] {
            std::ifstream f(directory / L"accounts.dat", std::ios::binary);
            return std::string((std::istreambuf_iterator<char>(f)), {});
        }();
        {
            std::ofstream f(directory / L"accounts.dat", std::ios::binary | std::ios::trunc);
            f.write(good.data(), good.size() - 1);
        }
        rejects([&] { store.load(); }, "Truncated catalog must fail closed");
        {
            std::ofstream f(directory / L"accounts.dat", std::ios::binary | std::ios::trunc);
            f.write(good.data(), good.size());
        }
        CredentialStore(prefix + L"/legacy").write(first);
        AccountStore migrated(migration, prefix + L"/migrated", prefix + L"/legacy");
        auto imported = migrated.load();
        require(imported.entries.size() == 1 && imported.first_account()->username == first.username,
                "Existing single-account credentials must migrate");
        const auto imported_id = imported.first_account()->id;
        require(migrated.load().first_account()->id == imported_id, "Migration must run only once");
        migrated.remove(imported, imported_id);
        require(migrated.load().entries.empty(),
                "An explicitly empty catalog cannot re-import the legacy account");
        store.remove(catalog, b);
        require(catalog.first_account()->id == a, "Deleting the first row promotes the next saved row");
        AccountCatalog policy{{{std::string(32, 'a'), std::string(32, 'd'), L"a"},
                               {std::string(32, 'b'), std::string(32, 'e'), L"b"},
                               {std::string(32, 'c'), std::string(32, 'f'), L"c"}}};
        pin_account(policy, std::string(32, 'c'));
        const std::vector<char> expected{'c', 'c', 'a', 'a', 'b', 'b'};
        AccountRotation rotation(policy);
        for (char id : expected) {
            require(!rotation.finished() && rotation.current().front() == id,
                    "Retry order must follow the visible rows from top to bottom");
            rotation.failed(scau::auth_rejected);
        }
        require(rotation.finished() && policy.first_account()->id == std::string(32, 'c'),
                "Exhaustion must stop without rewriting list order");
        for (int outcome : {0, 2, 3, scau::auth_environment_error, scau::auth_server_terminated,
                            scau::auth_protocol_unsupported, 70, 71}) {
            AccountRotation stopped(policy);
            require(!stopped.failed(outcome) && stopped.finished(),
                    "Infrastructure, stop and server logout must not rotate credentials");
        }
        AccountRotation recovery(policy);
        recovery.failed(scau::auth_rejected);
        recovery.failed(scau::auth_rejected);
        recovery.failed(scau::auth_rejected);
        recovery.authenticated();
        require(recovery.current() == std::string(32, 'a') && recovery.attempt() == 1,
                "A successful authentication resets the failure episode");
        std::cout << "PASS: isolated Windows multi-account storage, migration, atomic rollback, "
                     "row-order persistence, pinning and bounded failover\n";
        CoUninitialize();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        CoUninitialize();
        return 1;
    }
}
