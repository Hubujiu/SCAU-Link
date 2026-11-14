#include "desktop/connection_setup.hpp"
#include "profile_store.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace scau;
using namespace scau::desktop;
int wmain(int argc, wchar_t** argv) { try {
    if (argc != 3 || std::wstring_view(argv[1]) != L"--local-only-empty-directory")
        throw std::runtime_error("Use --local-only-empty-directory with an absolute, empty QA directory");
    const std::filesystem::path directory(argv[2]);
    if (!directory.is_absolute() || !std::filesystem::is_directory(directory) || !std::filesystem::is_empty(directory))
        throw std::runtime_error("Refusing a nonempty or relative directory");
    const auto adapters = connection_adapters();
    const auto selected = choose_connection_adapter(adapters);
    const auto setup = prepare_connection(directory, adapters);
    std::cout << std::boolalpha << "{\"initiallyEmpty\":true,\"adapterAvailable\":" << bool(selected)
              << ",\"cacheCreated\":" << setup.created << ",\"driverAvailable\":" << capture_driver_available();
    if (selected && setup.found) {
        const auto profile = load_profile(setup.path);
        std::cout << ",\"linkUp\":" << setup.link_up << ",\"localMacMatches\":" << (profile.local == adapters[*selected].mac)
                  << ",\"schoolServiceMatches\":" << (profile.service == scau_wired_service())
                  << ",\"deviceFieldBounded\":" << (profile.device_id.size() == 64)
                  << ",\"localDiskIdentityAvailable\":" << std::any_of(profile.device_id.begin(),profile.device_id.end(),[](Byte b){return b != 0;})
                  << ",\"serverWillBeDiscovered\":" << (profile.server == Mac{})
                  << ",\"accountNotStored\":" << profile.username.empty();
    }
    std::cout << ",\"networkRequests\":0,\"authenticationStarted\":false}\n";
    return 0;
} catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; } }
