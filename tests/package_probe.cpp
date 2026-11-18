// Explicit, single-account integration probe. Not registered with CTest.
// Uses the app's own saved portal credential only in memory; prints availability,
// never credentials, account identity, financial values or server responses.
#include "desktop/package_query.hpp"
#include "desktop/accounts.hpp"
#include "protocol.hpp"
#include "desktop/school_https.hpp"
#include "desktop/service_query.hpp"
#include "selfservice_crypto.hpp"
#include <fstream>
#include <roapi.h>
#include <iostream>

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"--public-rejected-summary") {
        if (FAILED(RoInitialize(RO_INIT_MULTITHREADED))) return 3;
        try {
            // Credential-free negative control. This branch never opens the
            // account store or submits a real username/password.
            const auto encoded = scau::selfservice_encode_query(
                L"userid=&password=&userip=255.255.255.255&callBack=ballInfo&channel=su");
            scau::desktop::detail::TlsDiagnostics tls;
            const auto reply = scau::desktop::detail::school_https_request("GET",
                "/selfservice/module/scgroup/web/login_judge2.jsf?s=" + encoded, {}, &tls);
            const auto text = scau::desktop::detail::decode_school_response(reply.response.body, reply.response.content_type);
            scau::desktop::PackageDiagnostics diagnostic;
            const auto info = text ? scau::desktop::parse_package_response(*text, &diagnostic) : scau::desktop::PackageInfo{};
            const bool passed = reply.state == scau::desktop::detail::TransportState::Complete &&
                reply.response.status == 200 && info.state == scau::desktop::PackageState::AuthError &&
                diagnostic.legacy_error_code.has_value();
            std::cout << "{\"credentialFreeControl\":true,\"passed\":" << (passed ? "true" : "false")
                << ",\"httpStatus\":" << reply.response.status << ",\"httpComplete\":" << (reply.response.complete ? "true" : "false")
                << ",\"bodyBytes\":" << reply.response.body.size() << ",\"queryState\":" << int(info.state)
                << ",\"summaryResult\":" << int(diagnostic.summary_result) << ",\"legacyError\":"
                << (diagnostic.legacy_error_code ? std::to_string(*diagnostic.legacy_error_code) : "null") << "}\n";
            RoUninitialize(); return passed ? 0 : 1;
        } catch (...) { RoUninitialize(); std::cout << "{\"credentialFreeControl\":true,\"passed\":false}\n"; return 1; }
    }
    if (argc == 2 && (std::wstring_view(argv[1]) == L"--public-tls" ||
                      std::wstring_view(argv[1]) == L"--public-empty-post")) {
        scau::desktop::detail::TlsDiagnostics diagnostics;
        const bool post = std::wstring_view(argv[1]) == L"--public-empty-post";
        const auto result = scau::desktop::detail::school_https_request(post ? "POST" : "GET",
            post ? "/selfservice/module/scgroup/web/login_judge2.jsf" : "/selfservice/", post ? "s=" : "", &diagnostics);
        std::cout << "{\"transportState\":" << int(result.state) << ",\"httpStatus\":" << result.response.status
                  << ",\"tlsConnected\":" << (diagnostics.connected ? "true" : "false")
                  << ",\"transportError\":" << diagnostics.socket_error << ",\"tlsError\":" << diagnostics.tls_error
                  << ",\"bodyBytes\":" << result.response.body.size()
                  << ",\"library\":\"" << scau::desktop::detail::school_tls_version() << "\"}\n";
        return result.state == scau::desktop::detail::TransportState::Complete ? 0 : 1;
    }
    const bool save_private = argc == 3 && std::wstring_view(argv[2]) == L"--save-private-response";
    const bool service = (argc == 2 || save_private) && std::wstring_view(argv[1]) == L"--live-service-readonly";
    if (!service && ((argc != 2 && !save_private) || std::wstring_view(argv[1]) != L"--live-own-account")) return 2;
    const auto initialized = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(initialized)) return 3;
    try {
        const auto directory = scau::desktop::data_directory();
        if (!std::filesystem::is_regular_file(directory / L"accounts.dat")) {
            std::cout << "{\"savedAccountAvailable\":false}\n";
            RoUninitialize(); return 0;
        }
        scau::desktop::AccountStore store(directory);
        const auto catalog = store.load();
        const auto* account = catalog.first_account();
        scau::desktop::Credential credential;
        if (!account || !store.read_portal(*account, credential)) {
            std::cout << "{\"savedAccountAvailable\":false}\n";
            RoUninitialize(); return 0;
        }
        std::array<unsigned char, 6> mac{};
        const auto profile = scau::desktop::locate_profile(directory, scau::desktop::executable_path());
        if (!profile.empty()) mac = scau::load_profile(profile).local;
        if (service) {
            scau::desktop::CampusSender sender;
            if (save_private) sender = [](auto method, auto path, auto body, auto cookie, auto cancel) {
                const std::string_view refresh = "/selfservice/module/userself/web/userself_ajax.jsf?methodName=indexBean.refreshSelfIndexData";
                if ((method == "POST" && path != refresh) || path.find("newConfirm") != std::string_view::npos)
                    return scau::desktop::detail::HttpsResult{}; // Probe cannot mutate an account.
                auto reply = scau::desktop::detail::school_https_request(method, path, body, nullptr, cancel, cookie);
                if (path == "/selfservice/module/userself/web/self_suspend.jsf") {
                    const auto folder = std::filesystem::current_path() / "captures/package-api-20261113/openssl-native/devices-pause-research";
                    std::filesystem::create_directories(folder);
                    std::ofstream(folder / "native-pause-form.bin", std::ios::binary).write(reply.response.body.data(), reply.response.body.size());
                }
                return reply;
            };
            scau::desktop::CampusSession session(std::move(sender));
            const auto view = session.prepare(credential, mac);
            credential.clear();
            std::cout << "{\"serviceState\":" << int(view.state) << ",\"error\":" << int(view.error)
                      << ",\"canPause\":" << (view.can_pause ? "true" : "false")
                      << ",\"canResume\":" << (view.can_resume ? "true" : "false")
                      << ",\"onlineDevices\":" << (view.online_devices ? std::to_string(*view.online_devices) : "null")
                      << ",\"ownTargetVerified\":" << (session.prepared() ? "true" : "false")
                      << ",\"stage\":" << session.diagnostic_stage() << ",\"mutationRequests\":0}\n";
            RoUninitialize(); return 0;
        }
        scau::desktop::PackageDiagnostics diagnostics;
        std::string private_response;
        const auto info = scau::desktop::query_package(credential, mac, &diagnostics, save_private ? &private_response : nullptr);
        SYSTEMTIME local{}; GetLocalTime(&local);
        const auto estimate = scau::desktop::estimate_next_charge(info, std::chrono::year{int(local.wYear)} /
            unsigned(local.wMonth) / unsigned(local.wDay));
        if (save_private) {
            const auto destination = std::filesystem::current_path() / L"captures/package-api-20261113/openssl-native";
            std::filesystem::create_directories(destination);
            std::ofstream(destination / "response.bin", std::ios::binary).write(private_response.data(), private_response.size());
            std::ofstream(destination / "content-type.txt") << diagnostics.content_type;
        }
        credential.clear();
        std::cout << "{\"savedAccountAvailable\":true,\"queryState\":" << int(info.state)
                  << ",\"queryStage\":" << int(diagnostics.stage) << ",\"interfaceIndex\":" << diagnostics.interface_index
                  << ",\"summaryResult\":" << int(diagnostics.summary_result)
                  << ",\"responseBytes\":" << diagnostics.response_bytes
                  << ",\"legacyError\":" << (diagnostics.legacy_error_code ? std::to_string(*diagnostics.legacy_error_code) : "null")
                  << ",\"transportError\":" << diagnostics.transport_error << ",\"httpStatus\":" << diagnostics.http_status
                  << ",\"tlsConnected\":" << (diagnostics.tls_connected ? "true" : "false")
                  << ",\"tlsError\":" << diagnostics.tls_library_error
                  << ",\"certificateChecksDisabled\":" << (diagnostics.certificate_checks_disabled ? "true" : "false")
                  << ",\"balanceAvailable\":" << (info.balance ? "true" : "false")
                  << ",\"monthlyFeeAvailable\":" << (info.monthly_fee ? "true" : "false")
                  << ",\"expiryAvailable\":" << (info.expires ? "true" : "false")
                  << ",\"cycleEndAvailable\":" << (info.cycle_end ? "true" : "false")
                  << ",\"detailRequested\":" << (diagnostics.detail_requested ? "true" : "false")
                  << ",\"detailHttpStatus\":" << diagnostics.detail_http_status
                  << ",\"detailLoginStatus\":" << diagnostics.detail_login_status
                  << ",\"detailSessionAvailable\":" << (diagnostics.detail_session_available ? "true" : "false")
                  << ",\"detailRedirectRecognized\":" << (diagnostics.detail_redirect_recognized ? "true" : "false")
                  << ",\"nextChargeAvailable\":" << (info.next_charge ? "true" : "false") << "}\n";
        std::cout << "{\"billingRequested\":" << (diagnostics.billing_requested ? "true" : "false")
                  << ",\"billingHttpStatus\":" << diagnostics.billing_http_status
                  << ",\"billingDetailMatched\":" << (diagnostics.billing_detail_matched ? "true" : "false")
                  << ",\"cycleFeeAvailable\":" << (info.cycle_fee ? "true" : "false")
                  << ",\"fixedDayCycleAvailable\":" << (info.cycle_days ? "true" : "false")
                  << ",\"estimatedNextChargeAvailable\":" << (estimate ? "true" : "false")
                  << ",\"authoritativeNextChargeAvailable\":" << (info.next_charge ? "true" : "false") << "}\n";
        std::cout << "{\"onlineDevices\":" << (info.online_devices ? std::to_string(*info.online_devices) : "null") << "}\n";
        RoUninitialize(); return 0;
    } catch (...) {
        RoUninitialize(); std::cout << "{\"probeError\":true}\n"; return 1;
    }
}
