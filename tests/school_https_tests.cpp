#include <winsock2.h>
#include <ws2tcpip.h>
#include "desktop/school_https.hpp"
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

using namespace scau::desktop::detail;
void require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
struct Socket {
    SOCKET value = INVALID_SOCKET;
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};
std::string read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(bool(input), "Cannot read synthetic TLS fixture");
    return {std::istreambuf_iterator<char>(input), {}};
}
struct Listener {
    Socket socket;
    unsigned short port{};
    Listener() {
        socket.value = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        require(bind(socket.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
                    listen(socket.value, 1) == 0, "Cannot bind loopback TLS fixture");
        int length = sizeof(address);
        require(getsockname(socket.value, reinterpret_cast<sockaddr*>(&address), &length) == 0, "No loopback port");
        port = ntohs(address.sin_port);
    }
    SOCKET accept() {
        fd_set ready{}; FD_ZERO(&ready); FD_SET(socket.value, &ready); timeval timeout{3, 0};
        require(select(0, &ready, nullptr, nullptr, &timeout) == 1, "Loopback accept deadline");
        return ::accept(socket.value, nullptr, nullptr);
    }
    SOCKET connect() {
        SOCKET client = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{}; address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(port);
        if (::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address))) {
            closesocket(client); throw std::runtime_error("Cannot connect loopback TLS fixture");
        }
        return client;
    }
};
int wmain(int argc, wchar_t** argv) {
    WSADATA startup{};
    if (WSAStartup(MAKEWORD(2, 2), &startup)) return 2;
    try {
        require(argc == 2, "Expected synthetic certificate directory");
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
        require(bool(context), "No server TLS context");
        SSL_CTX_set_security_level(context.get(), 0);
        require(SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION) == 1 &&
                    SSL_CTX_set_max_proto_version(context.get(), TLS1_2_VERSION) == 1 &&
                    SSL_CTX_set_cipher_list(context.get(), "ECDHE-RSA-AES256-SHA384") == 1, "Server protocol bounds");
        const auto directory = std::filesystem::path(argv[1]);
        const auto certificate = read(directory / "tls-md5-cert.pem"), private_key = read(directory / "tls-test-key.pem");
        std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(BIO_new_mem_buf(certificate.data(), int(certificate.size())), BIO_free);
        std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(BIO_new_mem_buf(private_key.data(), int(private_key.size())), BIO_free);
        std::unique_ptr<X509, decltype(&X509_free)> cert(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr), X509_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        require(cert && key && SSL_CTX_use_certificate(context.get(), cert.get()) == 1 &&
                    SSL_CTX_use_PrivateKey(context.get(), key.get()) == 1, "MD5 / 1024-bit fixture key pair");
        for (bool post : {true, false}) {
            Listener listener;
            std::string server_error;
            std::jthread server([&] {
                try {
                    Socket accepted; accepted.value = listener.accept();
                    DWORD timeout = 3000;
                    setsockopt(accepted.value, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
                    setsockopt(accepted.value, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
                    std::unique_ptr<SSL, decltype(&SSL_free)> tls(SSL_new(context.get()), SSL_free);
                    require(tls && SSL_set_fd(tls.get(), int(accepted.value)) == 1 && SSL_accept(tls.get()) == 1,
                            "MD5 fixture handshake failed");
                    const char* sni = SSL_get_servername(tls.get(), TLSEXT_NAMETYPE_host_name);
                    require(sni && std::string_view(sni) == "mavis.scau.edu.cn", "SNI must stay fixed to school origin");
                    std::string request;
                    for (;;) {
                        char buffer[2048]; const auto n = SSL_read(tls.get(), buffer, sizeof(buffer));
                        require(n > 0, "No fixture request"); request.append(buffer, n);
                        const auto end = request.find("\r\n\r\n");
                        if (end != std::string::npos && request.size() >= end + 4 + (post ? 9 : 0)) break;
                        require(request.size() < 8192, "Request bound");
                    }
                    require(request.starts_with(post ? "POST /selfservice/fixture HTTP/1.1\r\n" :
                                                       "GET /selfservice/fixture?s=fixture HTTP/1.1\r\n") &&
                                request.find("Host: mavis.scau.edu.cn:8443\r\n") != std::string::npos &&
                                (post ? request.find("Content-Length: 9\r\n") != std::string::npos && request.ends_with("s=fixture") :
                                        request.find("Content-Length: 0\r\n") != std::string::npos && request.ends_with("\r\n\r\n")),
                            "Exact GET query or POST body and origin");
                    require((request.find("Cookie: JSESSIONID=fixture\r\n") != std::string::npos) == !post,
                            "Cookie belongs only to the explicit request");
                    for (std::string_view part : {"HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=nextfixture; Path=/selfservice\r\nTransfer-Encoding: chunked\r\n\r\n",
                                                  "b\r\n{\"ok\":true}\r\n", "0\r\n\r\n"}) {
                        require(SSL_write(tls.get(), part.data(), int(part.size())) == int(part.size()), "Fragmented TLS write");
                        Sleep(5);
                    }
                    SSL_shutdown(tls.get());
                } catch (const std::exception& error) { server_error = error.what(); }
            });
            Socket client; client.value = listener.connect();
            TlsDiagnostics diagnostics;
            const auto result = school_tls_exchange(client.value, post ? "POST" : "GET",
                                                     post ? "/selfservice/fixture" : "/selfservice/fixture?s=fixture",
                                                     post ? "s=fixture" : "", GetTickCount64() + 4000, &diagnostics,
                                                     nullptr, post ? "" : "JSESSIONID=fixture");
            server.join();
            require(server_error.empty(), server_error.c_str());
            require(result.state == TransportState::Complete && diagnostics.connected &&
                        result.response.status == 200 && result.response.body == "{\"ok\":true}" &&
                        result.response.session_cookie == "JSESSIONID=nextfixture",
                    "Actual OpenSSL transport must accept legacy certificate and decode chunked response");
        }
        {
            Listener listener;
            std::jthread server([&] { Socket accepted; accepted.value = listener.accept(); Sleep(350); });
            Socket client; client.value = listener.connect();
            std::atomic_bool cancel = false;
            std::jthread canceller([&] { Sleep(30); cancel = true; });
            TlsDiagnostics diagnostics;
            const auto started = GetTickCount64();
            const auto result = school_tls_exchange(client.value, "GET", "/selfservice/fixture", {}, started + 4000,
                                                     &diagnostics, &cancel);
            const auto elapsed = GetTickCount64() - started;
            require(result.state == TransportState::NetworkError && diagnostics.socket_error == ERROR_CANCELLED && elapsed < 700,
                    "Cancellation must interrupt a stalled TLS handshake promptly");
        }
        std::cout << "PASS: real TLS 1.2 / MD5-certificate loopback, fixed SNI/Host, GET/POST, scoped cookie, chunking, cancellation\n";
        WSACleanup(); return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; WSACleanup(); return 1; }
}
