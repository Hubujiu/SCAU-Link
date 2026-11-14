#include <winsock2.h>
#include "portal_auth.hpp"
#include "platform.hpp"
#include "campus_wifi.hpp"
#include <openssl/bn.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cmath>
#include <map>
#include <memory>
#include <utility>

namespace scau::desktop::portal {
namespace {
constexpr std::size_t body_limit = 65536, query_limit = 8192;
void wipe(std::string& value) noexcept {
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
}
struct Wipe { std::string& value; ~Wipe() { wipe(value); } };
bool cancelled(const Options& options) {
    return options.cancel && options.cancel->load(std::memory_order_relaxed);
}
bool valid_utf8(std::string_view value) {
    return value.empty() || (value.size() <= body_limit &&
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                            static_cast<int>(value.size()), nullptr, 0) > 0);
}
std::string utf8(std::wstring_view value) {
    if (value.empty() || value.size() > 2048 || value.find(L'\0') != value.npos) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!count) return {};
    std::string result(count, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), count, nullptr, nullptr)) return {};
    return result;
}
bool text(std::string_view value, std::size_t maximum) {
    return value.size() <= maximum && value.find('\0') == value.npos && valid_utf8(value);
}
bool ipv4(std::string_view value) {
    unsigned parts[4]{};
    for (unsigned i = 0; i < 4; ++i) {
        auto end = value.find('.');
        if (i == 3) end = value.size();
        if (end == value.npos || end == 0 || end > 3) return false;
        auto [ptr, ec] = std::from_chars(value.data(), value.data() + end, parts[i]);
        if (ec != std::errc{} || ptr != value.data() + end || parts[i] > 255) return false;
        if (i == 3) { if (end != value.size()) return false; }
        else value.remove_prefix(end + 1);
    }
    return parts[0] != 0 && parts[0] < 224 &&
        !(parts[0] == 255 && parts[1] == 255 && parts[2] == 255 && parts[3] == 255);
}
std::string lower(std::string_view value) {
    std::string result(value);
    for (auto& ch : result) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    return result;
}
struct Url { std::string origin, host, path, query; unsigned short port{}; bool secure{}; };
std::optional<Url> url(std::string_view value) {
    if (value.size() > query_limit + 1024 || value.empty() ||
        std::any_of(value.begin(), value.end(), [](unsigned char c) { return c <= 32 || c >= 127 || c == '\\'; }) ||
        value.find('#') != value.npos || value.find('@') != value.npos) return {};
    Url result;
    if (value.starts_with("https://")) { result.secure = true; result.port = 443; value.remove_prefix(8); }
    else if (value.starts_with("http://")) { result.port = 80; value.remove_prefix(7); }
    else return {};
    const auto slash = value.find_first_of("/?");
    auto authority = value.substr(0, slash);
    if (slash == value.npos) value = {};
    else value.remove_prefix(slash);
    const auto colon = authority.find(':');
    auto host = authority.substr(0, colon);
    if (host.empty() || host.size() > 253 || host.front() == '.' || host.back() == '.' ||
        host.find("..") != host.npos || std::any_of(host.begin(), host.end(), [](char c) {
            return !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
                   !(c >= '0' && c <= '9') && c != '-' && c != '.';
        })) return {};
    result.host = lower(host);
    if (colon != authority.npos) {
        const auto port_text = authority.substr(colon + 1);
        unsigned port{};
        auto [ptr, ec] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
        if (port_text.empty() || ec != std::errc{} || ptr != port_text.data() + port_text.size() || !port || port > 65535) return {};
        result.port = static_cast<unsigned short>(port);
    }
    result.origin = (result.secure ? "https://" : "http://") + result.host;
    if (result.port != (result.secure ? 443 : 80)) result.origin += ":" + std::to_string(result.port);
    auto question = value.find('?');
    result.path = value.empty() || value.front() == '?' ? "/" : std::string(value.substr(0, question));
    if (question != value.npos) result.query = value.substr(question + 1);
    return result;
}
bool trusted(std::string_view origin, const Options& options) {
    auto candidate = url(origin);
    if (!candidate || candidate->path != "/" || !candidate->query.empty()) return false;
    return std::any_of(options.trusted_origins.begin(), options.trusted_origins.end(), [&](const auto& allowed) {
        auto parsed = url(allowed);
        return parsed && parsed->path == "/" && parsed->query.empty() && parsed->origin == candidate->origin;
    });
}
bool valid_target(const Target& target, const Options& options) {
    return trusted(target.origin, options) && ipv4(target.user_ip) &&
        !target.query_string.empty() && text(target.query_string, query_limit) &&
        target.query_string.find_first_of("\r\n#") == target.query_string.npos;
}
std::string quote(std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 6 + 2);
    result += '"';
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') { result += '\\'; result += static_cast<char>(ch); }
        else if (ch < 32) { result += "\\u00"; result += hex[ch >> 4]; result += hex[ch & 15]; }
        else result += static_cast<char>(ch);
    }
    result += '"';
    return result;
}
void field(std::string& json, std::string_view key, std::string_view value) {
    if (json.size() > 1) json += ',';
    json += quote(key); json += ':';
    auto encoded = quote(value);
    json += encoded;
    wipe(encoded);
}
Request post(const Target& target, std::string_view suffix, std::string body) {
    body += '}';
    Request request(target.origin + "/eportal/inferface/authAPI/" + std::string(suffix), "POST", std::move(body));
    request.expected_source_ip = target.user_ip;
    return request;
}
std::string uri_encode(std::string_view value) {
    constexpr char hex[]="0123456789ABCDEF"; std::string out; out.reserve(value.size()*3);
    for (unsigned char c:value) {
        if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
            c=='-'||c=='_'||c=='.'||c=='!'||c=='~'||c=='*'||c=='\''||c=='('||c==')') out+=char(c);
        else {out+='%';out+=hex[c>>4];out+=hex[c&15];}
    }
    return out;
}
std::string twice(std::string_view value) {auto once=uri_encode(value);Wipe wipe{once};return uri_encode(once);}
void form_field(std::string& body,std::string_view key,std::string_view value,bool double_encoding=true) {
    if(!body.empty())body+='&';body+=key;body+='=';
    auto encoded=double_encoding?twice(value):uri_encode(value);Wipe wipe{encoded};body+=encoded;
}
Request form_post(const Target& target,std::string_view method,std::string body) {
    Request request(target.origin+"/eportal/InterFace.do?method="+std::string(method),"POST",std::move(body));
    request.expected_source_ip=target.user_ip;request.form=true;return request;
}
std::optional<std::string> rsa_password(std::string_view password,const Target& target) {
    if(target.public_exponent.empty() || target.public_exponent.size()>8 ||
        !std::all_of(target.public_exponent.begin(),target.public_exponent.end(),[](unsigned char c){return std::isxdigit(c)!=0;}) || target.public_modulus.size()<128 ||
        target.public_modulus.size()>1024 || !std::all_of(target.public_modulus.begin(),target.public_modulus.end(),[](unsigned char c){return std::isxdigit(c)!=0;}))return {};
    std::string mac;
    for(std::size_t at=0;at<target.query_string.size();) {
        const auto end=target.query_string.find('&',at);const auto pair=std::string_view(target.query_string).substr(at,end==std::string::npos?end:end-at);
        if(pair.starts_with("mac="))mac=pair.substr(4);
        if(end==std::string::npos)break;at=end+1;
    }
    if(mac.empty() || mac.size()>64 || !std::all_of(mac.begin(),mac.end(),[](unsigned char c){return std::isxdigit(c)!=0||c==':'||c=='-'||c=='%';}))return {};
    // The deployed school's JS appends >MAC, reverses bytes, uses little-endian
    // 16-bit limbs and raw RSA with zero padding, then emits 4-digit hex limbs.
    // Never substitute PKCS#1 padding or silently send plaintext on encryption failure.
    std::string plain(password);plain+='>';plain+=mac;Wipe plain_wipe{plain};
    if(std::any_of(plain.begin(),plain.end(),[](unsigned char c){return c>=128;}))return {};
    std::reverse(plain.begin(),plain.end());
    BIGNUM *modulus=nullptr,*exponent=nullptr;
    const auto mod=target.public_modulus,exp=target.public_exponent;
    if(!BN_hex2bn(&modulus,mod.c_str()) || !BN_hex2bn(&exponent,exp.c_str())){BN_free(modulus);BN_free(exponent);return {};}
    std::unique_ptr<BIGNUM,decltype(&BN_free)> m(modulus,BN_free),e(exponent,BN_free);
    std::unique_ptr<BN_CTX,decltype(&BN_CTX_free)> context(BN_CTX_new(),BN_CTX_free);
    if(!context || !BN_is_odd(m.get()) || !BN_is_odd(e.get()) || BN_num_bits(e.get())<2 || BN_cmp(e.get(),m.get())>=0)return {};
    const std::size_t chunk=(std::size_t(BN_num_bits(m.get()))+15)/16*2-2;
    if(!chunk || plain.size()>chunk*4)return {};
    std::string encrypted;
    for(std::size_t at=0;at<plain.size();at+=chunk) {
        auto block=plain.substr(at,chunk);Wipe block_wipe{block};std::reverse(block.begin(),block.end());
        std::unique_ptr<BIGNUM,decltype(&BN_clear_free)> input(BN_bin2bn(reinterpret_cast<const unsigned char*>(block.data()),int(block.size()),nullptr),BN_clear_free);
        std::unique_ptr<BIGNUM,decltype(&BN_clear_free)> output(BN_new(),BN_clear_free);
        if(!input || !output || !BN_mod_exp(output.get(),input.get(),e.get(),m.get(),context.get()))return {};
        char* raw=BN_bn2hex(output.get());if(!raw)return {};
        std::string hex(raw);OPENSSL_free(raw);
        for(auto& c:hex)if(c>='A'&&c<='F')c+=32;
        hex.insert(0,(4-hex.size()%4)%4,'0');if(!encrypted.empty())encrypted+=' ';encrypted+=hex;
    }
    return encrypted;
}

// Small bounded JSON reader. Duplicate keys, invalid UTF-8, trailing data,
// malformed surrogate escapes and excessive nesting/collections fail closed.
struct Json {
    enum class Kind { Null, String, Number, Boolean, Object, Array } kind = Kind::Null;
    std::string value;
    std::map<std::string, Json> object;
    std::vector<Json> array;
    Json() = default;
    Json(Json&&) = default;
    Json& operator=(Json&&) = default;
    ~Json() { wipe(value); }
    const Json* get(std::string_view name) const {
        auto item = object.find(std::string(name));
        return item == object.end() ? nullptr : &item->second;
    }
    std::optional<std::string_view> string(std::string_view name) const {
        auto child = get(name);
        if (!child || child->kind != Kind::String) return {};
        return child->value;
    }
};
class Reader {
    std::string_view input_;
    std::size_t at_{};
    unsigned count_{};
    void space() { while (at_ < input_.size() && (input_[at_] == ' ' || input_[at_] == '\t' || input_[at_] == '\r' || input_[at_] == '\n')) ++at_; }
    bool take(char c) { space(); if (at_ < input_.size() && input_[at_] == c) { ++at_; return true; } return false; }
    std::optional<unsigned> hex4() {
        if (input_.size() - at_ < 4) return {};
        unsigned value{};
        for (unsigned i = 0; i < 4; ++i) {
            unsigned char c = input_[at_++];
            unsigned digit = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 16;
            if (digit == 16) return {};
            value = value * 16 + digit;
        }
        return value;
    }
    static void codepoint(std::string& out, unsigned c) {
        if (c < 0x80) out += static_cast<char>(c);
        else if (c < 0x800) { out += static_cast<char>(0xc0 | c >> 6); out += static_cast<char>(0x80 | (c & 63)); }
        else if (c < 0x10000) { out += static_cast<char>(0xe0 | c >> 12); out += static_cast<char>(0x80 | (c >> 6 & 63)); out += static_cast<char>(0x80 | (c & 63)); }
        else { out += static_cast<char>(0xf0 | c >> 18); out += static_cast<char>(0x80 | (c >> 12 & 63)); out += static_cast<char>(0x80 | (c >> 6 & 63)); out += static_cast<char>(0x80 | (c & 63)); }
    }
    bool string(std::string& result) {
        if (!take('"')) return false;
        while (at_ < input_.size()) {
            unsigned char c = input_[at_++];
            if (c == '"') return true;
            if (c < 32) return false;
            if (c != '\\') { result += static_cast<char>(c); continue; }
            if (at_ == input_.size()) return false;
            switch (c = input_[at_++]) {
            case '"': case '\\': case '/': result += static_cast<char>(c); break;
            case 'b': result += '\b'; break; case 'f': result += '\f'; break;
            case 'n': result += '\n'; break; case 'r': result += '\r'; break; case 't': result += '\t'; break;
            case 'u': {
                auto first = hex4(); if (!first) return false;
                unsigned point = *first;
                if (point >= 0xd800 && point <= 0xdbff) {
                    if (input_.substr(at_, 2) != "\\u") return false;
                    at_ += 2; auto second = hex4();
                    if (!second || *second < 0xdc00 || *second > 0xdfff) return false;
                    point = 0x10000 + (point - 0xd800) * 1024 + *second - 0xdc00;
                } else if (point >= 0xdc00 && point <= 0xdfff) return false;
                codepoint(result, point); break;
            }
            default: return false;
            }
        }
        return false;
    }
    bool value(Json& out, unsigned depth) {
        if (depth > 16 || ++count_ > 1024) return false;
        space(); if (at_ == input_.size()) return false;
        if (input_[at_] == '"') { out.kind = Json::Kind::String; return string(out.value); }
        if (take('{')) {
            out.kind = Json::Kind::Object;
            if (take('}')) return true;
            do {
                std::string key; if (!string(key) || !take(':') || out.object.contains(key)) return false;
                Json child; if (!value(child, depth + 1)) return false;
                out.object.emplace(std::move(key), std::move(child));
                if (out.object.size() > 128) return false;
                if (take('}')) return true;
            } while (take(','));
            return false;
        }
        if (take('[')) {
            out.kind = Json::Kind::Array;
            if (take(']')) return true;
            do {
                Json child; if (!value(child, depth + 1)) return false;
                out.array.emplace_back(std::move(child));
                if (out.array.size() > 128) return false;
                if (take(']')) return true;
            } while (take(','));
            return false;
        }
        for (auto literal : {std::string_view("true"), std::string_view("false"), std::string_view("null")}) {
            if (input_.substr(at_).starts_with(literal)) {
                at_ += literal.size(); out.kind = literal == "null" ? Json::Kind::Null : Json::Kind::Boolean;
                out.value = literal; return true;
            }
        }
        const auto start = at_;
        if (input_[at_] == '-') ++at_;
        if (at_ == input_.size()) return false;
        if (input_[at_] == '0') ++at_;
        else { if (input_[at_] < '1' || input_[at_] > '9') return false;
            while (at_ < input_.size() && input_[at_] >= '0' && input_[at_] <= '9') ++at_; }
        for (char marker : {'.', 'e'}) {
            if (at_ < input_.size() && (input_[at_] == marker || (marker == 'e' && input_[at_] == 'E'))) {
                ++at_;
                if (marker == 'e' && at_ < input_.size() && (input_[at_] == '+' || input_[at_] == '-')) ++at_;
                const auto digits = at_;
                while (at_ < input_.size() && input_[at_] >= '0' && input_[at_] <= '9') ++at_;
                if (digits == at_) return false;
            }
        }
        out.kind = Json::Kind::Number; out.value = input_.substr(start, at_ - start); return true;
    }
public:
    explicit Reader(std::string_view input) : input_(input) {}
    bool read(Json& result) {
        if (input_.empty() || input_.size() > body_limit || !valid_utf8(input_) || !value(result, 0)) return false;
        space(); return at_ == input_.size() && result.kind == Json::Kind::Object;
    }
};
std::string message(const Json& root) {
    const auto raw = root.string("message");
    if (!raw) return {};
    std::string result(*raw);
    for (auto& c : result) if (static_cast<unsigned char>(c) < 32 || c == 127) c = ' ';
    if (result.size() > 768) {
        std::size_t end = 768;
        while (end && (static_cast<unsigned char>(result[end]) & 0xc0) == 0x80) --end;
        result.resize(end);
    }
    return result;
}
Result parse_result(std::string_view json, bool online, bool login) {
    Result result; Json root;
    if (!Reader(json).read(root)) return result;
    auto status = root.string("result");
    if (!status || status->empty() || status->size() > 32 || status->find('\0') != status->npos) return result;
    result.message = message(root);
    if (online) {
        if (*status == "success") result.state = State::Success;
        else if (*status == "fail") result.state = State::Offline;
        return result;
    }
    if (*status == "fail") { result.state = State::Rejected; return result; }
    if (*status != "success") return result;
    if (login) {
        auto index = root.string("userIndex");
        if (!index || index->empty() || !text(*index, 512)) return result;
        result.user_index = *index;
        if (auto interval = root.get("keepaliveInterval")) {
            std::uint32_t number{};
            if (interval->kind != Json::Kind::Number && interval->kind != Json::Kind::String) return Result{};
            auto [ptr, ec] = std::from_chars(interval->value.data(), interval->value.data() + interval->value.size(), number);
            if (ec != std::errc{} || ptr != interval->value.data() + interval->value.size()) return Result{};
            result.keepalive_interval = number;
        }
    }
    result.state = State::Success; return result;
}
Result fail(State state) { Result result; result.state = state; return result; }
using Parser = Result(*)(std::string_view);
Result exchange(std::optional<Request> request, const Options& options, Transport sender, Parser parser) {
    if (cancelled(options)) return fail(State::Cancelled);
    if (!request) return fail(State::InvalidInput);
    Response response = sender ? sender(*request, options) : send_winhttp(*request, options);
    Wipe response_wipe{response.body};
    if (cancelled(options)) return fail(State::Cancelled);
    Result result;
    if (response.state != State::Ready) result.state = response.state;
    else if (response.status >= 300 && response.status < 400) result.state = State::UntrustedTarget;
    else if (response.status == 401 || response.status == 403) result.state = State::Rejected;
    else if (response.status != 200) result.state = State::NetworkError;
    else result = parser(response.body);
    result.http_status = response.status;
    result.transport_error = response.error;
    return result;
}
void redact(std::string& message, std::string_view secret) {
    if (secret.empty()) return;
    for (std::size_t at = 0; (at = message.find(secret, at)) != message.npos;) {
        message.replace(at, secret.size(), "[hidden]"); at += 8;
    }
}

struct Internet {
    HINTERNET handle{};
    explicit Internet(HINTERNET value = nullptr) : handle(value) {}
    Internet(const Internet&) = delete;
    ~Internet() { if (handle) WinHttpCloseHandle(handle); }
};
struct AsyncState {
    HANDLE event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    std::atomic<DWORD> error{}, read{};
    std::array<char, 8192> buffer{};
    std::string body;
    ~AsyncState() { wipe(body); SecureZeroMemory(buffer.data(), buffer.size()); if (event) CloseHandle(event); }
};
void CALLBACK status_callback(HINTERNET, DWORD_PTR context, DWORD status, void* information, DWORD length) {
    if (!context) return;
    auto holder = reinterpret_cast<std::shared_ptr<AsyncState>*>(context);
    auto state = *holder;
    if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) { delete holder; return; }
    if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
        auto error = static_cast<WINHTTP_ASYNC_RESULT*>(information);
        state->error.store(error ? error->dwError : ERROR_WINHTTP_INTERNAL_ERROR);
    } else if (status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) state->read.store(length);
    else if (status == WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE)
        state->read.store(information && length == sizeof(DWORD) ? *static_cast<DWORD*>(information) : 0);
    SetEvent(state->event);
}
State error_state(DWORD error) {
    if (error == ERROR_WINHTTP_TIMEOUT) return State::Timeout;
    if (error == ERROR_WINHTTP_SECURE_FAILURE || error == ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED) return State::CertificateError;
    if (error == ERROR_WINHTTP_OPERATION_CANCELLED) return State::Cancelled;
    return State::NetworkError;
}
bool interface_available(std::uint32_t index, const SOCKADDR_STORAGE* source = nullptr) {
    if (!index) return false;
    ULONG bytes = 16384;
    std::vector<unsigned char> storage(bytes);
    auto adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    ULONG error = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                       nullptr, adapters, &bytes);
    if (error == ERROR_BUFFER_OVERFLOW && bytes <= 1048576) {
        storage.resize(bytes); adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
        error = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                     nullptr, adapters, &bytes);
    }
    if (error != NO_ERROR) return false;
    for (auto adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->IfIndex != index || adapter->OperStatus != IfOperStatusUp) continue;
        for (auto address = adapter->FirstUnicastAddress; address; address = address->Next) {
            if (!address->Address.lpSockaddr || address->Address.lpSockaddr->sa_family != AF_INET) continue;
            if (!source) return true;
            if (source->ss_family == AF_INET &&
                reinterpret_cast<const sockaddr_in*>(source)->sin_addr.s_addr ==
                reinterpret_cast<const sockaddr_in*>(address->Address.lpSockaddr)->sin_addr.s_addr) return true;
        }
    }
    return false;
}
} // namespace

Request::Request(std::string endpoint, std::string verb, std::string data)
    : url(std::move(endpoint)), method(std::move(verb)), body(std::move(data)) { wipe(data); }
Request::~Request() { wipe(body); }
Request::Request(Request&& other) noexcept : url(std::move(other.url)), method(std::move(other.method)) {
    body.swap(other.body); expected_source_ip = std::move(other.expected_source_ip);form=other.form;
}
Request& Request::operator=(Request&& other) noexcept {
    if (this != &other) { wipe(body); url = std::move(other.url); method = std::move(other.method); body.swap(other.body); expected_source_ip = std::move(other.expected_source_ip);form=other.form; }
    return *this;
}
std::optional<Target> target_from_url(std::string_view value, std::string_view user_ip, const Options& options) {
    auto parsed = url(value);
    if (!parsed || parsed->path != "/eportal/index.jsp" || !trusted(parsed->origin, options) ||
        parsed->query.empty() || !ipv4(user_ip)) return {};
    Target target{std::move(parsed->origin), std::move(parsed->query), std::string(user_ip)};
    target.protocol=options.protocol;
    return valid_target(target, options) ? std::optional<Target>(std::move(target)) : std::nullopt;
}
Discovery parse_discovery(const Response& response, std::string_view user_ip, const Options& options) {
    Discovery result;
    if (cancelled(options)) { result.state = State::Cancelled; return result; }
    if (!ipv4(user_ip)) { result.state = State::InvalidInput; return result; }
    if (response.state != State::Ready) { result.state = response.state; return result; }
    std::string candidate;
    if (response.status >= 300 && response.status < 400) candidate = response.location;
    else if (response.status == 200 && response.body.size() <= body_limit) {
        std::string_view body = response.body;
        const auto marker = body.find("location.href");
        if (marker == body.npos) return result;
        body.remove_prefix(marker + 13);
        const auto skip = [&] { while (!body.empty() && (body.front() == ' ' || body.front() == '\t' || body.front() == '\r' || body.front() == '\n')) body.remove_prefix(1); };
        skip(); if (body.empty() || body.front() != '=') return result;
        body.remove_prefix(1); skip();
        if (body.empty() || (body.front() != '\'' && body.front() != '"')) return result;
        const char delimiter = body.front(); body.remove_prefix(1);
        auto end = body.find(delimiter);
        if (end == body.npos || body.substr(0, end).find('\\') != body.npos) return result;
        candidate = body.substr(0, end);
        if (body.substr(end + 1).find("location.href") != body.npos) return result;
    } else return result;
    if (candidate.empty()) return result;
    auto parsed = url(candidate);
    if (!parsed || parsed->path != "/eportal/index.jsp" || parsed->query.empty()) return result;
    result.candidate_origin = parsed->origin;
    if (!trusted(parsed->origin, options)) { result.state = State::UntrustedTarget; return result; }
    result.target = target_from_url(candidate, user_ip, options);
    result.state = result.target ? State::Ready : State::Unsupported;
    return result;
}
Result parse_page_info(std::string_view json) {
    Result result; Json root;
    if (!Reader(json).read(root)) return result;
    if (auto status = root.string("result"); status && *status != "success") {
        result.state = State::Rejected; result.message = message(root); return result;
    }
    auto services = root.get("service");
    // The deployed browser endpoint returns {} when this school has no
    // service selector. The older DLL endpoint returns a service array.
    if (!services || (services->kind != Json::Kind::Array &&
        !(services->kind==Json::Kind::Object && services->object.empty()))) return result;
    for (const auto& item : services->array) {
        auto name = item.string("serviceName");
        if (item.kind != Json::Kind::Object || !name || name->empty() || !text(*name, 256)) return Result{};
        bool preferred = false;
        if (auto value = item.get("serviceDefault")) {
            if (value->kind != Json::Kind::String && value->kind != Json::Kind::Boolean) return Result{};
            if (value->value != "true" && value->value != "false") return Result{};
            preferred = value->value == "true";
        }
        if (std::any_of(result.services.begin(), result.services.end(), [&](const auto& s) { return s.name == *name; })) return Result{};
        result.services.push_back({std::string(*name), preferred});
    }
    if (auto encrypted=root.string("passwordEncrypt")) {
        if(*encrypted!="true" && *encrypted!="false")return Result{};
        result.password_encrypt=*encrypted=="true";
    }
    if (auto exponent=root.string("publicKeyExponent"))result.public_exponent=*exponent;
    if (auto modulus=root.string("publicKeyModulus"))result.public_modulus=*modulus;
    if (auto captcha=root.string("validCodeUrl"))result.captcha_required=!captcha->empty();
    result.state = State::Ready; return result;
}
Result parse_login(std::string_view json) { return parse_result(json, false, true); }
Result parse_online(std::string_view json) { return parse_result(json, true, false); }
Result parse_logout(std::string_view json) { return parse_result(json, false, false); }
std::optional<Request> page_info_request(const Target& target, const Options& options) {
    if (!valid_target(target, options)) return {};
    if(target.protocol==Protocol::InterFace){std::string body;form_field(body,"queryString",target.query_string,false);return form_post(target,"pageInfo",std::move(body));}
    std::string body = "{";
    field(body, "queryString", target.query_string); field(body, "userAgent", "PC"); field(body, "userip", target.user_ip);
    return post(target, "pageInfo", std::move(body));
}
std::optional<Request> login_request(const Target& target, const Credential& credential, std::string_view service, const Options& options) {
    if (!valid_target(target, options) || !text(service, 256)) return {};
    auto username = utf8(credential.username), password = utf8(credential.password);
    Wipe user_wipe{username}, pass_wipe{password};
    if (username.empty() || password.empty()) return {};
    if(target.protocol==Protocol::InterFace) {
        if(target.password_encrypt){auto encrypted=rsa_password(password,target);if(!encrypted)return {};wipe(password);password=std::move(*encrypted);}
        std::string body;body.reserve((username.size()+password.size()+target.query_string.size()+service.size())*9+256);
        form_field(body,"userId",username);form_field(body,"password",password);form_field(body,"service",service);
        form_field(body,"queryString",target.query_string);form_field(body,"operatorPwd",{});form_field(body,"operatorUserId",{});
        form_field(body,"validcode",{});form_field(body,"passwordEncrypt",target.password_encrypt?"true":"false");
        if(body.size()>body_limit)return {};return form_post(target,"login",std::move(body));
    }
    std::string body = "{";
    const auto maximum = (username.size() + password.size() + target.query_string.size() + service.size()) * 6 + 256;
    if (maximum > body_limit) return {};
    body.reserve(maximum); // Avoid reallocating/freeing credential-bearing prefixes.
    field(body, "password", password); field(body, "queryString", target.query_string);
    field(body, "service", service); field(body, "userAgent", "PC");
    field(body, "userId", username); field(body, "userip", target.user_ip);
    return post(target, "login", std::move(body));
}
std::optional<Request> online_request(const Target& target, std::string_view index, const Options& options) {
    if (!valid_target(target, options) || !text(index, 512)) return {};
    if(target.protocol==Protocol::InterFace){std::string body;form_field(body,"userIndex",index);return form_post(target,"getOnlineUserInfo",std::move(body));}
    std::string body = "{"; field(body, "userip", target.user_ip); field(body, "userIndex", index);
    return post(target, "getOnlineUserInfo", std::move(body));
}
std::optional<Request> logout_request(const Target& target, std::string_view index, const Options& options) {
    if (!valid_target(target, options) || index.empty() || !text(index, 512)) return {};
    if(target.protocol==Protocol::InterFace){std::string body;form_field(body,"userIndex",index);return form_post(target,"logout",std::move(body));}
    std::string body = "{"; field(body, "userip", target.user_ip); field(body, "userIndex", index);
    return post(target, "logout", std::move(body));
}

Response send_winhttp(const Request& request, const Options& options) {
    Response response;
    if (cancelled(options)) { response.state = State::Cancelled; return response; }
    if (options.timeout.count() <= 0 || options.timeout > std::chrono::minutes(2)) { response.state = State::InvalidInput; return response; }
    auto endpoint = url(request.url);
    if (!endpoint || (request.method != "GET" && request.method != "POST") || request.body.size() > body_limit ||
        (request.method == "GET" && !request.body.empty()) ||
        (request.method == "POST" && ((!request.form && !endpoint->query.empty()) || !trusted(endpoint->origin, options) ||
          (request.form ? (endpoint->path!="/eportal/InterFace.do" ||
             (endpoint->query!="method=pageInfo" && endpoint->query!="method=login" && endpoint->query!="method=getOnlineUserInfo" &&
              endpoint->query!="method=logout" && endpoint->query!="method=keepalive")) :
          (endpoint->path != "/eportal/inferface/authAPI/pageInfo" && endpoint->path != "/eportal/inferface/authAPI/login" &&
           endpoint->path != "/eportal/inferface/authAPI/logout" && endpoint->path != "/eportal/inferface/authAPI/getOnlineUserInfo"))))) {
        response.state = State::UntrustedTarget; return response;
    }
    if (!interface_available(options.interface_index)) { response.state = State::InterfaceUnavailable; return response; }
    const auto deadline = std::chrono::steady_clock::now() + options.timeout;
    // The school's deployed servlet returns an empty/404-shaped page for
    // unrecognized client user agents; match its Windows browser branch.
    Internet session(WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) SCAU-Link/0.12.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                                 WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC));
    const auto failed = [&](DWORD error) { response.error = error; response.state = error_state(error); };
    if (!session.handle) { failed(GetLastError()); return response; }
    DWORD affinity = options.interface_index, redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(session.handle, WINHTTP_OPTION_NETWORK_INTERFACE_AFFINITY, &affinity, sizeof(affinity))) {
        response.error = GetLastError(); response.state = State::InterfaceUnavailable; return response;
    }
    if (!WinHttpSetOption(session.handle, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect)) ||
        !WinHttpSetTimeouts(session.handle, static_cast<int>(options.timeout.count()), static_cast<int>(options.timeout.count()),
                           static_cast<int>(options.timeout.count()), static_cast<int>(options.timeout.count()))) {
        failed(GetLastError()); return response;
    }
    std::wstring hostname(endpoint->host.begin(), endpoint->host.end()),resolved;
    IN_ADDR address{};
    if(InetPtonA(AF_INET,endpoint->host.c_str(),&address)!=1) {
        const auto addresses=resolve_interface_ipv4(endpoint->host,options.interface_index,
            std::min(options.timeout,std::chrono::milliseconds(3000)),options.cancel);
        if(addresses.empty()){failed(ERROR_WINHTTP_NAME_NOT_RESOLVED);return response;}
        resolved.assign(addresses.front().begin(),addresses.front().end());
    }
    // HTTP can connect to the bound DNS answer and retain its original Host
    // header on older Windows. HTTPS keeps the hostname for SNI/cert validation.
    const auto& connect_host=!endpoint->secure && !resolved.empty()?resolved:hostname;
    Internet connection(WinHttpConnect(session.handle, connect_host.c_str(), endpoint->port, 0));
    if (!connection.handle) { failed(GetLastError()); return response; }
    std::string object = endpoint->path;
    if (!endpoint->query.empty()) object += '?' + endpoint->query;
    std::wstring path(object.begin(), object.end()), method(request.method.begin(), request.method.end());
    Internet handle(WinHttpOpenRequest(connection.handle, method.c_str(), path.c_str(), nullptr,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      endpoint->secure ? WINHTTP_FLAG_SECURE : 0));
    if (!handle.handle) { failed(GetLastError()); return response; }
    if(endpoint->secure && !resolved.empty()) {
        if(!WinHttpSetOption(handle.handle,WINHTTP_OPTION_RESOLUTION_HOSTNAME,resolved.data(),DWORD((resolved.size()+1)*sizeof(wchar_t)))){
            failed(GetLastError());return response;
        }
    }
    if(!endpoint->secure && !resolved.empty()) {
        const auto header=L"Host: "+hostname+(endpoint->port==80?L"":L":"+std::to_wstring(endpoint->port))+L"\r\n";
        if(!WinHttpAddRequestHeaders(handle.handle,header.c_str(),DWORD(-1),WINHTTP_ADDREQ_FLAG_ADD|WINHTTP_ADDREQ_FLAG_REPLACE)) {
            failed(GetLastError());return response;
        }
    }
    DWORD features = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    DWORD auto_logon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
    if (!WinHttpSetOption(handle.handle, WINHTTP_OPTION_DISABLE_FEATURE, &features, sizeof(features)) ||
        !WinHttpSetOption(handle.handle, WINHTTP_OPTION_AUTOLOGON_POLICY, &auto_logon, sizeof(auto_logon))) {
        failed(GetLastError()); return response;
    }
    auto state = std::make_shared<AsyncState>();
    if (!state->event) { failed(GetLastError()); return response; }
    state->body = request.body;
    auto holder = std::make_unique<std::shared_ptr<AsyncState>>(state);
    DWORD_PTR context = reinterpret_cast<DWORD_PTR>(holder.get());
    if (!WinHttpSetOption(handle.handle, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context))) { failed(GetLastError()); return response; }
    if (WinHttpSetStatusCallback(handle.handle, status_callback,
            WINHTTP_CALLBACK_FLAG_SENDREQUEST_COMPLETE | WINHTTP_CALLBACK_FLAG_HEADERS_AVAILABLE |
            WINHTTP_CALLBACK_FLAG_READ_COMPLETE | WINHTTP_CALLBACK_FLAG_WRITE_COMPLETE |
            WINHTTP_CALLBACK_FLAG_REQUEST_ERROR | WINHTTP_CALLBACK_FLAG_HANDLES, 0)
            == WINHTTP_INVALID_STATUS_CALLBACK) { failed(GetLastError()); return response; }
    holder.release(); // Released by the final HANDLE_CLOSING callback, even on cancellation.
    const auto wait = [&]() {
        for (;;) {
            if (cancelled(options)) { response.state = State::Cancelled; return false; }
            if (std::chrono::steady_clock::now() >= deadline) { response.state = State::Timeout; return false; }
            const DWORD waited = WaitForSingleObject(state->event, 15);
            if (waited == WAIT_OBJECT_0) {
                if (DWORD error = state->error.load()) { failed(error); return false; }
                return true;
            }
            if (waited != WAIT_TIMEOUT) { failed(GetLastError()); return false; }
        }
    };
    const wchar_t* headers = request.method == "POST" ? request.form
        ? L"Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
        : L"Accept: application/json\r\nContent-Type: application/json\r\n" : L"Accept: text/html\r\n";
    // Send headers before the credential-bearing body. Verify the actual local
    // socket address belongs to the selected adapter before writing any body.
    if (!WinHttpSendRequest(handle.handle, headers, static_cast<DWORD>(-1), nullptr, 0,
                            static_cast<DWORD>(state->body.size()), context)) {
        const DWORD error = GetLastError(); if (error != ERROR_IO_PENDING) { failed(error); return response; }
    }
    if (!wait()) return response;
    WINHTTP_CONNECTION_INFO connection_info{};
    DWORD bytes = sizeof(connection_info);
    if (!WinHttpQueryOption(handle.handle, WINHTTP_OPTION_CONNECTION_INFO, &connection_info, &bytes) ||
        !interface_available(options.interface_index, &connection_info.LocalAddress)) {
        response.error = GetLastError(); response.state = State::InterfaceUnavailable; return response;
    }
    if (!request.expected_source_ip.empty()) {
        const auto raw = reinterpret_cast<const unsigned char*>(
            &reinterpret_cast<const sockaddr_in*>(&connection_info.LocalAddress)->sin_addr.s_addr);
        const auto actual_ip = std::to_string(raw[0]) + '.' + std::to_string(raw[1]) + '.' +
            std::to_string(raw[2]) + '.' + std::to_string(raw[3]);
        if (actual_ip != request.expected_source_ip) { response.state = State::InterfaceUnavailable; return response; }
    }
    if (!state->body.empty()) {
        if (!WinHttpWriteData(handle.handle, state->body.data(), static_cast<DWORD>(state->body.size()), nullptr)) {
            const DWORD error = GetLastError(); if (error != ERROR_IO_PENDING) { failed(error); return response; }
        }
        if (!wait()) return response;
        if (state->read.load() != state->body.size()) { response.state = State::NetworkError; return response; }
    }
    if (!WinHttpReceiveResponse(handle.handle, nullptr)) {
        const DWORD error = GetLastError(); if (error != ERROR_IO_PENDING) { failed(error); return response; }
    }
    if (!wait()) return response;
    DWORD status{}; bytes = sizeof(status);
    if (!WinHttpQueryHeaders(handle.handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                             &status, &bytes, WINHTTP_NO_HEADER_INDEX)) { failed(GetLastError()); return response; }
    response.status = status;
    bytes = 0;
    WinHttpQueryHeaders(handle.handle, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &bytes, WINHTTP_NO_HEADER_INDEX);
    if (bytes > 0 && bytes <= (query_limit + 1024) * sizeof(wchar_t)) {
        std::wstring location(bytes / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(handle.handle, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                               location.data(), &bytes, WINHTTP_NO_HEADER_INDEX)) {
            location.resize(wcsnlen(location.data(), location.size())); response.location = utf8(location);
        }
    }
    for (;;) {
        state->read.store(0);
        if (!WinHttpReadData(handle.handle, state->buffer.data(), static_cast<DWORD>(state->buffer.size()), nullptr)) {
            const DWORD error = GetLastError(); if (error != ERROR_IO_PENDING) { failed(error); return response; }
        }
        if (!wait()) return response;
        const auto read = state->read.load();
        if (!read) break;
        if (response.body.size() + read > body_limit) { response.state = State::InvalidResponse; wipe(response.body); return response; }
        response.body.append(state->buffer.data(), read);
    }
    response.state = State::Ready; return response;
}
Discovery discover(std::string_view probe, std::string_view user_ip, const Options& options, Transport sender) {
    if (cancelled(options)) return {State::Cancelled, {}};
    auto parsed = url(probe);
    if (!parsed || parsed->secure || !parsed->query.empty() || !ipv4(user_ip)) return {State::InvalidInput, {}};
    Request request(std::string(probe), "GET", {});
    request.expected_source_ip = user_ip;
    Response response = sender ? sender(request, options) : send_winhttp(request, options);
    Wipe response_wipe{response.body};
    return parse_discovery(response, user_ip, options);
}
Result page_info(const Target& target, const Options& options, Transport sender) {
    if (!trusted(target.origin, options)) return fail(State::UntrustedTarget);
    return exchange(page_info_request(target, options), options, std::move(sender), parse_page_info);
}
Result login(const Target& target, const Credential& credential, std::string_view service, const Options& options, Transport sender) {
    if (!trusted(target.origin, options)) return fail(State::UntrustedTarget);
    auto result = exchange(login_request(target, credential, service, options), options, std::move(sender), parse_login);
    auto username = utf8(credential.username), password = utf8(credential.password);
    Wipe user_wipe{username}, pass_wipe{password};
    redact(result.message, password); redact(result.message, username);
    if (result.message.size() > 768) {
        std::size_t end = 768;
        while (end && (static_cast<unsigned char>(result.message[end]) & 0xc0) == 0x80) --end;
        result.message.resize(end);
    }
    return result;
}
Result online(const Target& target, std::string_view index, const Options& options, Transport sender) {
    if (!trusted(target.origin, options)) return fail(State::UntrustedTarget);
    return exchange(online_request(target, index, options), options, std::move(sender), parse_online);
}
Result logout(const Target& target, std::string_view index, const Options& options, Transport sender) {
    if (!trusted(target.origin, options)) return fail(State::UntrustedTarget);
    return exchange(logout_request(target, index, options), options, std::move(sender), parse_logout);
}
Result keepalive(const Target& target,std::string_view index,const Options& options,Transport sender) {
    if(target.protocol!=Protocol::InterFace || !valid_target(target,options) || index.empty() || !text(index,512))return fail(State::InvalidInput);
    std::string body;form_field(body,"userIndex",index);
    return exchange(std::optional<Request>(form_post(target,"keepalive",std::move(body))),options,std::move(sender),parse_online);
}
std::vector<std::string> school_portal_origins(){return {"http://192.168.253.3","http://192.168.253.3:8080"};}
State internet_available(std::string_view user_ip,const Options& options,Transport sender) {
    if(!ipv4(user_ip))return State::InvalidInput;
    State result=State::Unsupported;
    bool legacy_resolver=false;
    for(const auto* endpoint:{"https://cp.cloudflare.com/generate_204",
                             "https://connectivitycheck.platform.hicloud.com/generate_204"}) {
        if(cancelled(options))return State::Cancelled;
        Request request(endpoint,"GET",{});request.expected_source_ip=user_ip;
        auto response=sender?sender(request,options):send_winhttp(request,options);
        legacy_resolver=legacy_resolver || response.error==ERROR_WINHTTP_INVALID_OPTION || response.error==ERROR_INVALID_PARAMETER;
        Wipe wipe{response.body};
        if(response.state==State::Ready && response.status==204 && response.body.empty())return State::Success;
        result=response.state==State::Ready?State::Unsupported:response.state;
    }
    if(legacy_resolver && !cancelled(options)) {
        // Older WinHTTP lacks the HTTPS DNS override option. NCSI is only a
        // network-availability fallback; it never authenticates an account.
        Request request("http://www.msftconnecttest.com/connecttest.txt","GET",{});request.expected_source_ip=user_ip;
        auto response=sender?sender(request,options):send_winhttp(request,options);Wipe wipe{response.body};
        if(response.state==State::Ready && response.status==200 && response.body=="Microsoft Connect Test")return State::Success;
    }
    return result;
}
} // namespace scau::desktop::portal
