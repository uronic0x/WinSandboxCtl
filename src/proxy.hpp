#pragma once
// Explicit HTTPS CONNECT proxy. This is NOT transparent network enforcement.
// Hostname/port allowlist + DNS address validation + bounded connections.
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include "core.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

namespace sa::net {
#ifdef _WIN32
using socket_type = SOCKET;
constexpr socket_type bad_socket = INVALID_SOCKET;
inline void close_socket(socket_type s) { closesocket(s); }
#else
using socket_type = int;
constexpr socket_type bad_socket = -1;
inline void close_socket(socket_type s) { close(s); }
#endif
struct Socket {
    socket_type value = bad_socket;
    explicit Socket(socket_type s = bad_socket) : value(s) {}
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& s) noexcept : value(s.value) { s.value = bad_socket; }
    Socket& operator=(Socket&& s) noexcept {
        if (this != &s) { if (value != bad_socket) close_socket(value); value = s.value; s.value = bad_socket; }
        return *this;
    }
    ~Socket() { if (value != bad_socket) close_socket(value); }
};
struct Startup {
    Startup() {
#ifdef _WIN32
        WSADATA data{};
        require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "WSAStartup failed.");
#endif
    }
    ~Startup() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};
inline bool send_all(socket_type s, const char* data, std::size_t size) {
    while (size) {
#ifdef _WIN32
        int n = send(s, data, static_cast<int>(size), 0);
#else
        int n = static_cast<int>(send(s, data, size, MSG_NOSIGNAL));
#endif
        if (n <= 0) return false;
        data += n; size -= static_cast<std::size_t>(n);
    }
    return true;
}
inline void timeout(socket_type s) {
#ifdef _WIN32
    DWORD ms = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
#else
    timeval tv{10, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}
inline bool public_v4(std::uint32_t ip) {
    auto a = ip >> 24, b = (ip >> 16) & 255, c = (ip >> 8) & 255;
    if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
    if (a == 100 && b >= 64 && b <= 127) return false;
    if (a == 169 && b == 254) return false;
    if (a == 172 && b >= 16 && b <= 31) return false;
    if (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99))) return false;
    if (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100))) return false;
    if (a == 203 && b == 0 && c == 113) return false;
    return true;
}
inline bool public_address(const sockaddr* addr) {
    if (addr->sa_family == AF_INET)
        return public_v4(ntohl(reinterpret_cast<const sockaddr_in*>(addr)->sin_addr.s_addr));
    if (addr->sa_family != AF_INET6) return false;
    const auto* bytes = reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr);
    // Accept only native global unicast 2000::/3, excluding special/documentation/tunnel prefixes.
    if ((bytes[0] & 0xe0) != 0x20) return false;
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && (bytes[2] < 2 || (bytes[2] == 0x0d && bytes[3] == 0xb8))) return false;
    if (bytes[0] == 0x20 && bytes[1] == 0x02) return false; // 6to4 can encode private IPv4.
    if (bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0) return false;
    return true;
}
inline std::string ascii_lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return s;
}
inline bool hostname(const std::string& host) {
    if (host.empty() || host.size() > 253 || host.back() == '.') return false;
    std::size_t start = 0;
    while (start < host.size()) {
        auto end = host.find('.', start);
        auto label = host.substr(start, end == host.npos ? host.npos : end - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        for (char c : label) if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
        if (end == host.npos) return true;
        start = end + 1;
    }
    return false;
}
inline bool allowed_host(const std::string& host, const std::vector<std::string>& patterns) {
    for (const auto& pattern : patterns) {
        if (pattern.compare(0, 2, "*.") == 0) {
            auto suffix = pattern.substr(1);
            if (host.size() > suffix.size() && host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0) return true;
        } else if (pattern == host) return true;
    }
    return false;
}
struct Cidr {
    std::uint32_t network = 0, mask = 0;
    bool accepts(std::uint32_t ip) const { return (ip & mask) == network; }
};
inline Cidr cidr(const std::wstring& value) {
    auto slash = value.find(L'/');
    require(slash != value.npos, "--clients must use IPv4 CIDR syntax.");
    auto prefix = integer(value.substr(slash + 1), 1, 32);
    in_addr ip{};
    require(inet_pton(AF_INET, utf8(value.substr(0, slash)).c_str(), &ip) == 1, "Invalid IPv4 client CIDR.");
    Cidr out;
    out.mask = 0xffffffffu << (32 - prefix);
    out.network = ntohl(ip.s_addr) & out.mask;
    return out;
}
struct ProxyOptions {
    std::string listen = "127.0.0.1";
    std::uint16_t port = 18080;
    Cidr clients{0x7f000000u, 0xff000000u};
    std::vector<std::string> hosts;
    std::set<std::uint16_t> ports{443};
    bool private_upstream = false;
    bool allow_all = false;
};
inline ProxyOptions parse_proxy(const std::vector<std::wstring>& argv) {
    ProxyOptions o;
    bool explicit_clients = false;
    std::set<std::wstring> seen;
    for (std::size_t i = 0; i < argv.size(); ++i) {
        auto key = argv[i];
        require(key == L"--allow" || seen.insert(key).second, "Duplicate proxy option.");
        if (key == L"--allow-all") { o.allow_all = true; continue; }
        if (key == L"--allow-private-upstream") { o.private_upstream = true; continue; }
        require(i + 1 < argv.size(), "Proxy option needs a value.");
        auto value = argv[++i];
        if (key == L"--listen") o.listen = utf8(value);
        else if (key == L"--port") o.port = static_cast<std::uint16_t>(integer(value, 1, 65535));
        else if (key == L"--clients") { o.clients = cidr(value); explicit_clients = true; }
        else if (key == L"--allow") {
            auto host = ascii_lower(utf8(value));
            require(hostname(host.compare(0, 2, "*.") == 0 ? host.substr(2) : host), "Invalid allowlist hostname.");
            o.hosts.push_back(host);
        } else if (key == L"--ports") {
            o.ports.clear();
            std::size_t start = 0;
            do {
                auto end = value.find(L',', start);
                o.ports.insert(static_cast<std::uint16_t>(integer(value.substr(start, end == value.npos ? value.npos : end - start), 1, 65535)));
                if (end == value.npos) break;
                start = end + 1;
            } while (true);
        } else throw std::runtime_error("Unknown proxy option.");
    }
    in_addr address{};
    require(inet_pton(AF_INET, o.listen.c_str(), &address) == 1 && o.listen != "0.0.0.0", "Bind to a specific local IPv4 address.");
    require(o.listen.compare(0, 4, "127.") == 0 || explicit_clients, "Remote proxy binding requires explicit --clients CIDR.");
    require(o.allow_all || !o.hosts.empty(), "Proxy requires at least one --allow domain (or --allow-all).");
    require(!(o.allow_all && !o.hosts.empty()), "--allow-all cannot be combined with --allow domains.");
    return o;
}
inline Socket upstream(const std::string& host, std::uint16_t port, bool allow_private) {
    addrinfo hints{}, *raw = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICSERV;
    require(getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &raw) == 0, "DNS resolution failed.");
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(raw, freeaddrinfo);
    for (auto* p = raw; p; p = p->ai_next)
        require(allow_private || public_address(p->ai_addr), "Upstream resolves to a non-public address.");
    for (auto* p = raw; p; p = p->ai_next) {
        Socket s(socket(p->ai_family, p->ai_socktype, p->ai_protocol));
        if (s.value == bad_socket) continue;
        timeout(s.value);
#ifdef _WIN32
        u_long blocking = 1;
        if (ioctlsocket(s.value, FIONBIO, &blocking) != 0) continue;
#else
        if (fcntl(s.value, F_SETFL, O_NONBLOCK) < 0) continue;
#endif
        int connected = connect(s.value, p->ai_addr, static_cast<int>(p->ai_addrlen));
        if (connected != 0) {
            fd_set writes, errors; FD_ZERO(&writes); FD_ZERO(&errors);
            FD_SET(s.value, &writes); FD_SET(s.value, &errors);
            timeval wait{5, 0};
            if (select(static_cast<int>(s.value + 1), nullptr, &writes, &errors, &wait) <= 0 || FD_ISSET(s.value, &errors)) continue;
            int error = 0;
#ifdef _WIN32
            int length = sizeof(error);
            if (getsockopt(s.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) != 0 || error) continue;
            blocking = 0; if (ioctlsocket(s.value, FIONBIO, &blocking) != 0) continue;
#else
            socklen_t length = sizeof(error);
            if (getsockopt(s.value, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error) continue;
            if (fcntl(s.value, F_SETFL, 0) < 0) continue;
#endif
        } else {
#ifdef _WIN32
            blocking = 0; if (ioctlsocket(s.value, FIONBIO, &blocking) != 0) continue;
#else
            if (fcntl(s.value, F_SETFL, 0) < 0) continue;
#endif
        }
        return s; // Uses the already validated sockaddr; no second DNS lookup.
    }
    throw std::runtime_error("Upstream connection failed.");
}
inline void response(socket_type client, const char* status) {
    auto message = std::string("HTTP/1.1 ") + status + "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    send_all(client, message.data(), message.size());
}
struct Request { std::string host; std::uint16_t port; };
inline Request connect_request(const std::string& header) {
    require(header.size() <= 8192 && header.size() >= 4 && header.substr(header.size() - 4) == "\r\n\r\n", "Invalid proxy header.");
    auto end = header.find("\r\n");
    auto line = header.substr(0, end);
    auto space = line.find(' '), last = line.rfind(' ');
    require(space != line.npos && space != last && line.substr(0, space) == "CONNECT", "Only HTTPS CONNECT is supported.");
    auto version = line.substr(last + 1);
    require(version == "HTTP/1.0" || version == "HTTP/1.1", "Invalid proxy HTTP version.");
    auto authority = line.substr(space + 1, last - space - 1);
    auto colon = authority.find(':');
    require(colon != authority.npos && authority.find(':', colon + 1) == authority.npos, "Expected hostname:port (IPv6 literals unsupported).");
    auto host = ascii_lower(authority.substr(0, colon));
    require(hostname(host), "Invalid CONNECT hostname.");
    auto port = static_cast<std::uint16_t>(integer(wide(authority.substr(colon + 1)), 1, 65535));
    for (std::size_t i = 0; i < header.size(); ++i) {
        auto c = static_cast<unsigned char>(header[i]);
        if (c == '\r') require(i + 1 < header.size() && header[i + 1] == '\n', "Invalid CR in header.");
        else if (c == '\n') require(i != 0 && header[i - 1] == '\r', "Invalid LF in header.");
        else require(c == '\t' || (c >= 32 && c < 127), "Non-ASCII/control byte in proxy header.");
    }
    return {host, port};
}
inline std::pair<std::uint64_t, std::uint64_t> relay(socket_type client, socket_type remote) {
    std::array<char, 16384> buffer{};
    std::uint64_t upload = 0, download = 0;
    bool client_open = true, remote_open = true;
    while (client_open || remote_open) {
        fd_set reads; FD_ZERO(&reads);
        if (client_open) FD_SET(client, &reads);
        if (remote_open) FD_SET(remote, &reads);
        timeval idle{60, 0};
        if (select(static_cast<int>(std::max(client, remote) + 1), &reads, nullptr, nullptr, &idle) <= 0) break;
        for (int direction = 0; direction < 2; ++direction) {
            auto source = direction == 0 ? client : remote, dest = direction == 0 ? remote : client;
            auto& open = direction == 0 ? client_open : remote_open;
            if (!open || !FD_ISSET(source, &reads)) continue;
            int n = static_cast<int>(recv(source, buffer.data(), static_cast<int>(buffer.size()), 0));
            if (n <= 0) {
                open = false;
#ifdef _WIN32
                shutdown(dest, SD_SEND);
#else
                shutdown(dest, SHUT_WR);
#endif
            } else {
                if (!send_all(dest, buffer.data(), static_cast<std::size_t>(n))) return {upload, download};
                (direction == 0 ? upload : download) += static_cast<std::uint64_t>(n);
            }
        }
    }
    return {upload, download};
}
inline std::mutex& log_mutex() { static std::mutex m; return m; }
inline void log(const std::string& s) {
    std::lock_guard<std::mutex> lock(log_mutex());
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char ts[20];
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    std::cout << '[' << ts << "] " << s << std::endl;
}
inline void serve_client(Socket client, std::shared_ptr<const ProxyOptions> options, std::shared_ptr<std::atomic<int>> active) {
    struct Counter { std::shared_ptr<std::atomic<int>> n; ~Counter() { --*n; } } counter{active};
    try {
        timeout(client.value);
        std::string header;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while (header.size() < 8192 && (header.size() < 4 || header.substr(header.size() - 4) != "\r\n\r\n")) {
            require(std::chrono::steady_clock::now() < deadline, "Header deadline exceeded.");
            char c;
            require(recv(client.value, &c, 1, 0) == 1, "Header read failed/timeout.");
            header += c;
        }
        Request r;
        try { r = connect_request(header); }
        catch (...) { response(client.value, "400 Bad Request"); return; }
        if ((!options->allow_all && !allowed_host(r.host, options->hosts)) || !options->ports.count(r.port)) {
            response(client.value, "403 Forbidden"); log("DENY " + r.host + ":" + std::to_string(r.port)); return;
        }
        Socket remote;
        try { remote = upstream(r.host, r.port, options->private_upstream); }
        catch (...) { response(client.value, "502 Bad Gateway"); log("DENY_OR_UNREACHABLE " + r.host); return; }
        const std::string established = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (!send_all(client.value, established.data(), established.size())) return;
        auto bytes = relay(client.value, remote.value);
        log("ALLOW " + r.host + ":" + std::to_string(r.port) + " upload=" + std::to_string(bytes.first) + " download=" + std::to_string(bytes.second));
    } catch (...) { /* Network peer failure ends this connection only. */ }
}
inline int proxy_main(const std::vector<std::wstring>& argv) {
    Startup startup;
    auto options = std::make_shared<const ProxyOptions>(parse_proxy(argv));
    Socket listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    require(listener.value != bad_socket, "Cannot create proxy listener.");
    int reuse = 1;
#ifdef _WIN32
    require(setsockopt(listener.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&reuse), sizeof(reuse)) == 0,
            "Cannot set exclusive proxy listener.");
#else
    setsockopt(listener.value, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(options->port);
    require(inet_pton(AF_INET, options->listen.c_str(), &address.sin_addr) == 1, "Invalid listener address.");
    require(bind(listener.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "Cannot bind proxy address/port.");
    require(listen(listener.value, 16) == 0, "Cannot listen on proxy socket.");
    log("READY explicit CONNECT proxy " + options->listen + ":" + std::to_string(options->port));
    log(options->allow_all ? "ALLOW-ALL mode: domain allowlist is bypassed. Private/loopback upstreams and port policy still apply."
                           : "Policy applies only to connections using this proxy. Ctrl+C stops it. No firewall rules are installed.");
    auto active = std::make_shared<std::atomic<int>>(0);
    for (;;) {
        sockaddr_in peer{};
#ifdef _WIN32
        int length = sizeof(peer);
#else
        socklen_t length = sizeof(peer);
#endif
        Socket client(accept(listener.value, reinterpret_cast<sockaddr*>(&peer), &length));
        if (client.value == bad_socket) throw std::runtime_error("Proxy accept failed.");
        if (!options->clients.accepts(ntohl(peer.sin_addr.s_addr)) || active->load() >= 16) { response(client.value, "403 Forbidden"); continue; }
        ++*active;
        try { std::thread(serve_client, std::move(client), options, active).detach(); }
        catch (...) { --*active; throw; }
    }
}
} // namespace sa::net
