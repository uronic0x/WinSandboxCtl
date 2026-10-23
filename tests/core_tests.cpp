#include "../src/proxy.hpp"
#include <functional>
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

namespace {
void check(bool value, const char* name) { if (!value) throw std::runtime_error(name); }
void rejects(const std::function<void()>& f) { bool failed = false; try { f(); } catch (const std::exception&) { failed = true; } check(failed, "Expected rejection"); }
// Independent inverse of the CRT quoting transformation for round-trip tests.
std::vector<std::wstring> split_crt(const std::wstring& command) {
    std::vector<std::wstring> out;
    std::size_t i = 0;
    while (i < command.size()) {
        while (i < command.size() && (command[i] == L' ' || command[i] == L'\t')) ++i;
        if (i == command.size()) break;
        std::wstring token;
        bool quoted = false;
        while (i < command.size()) {
            if (!quoted && (command[i] == L' ' || command[i] == L'\t')) break;
            std::size_t slashes = 0;
            while (i < command.size() && command[i] == L'\\') { ++slashes; ++i; }
            if (i < command.size() && command[i] == L'"') {
                token.append(slashes / 2, L'\\');
                if (slashes % 2) token += L'"'; else quoted = !quoted;
                ++i;
            } else {
                token.append(slashes, L'\\');
                if (i < command.size() && (quoted || (command[i] != L' ' && command[i] != L'\t'))) token += command[i++];
            }
        }
        check(!quoted, "Unclosed quote");
        out.push_back(token);
    }
    return out;
}
}
int main() {
    try {
        sa::net::Startup sockets;
        for (const auto& value : {L"..\\escape.exe", L"C:\\a.exe", L"\\\\server\\a", L"a\\..\\x", L"a//b", L"a:stream", L"CON.txt", L"aux", L"LPT9.dat", L"COM\u00b9", L"bad.\\x", L"bad ", L"x\n", L"a?b"})
            rejects([&] { sa::relative(value); });
        check(sa::relative(L"\u4e2d\u6587 app/sub.exe") == L"\u4e2d\u6587 app\\sub.exe", "Unicode path");
        std::vector<std::wstring> strings{L"", L"plain", L"a b", L"\"", L"\\", L"C:\\a b\\", L"\\\\\"x", L"& calc.exe", L"%PATH%", L"\u4e2d\u6587", L"x\ty"};
        check(split_crt(sa::arguments(strings)) == strings, "Argument round trip");
        // Enumerate short combinations of whitespace, quotes, and backslashes.
        const std::wstring alphabet = L"a \\\"";
        std::vector<std::wstring> cases{L""};
        for (int length = 0; length < 6; ++length) {
            auto previous = cases;
            for (const auto& prefix : previous) if (prefix.size() == static_cast<std::size_t>(length))
                for (auto c : alphabet) cases.push_back(prefix + c);
        }
        for (const auto& s : cases) {
            check(split_crt(sa::quote(s)) == std::vector<std::wstring>{s}, "Enumerated argument round trip");
#ifdef _WIN32
            int count = 0;
            auto native = CommandLineToArgvW((L"dummy.exe " + sa::quote(s)).c_str(), &count);
            check(native != nullptr, "CommandLineToArgvW failed");
            const bool same = count == 2 && std::wstring(native[1]) == s;
            LocalFree(native);
            check(same, "Windows native argument round trip");
#endif
        }
        check(sa::json(L"a\"\\\n") == "\"a\\\"\\\\\\u000a\"", "JSON escape");
        check(sa::xml(L"a&<>\"'") == L"a&amp;&lt;&gt;&quot;&apos;", "XML escape");
        for (const auto& n : {L"", L"-1", L"0", L"65536", L"1x", L"99999999999999999999"})
            rejects([&] { sa::integer(n, 1, 65535); });
        rejects([] { sa::parse({L"run", L"--app", L"x.exe", L"--network", L"proxy"}); });
        rejects([] { sa::parse({L"run", L"--app", L"x.exe", L"--appdata", L"App", L"--data", L"read"}); });
        rejects([] { sa::parse({L"prepare", L"--app", L"x.cmd"}); });
        rejects([] { sa::parse({L"prepare", L"--app", std::wstring(187, L'a') + L".exe"}); });
        rejects([] { sa::parse({L"run", L"--app", L"x.exe", L"--network", L"direct", L"--network", L"off"}); });
        rejects([] { sa::proxy_address(L"127.0.0.1:18080"); });
        rejects([] { sa::proxy_address(L"1.2.3.4.5:443"); });
        sa::proxy_address(L"172.20.0.1:18080");
        auto defaults = sa::parse({L"prepare", L"--app", L"x.exe"});
        check(defaults.network == L"off" && defaults.protected_client, "Safe defaults");
        auto config = sa::wsb(defaults, sa::path(L"C:/a&b"), sa::path(L"C:/input"), sa::path(L"C:/data"));
        check(config.find("a&amp;b") != std::string::npos && config.find("<Networking>Disable</Networking>") != std::string::npos, "WSB escaping/default");
        check(sa::net::allowed_host("x.example.com", {"*.example.com"}), "Wildcard subdomain");
        check(!sa::net::allowed_host("example.com", {"*.example.com"}) && !sa::net::allowed_host("badexample.com", {"*.example.com"}), "Wildcard boundary");
        for (const auto& h : {"", "a..b", "a.", "a@b", "a/b", "-x.com"}) check(!sa::net::hostname(h), "Invalid hostname");
        for (auto ip : {0x00000000u, 0x0a000001u, 0x7f000001u, 0xa9fe0001u, 0xac100001u, 0xc0a80001u, 0x64400001u, 0xe0000001u})
            check(!sa::net::public_v4(ip), "Private address denied");
        check(sa::net::public_v4(0x08080808u), "Public address classification");
        auto client_range = sa::net::cidr(L"172.20.0.0/16");
        check(client_range.accepts(0xac140002u) && !client_range.accepts(0xac150001u), "Client CIDR");
        rejects([] { sa::net::parse_proxy({L"--listen", L"172.20.0.1", L"--allow", L"example.com"}); });
        auto request = sa::net::connect_request("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        check(request.host == "example.com" && request.port == 443, "CONNECT parse");
        for (const auto& bad : {"GET http://example.com HTTP/1.1\r\n\r\n", "CONNECT example.com:0 HTTP/1.1\r\n\r\n", "CONNECT example.com:443 HTTP/2\r\n\r\n", "CONNECT example.com:443 HTTP/1.1\nX: a\r\n\r\n"})
            rejects([&] { sa::net::connect_request(bad); });
        std::cout << "PASS core tests; argument cases=" << cases.size() << '\n';
        return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
