#pragma once
// WinSandboxCtl: configuration/argument code. No target code runs in the host.
#include <algorithm>
#include <cctype>
#include <codecvt>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace sa {
namespace fs = std::filesystem;
inline void require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
inline std::string utf8(const std::wstring& s) {
#ifdef _WIN32
    return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().to_bytes(s);
#else
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(s);
#endif
}
inline std::wstring wide(const std::string& s) {
#ifdef _WIN32
    return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(s);
#else
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(s);
#endif
}
inline fs::path path(const std::wstring& s) {
#ifdef _WIN32
    return fs::path(s);
#else
    return fs::u8path(utf8(s));
#endif
}
inline std::wstring text(const fs::path& p) {
#ifdef _WIN32
    return p.wstring();
#else
    return wide(p.u8string());
#endif
}
inline std::wstring lower(std::wstring s) {
    for (auto& c : s) if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
    return s;
}
inline void validate_text(const std::wstring& s) {
    for (wchar_t c : s) require(c >= 32 && c != 127, "Control characters are not allowed.");
}
inline std::wstring relative(const std::wstring& value) {
    require(!value.empty() && value.size() < 220, "Expected a short relative Windows path.");
    std::wstring s = value;
    std::replace(s.begin(), s.end(), L'/', L'\\');
    require(s.front() != L'\\', "Absolute/UNC paths are not allowed here.");
    std::size_t start = 0;
    while (start <= s.size()) {
        auto end = s.find(L'\\', start);
        auto component = s.substr(start, end == s.npos ? s.npos : end - start);
        require(!component.empty() && component != L"." && component != L"..", "Empty/dot path components are not allowed.");
        require(component.back() != L'.' && component.back() != L' ', "Trailing dots/spaces are not allowed.");
        for (auto c : component)
            require(c >= 32 && c != 127 && std::wstring(L"<>:\"|?*").find(c) == s.npos,
                    "Invalid Windows path character.");
        auto stem = lower(component.substr(0, component.find(L'.')));
        require(stem != L"con" && stem != L"prn" && stem != L"aux" && stem != L"nul" && stem != L"clock$",
                "Reserved Windows device name.");
        if (stem.size() == 4 && (stem.substr(0, 3) == L"com" || stem.substr(0, 3) == L"lpt"))
            require(std::wstring(L"123456789\u00b9\u00b2\u00b3").find(stem[3]) == s.npos, "Reserved Windows device name.");
        if (end == s.npos) break;
        start = end + 1;
    }
    return s;
}
inline void box_name(const std::wstring& s) {
    require(!s.empty() && s.size() <= 48, "Box name must contain 1..48 ASCII characters.");
    for (auto c : s) require((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
        (c >= L'0' && c <= L'9') || c == L'-' || c == L'_', "Box name permits letters, digits, - and _ only.");
    relative(s);
}
inline std::uint32_t integer(const std::wstring& s, std::uint32_t low, std::uint32_t high) {
    require(!s.empty(), "Missing integer.");
    std::uint64_t value = 0;
    for (auto c : s) {
        require(c >= L'0' && c <= L'9', "Expected decimal integer.");
        value = value * 10 + (c - L'0');
        require(value <= high, "Integer exceeds supported range.");
    }
    require(value >= low, "Integer below supported range.");
    return static_cast<std::uint32_t>(value);
}
// Microsoft CRT command-line quoting. Arguments are never sent through cmd.exe.
inline std::wstring quote(const std::wstring& s) {
    std::wstring out = L"\"";
    std::size_t backslashes = 0;
    for (auto c : s) {
        require(c != 0, "NUL is not a valid process argument.");
        if (c == L'\\') { ++backslashes; continue; }
        if (c == L'\"') out.append(backslashes * 2 + 1, L'\\');
        else out.append(backslashes, L'\\');
        out += c;
        backslashes = 0;
    }
    out.append(backslashes * 2, L'\\');
    return out + L"\"";
}
inline std::wstring arguments(const std::vector<std::wstring>& args) {
    std::wstring out;
    for (const auto& a : args) { if (!out.empty()) out += L' '; out += quote(a); }
    require(out.size() < 24000, "Target command line is too long.");
    return out;
}
inline std::string json(const std::wstring& value) {
    auto s = utf8(value);
    std::string out = "\"";
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 32) { out += "\\u00"; out += digits[c >> 4]; out += digits[c & 15]; }
        else out += static_cast<char>(c);
    }
    return out + '"';
}
inline std::wstring xml(const std::wstring& s) {
    validate_text(s);
    std::wstring out;
    for (auto c : s) switch (c) {
        case L'&': out += L"&amp;"; break;
        case L'<': out += L"&lt;"; break;
        case L'>': out += L"&gt;"; break;
        case L'"': out += L"&quot;"; break;
        case L'\'': out += L"&apos;"; break;
        default: out += c;
    }
    return out;
}
inline void write(const fs::path& destination, const std::string& contents) {
    std::ofstream stream(destination, std::ios::binary | std::ios::trunc);
    require(static_cast<bool>(stream), "Cannot create output file.");
    stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    stream.close();
    require(static_cast<bool>(stream), "Cannot finish output file.");
}
inline std::string read(const fs::path& source, std::size_t limit = 1024 * 1024) {
    std::ifstream stream(source, std::ios::binary);
    require(static_cast<bool>(stream), "Cannot open file.");
    std::string s;
    char buffer[4096];
    while (stream.read(buffer, sizeof(buffer)) || stream.gcount()) {
        auto n = static_cast<std::size_t>(stream.gcount());
        require(s.size() + n <= limit, "Input file exceeds size limit.");
        s.append(buffer, n);
    }
    require(stream.eof(), "Cannot finish reading file.");
    return s;
}
inline fs::path relative_path(const std::wstring& s) {
    auto normalized = relative(s);
#ifndef _WIN32
    std::replace(normalized.begin(), normalized.end(), L'\\', L'/');
#endif
    return path(normalized);
}
inline bool contains(const fs::path& parent, const fs::path& child) {
    auto p = fs::absolute(parent).lexically_normal();
    auto c = fs::absolute(child).lexically_normal();
    auto a = p.begin(), b = c.begin();
    for (; a != p.end(); ++a, ++b) {
        if (b == c.end()) return false;
#ifdef _WIN32
        if (lower(text(*a)) != lower(text(*b))) return false;
#else
        if (*a != *b) return false;
#endif
    }
    return true;
}
struct Options {
    std::wstring command = L"help", box = L"Demo", app, network = L"off", data = L"write";
    std::wstring identity = L"admin", proxy, roaming, local, root, input;
    std::vector<std::wstring> target_args;
    std::uint32_t memory = 4096;
    bool protected_client = true;
};
inline void proxy_address(const std::wstring& s) {
    auto colon = s.find(L':');
    require(colon != s.npos && colon != 0 && s.find(L':', colon + 1) == s.npos,
            "Proxy must be an IPv4-address:port, without a URL scheme.");
    integer(s.substr(colon + 1), 1, 65535);
    auto ip = s.substr(0, colon);
    std::size_t start = 0;
    for (int part = 0; part < 4; ++part) {
        auto dot = ip.find(L'.', start);
        require((part == 3) == (dot == ip.npos), "Expected dotted IPv4 proxy address.");
        integer(ip.substr(start, dot == ip.npos ? ip.npos : dot - start), 0, 255);
        start = dot == ip.npos ? ip.size() : dot + 1;
    }
    require(ip != L"0.0.0.0" && ip.substr(0, 4) != L"127.", "Guest proxy must use a reachable host interface, not loopback.");
}
inline Options parse(const std::vector<std::wstring>& argv) {
    Options o;
    if (argv.empty()) return o;
    o.command = argv.front();
    require(o.command == L"help" || o.command == L"doctor" || o.command == L"init" ||
        o.command == L"prepare" || o.command == L"run" || o.command == L"status", "Unknown command.");
    std::vector<std::wstring> seen;
    for (std::size_t i = 1; i < argv.size(); ++i) {
        const auto& key = argv[i];
        if (key == L"--") { o.target_args.assign(argv.begin() + i + 1, argv.end()); break; }
        require(std::find(seen.begin(), seen.end(), key) == seen.end(), "Duplicate option.");
        seen.push_back(key);
        require(i + 1 < argv.size(), "Option needs a value.");
        auto value = argv[++i];
        if (key == L"--box") o.box = value;
        else if (key == L"--app") o.app = relative(value);
        else if (key == L"--root") o.root = value;
        else if (key == L"--input") o.input = value;
        else if (key == L"--network") o.network = value;
        else if (key == L"--data") o.data = value;
        else if (key == L"--identity") o.identity = value;
        else if (key == L"--proxy") o.proxy = value;
        else if (key == L"--appdata") o.roaming = relative(value);
        else if (key == L"--localappdata") o.local = relative(value);
        else if (key == L"--memory") o.memory = integer(value, 2048, 32768);
        else if (key == L"--protected-client") {
            require(value == L"on" || value == L"off", "Protected client expects on/off.");
            o.protected_client = value == L"on";
        } else throw std::runtime_error("Unknown option: " + utf8(key));
    }
    box_name(o.box);
    require(o.network == L"off" || o.network == L"direct" || o.network == L"proxy", "Network expects off/direct/proxy.");
    require(o.data == L"none" || o.data == L"read" || o.data == L"write", "Data expects none/read/write.");
    require(o.identity == L"admin" || o.identity == L"system", "Identity expects admin/system.");
    if (o.network == L"proxy") { proxy_address(o.proxy); }
    else require(o.proxy.empty(), "--proxy is only valid with --network proxy.");
    if (!o.roaming.empty() || !o.local.empty()) require(o.data == L"write", "AppData persistence requires --data write.");
    if (o.command == L"run" || o.command == L"prepare") {
        require(!o.app.empty(), "--app is required.");
        require(o.app.size() <= 190, "Entry path is too long for the guest work directory.");
        auto extension = lower(text(relative_path(o.app).extension()));
        require(extension == L".exe" || extension == L".msi", "Entry must be an EXE or MSI (not a shell script).");
    }
    arguments(o.target_args);
    return o;
}
inline std::string manifest(const Options& o, const std::wstring& id, const std::wstring& machine) {
    std::ostringstream s;
    s << "{\n  \"schema\":1,\n  \"runId\":" << json(id)
      << ",\n  \"hostMachine\":" << json(machine) << ",\n  \"entry\":" << json(o.app)
      << ",\n  \"arguments\":[";
    for (std::size_t i = 0; i < o.target_args.size(); ++i) { if (i) s << ','; s << json(o.target_args[i]); }
    s << "],\n  \"argumentsCommandLine\":" << json(arguments(o.target_args))
      << ",\n  \"identity\":" << json(o.identity) << ",\n  \"network\":" << json(o.network)
      << ",\n  \"proxy\":" << json(o.proxy) << ",\n  \"data\":" << json(o.data)
      << ",\n  \"roaming\":" << json(o.roaming) << ",\n  \"local\":" << json(o.local) << "\n}\n";
    return s.str();
}
inline std::string wsb(const Options& o, const fs::path& control, const fs::path& input, const fs::path& data) {
    auto mapping = [](const fs::path& host, const std::wstring& guest, bool ro) {
        return L"    <MappedFolder><HostFolder>" + xml(text(host)) + L"</HostFolder><SandboxFolder>" +
            guest + L"</SandboxFolder><ReadOnly>" + (ro ? L"true" : L"false") + L"</ReadOnly></MappedFolder>\n";
    };
    std::wstring out = L"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Configuration>\n";
    out += L"  <vGPU>Disable</vGPU>\n  <Networking>" + std::wstring(o.network == L"off" ? L"Disable" : L"Default") + L"</Networking>\n";
    out += L"  <AudioInput>Disable</AudioInput>\n  <VideoInput>Disable</VideoInput>\n";
    out += L"  <PrinterRedirection>Disable</PrinterRedirection>\n  <ClipboardRedirection>Disable</ClipboardRedirection>\n";
    out += L"  <ProtectedClient>" + std::wstring(o.protected_client ? L"Enable" : L"Disable") + L"</ProtectedClient>\n";
    out += L"  <MemoryInMB>" + std::to_wstring(o.memory) + L"</MemoryInMB>\n  <MappedFolders>\n";
    out += mapping(control, L"C:\\Sandbox\\Control", true);
    out += mapping(input, L"C:\\Sandbox\\Input", true);
    if (o.data != L"none") out += mapping(data, L"C:\\Sandbox\\Data", o.data == L"read");
    out += L"  </MappedFolders>\n  <LogonCommand><Command>";
    // Fixed command only. Untrusted target arguments live in JSON, not a shell command.
    out += L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\\Sandbox\\Control\\guest.ps1";
    out += L"</Command></LogonCommand>\n</Configuration>\n";
    return utf8(out);
}
} // namespace sa
