#include "proxy.hpp" // Winsock must precede Windows.h.
#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <objbase.h>
#endif
#include <cstdlib>
#include <iomanip>
#include <random>

namespace {
using namespace sa;
fs::path executable_directory;
void print_path(const char* label, const fs::path& p) { std::cout << label << utf8(text(p)) << '\n'; }
[[maybe_unused]] std::wstring environment(const wchar_t* name) {
#ifdef _WIN32
    DWORD length = GetEnvironmentVariableW(name, nullptr, 0);
    if (!length) return {};
    std::wstring out(length, L'\0');
    DWORD n = GetEnvironmentVariableW(name, out.data(), length);
    require(n > 0 && n < length, "Cannot read environment variable.");
    out.resize(n); return out;
#else
    auto key = utf8(name); const auto* value = std::getenv(key.c_str());
    return value ? wide(value) : L"";
#endif
}
std::wstring machine_name() {
#ifdef _WIN32
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    require(GetComputerNameW(buffer, &size) != FALSE, "Cannot obtain host machine name.");
    return std::wstring(buffer, size);
#else
    char name[256]{};
    require(gethostname(name, sizeof(name) - 1) == 0, "Cannot obtain host machine name.");
    return wide(name);
#endif
}
std::wstring run_id() {
#ifdef _WIN32
    GUID id{};
    require(SUCCEEDED(CoCreateGuid(&id)), "Cannot generate run ID.");
    wchar_t buffer[40]{};
    require(StringFromGUID2(id, buffer, 40) != 0, "Cannot format run ID.");
    auto s = std::wstring(buffer);
    return s.substr(1, s.size() - 2);
#else
    std::random_device random;
    std::wostringstream out;
    for (int i = 0; i < 4; ++i) out << std::hex << std::setw(8) << std::setfill(L'0') << random();
    return out.str();
#endif
}
void no_reparse(const fs::path& p) {
    auto full = fs::absolute(p).lexically_normal();
    fs::path current;
    for (const auto& segment : full) {
        current /= segment;
        auto status = fs::symlink_status(current);
        if (!fs::exists(status)) continue;
        require(!fs::is_symlink(status), "Symlink/reparse paths are not accepted.");
#ifdef _WIN32
        DWORD attr = GetFileAttributesW(current.c_str());
        require(attr != INVALID_FILE_ATTRIBUTES, "Cannot inspect filesystem attributes.");
        require((attr & FILE_ATTRIBUTE_REPARSE_POINT) == 0, "Symlink/junction/reparse paths are not accepted.");
#endif
    }
}
fs::path absolute_local(const fs::path& source) {
    auto out = fs::absolute(source).lexically_normal();
    validate_text(text(out));
#ifdef _WIN32
    auto s = text(out);
    require(s.size() >= 3 && s[1] == L':' && (s[2] == L'\\' || s[2] == L'/') && s.size() < 220,
            "Use a short local drive path, not UNC/device/extended paths.");
    for (std::size_t i = 2; i < s.size(); ++i) require(s[i] != L':', "Alternate data streams are not accepted.");
    auto root = out.root_path();
    auto sub = out.lexically_relative(root);
    if (!sub.empty()) relative(text(sub));
#endif
    no_reparse(out);
    return out;
}
fs::path root_path(const Options& o) {
    if (!o.root.empty()) return absolute_local(path(o.root));
#ifdef _WIN32
    auto root = environment(L"LOCALAPPDATA");
    require(!root.empty(), "LOCALAPPDATA is unavailable; pass --root.");
    return absolute_local(path(root) / "WinSandboxCtl" / "Boxes");
#else
    return absolute_local(fs::current_path() / "Boxes");
#endif
}
fs::path initialize(const Options& o) {
    auto box = root_path(o) / path(o.box);
    for (const auto& name : {"ReadOnlyBin", "PersistData", "Runtime"}) {
        auto p = absolute_local(box / name);
        fs::create_directories(p); no_reparse(p);
        require(fs::is_directory(p), "Expected a directory.");
    }
    return box;
}
void stage_tree(const fs::path& source, const fs::path& destination) {
    require(fs::is_directory(source), "Input directory is missing.");
    require(!contains(source, destination) && !contains(destination, source), "Input and runtime directories must not overlap.");
    fs::create_directories(destination);
    std::uint64_t bytes = 0, entries = 0;
    constexpr std::uint64_t max_bytes = 2ull * 1024 * 1024 * 1024;
    for (const auto& entry : fs::recursive_directory_iterator(source)) {
        require(++entries <= 50000, "Staging limit exceeded: too many entries.");
        no_reparse(entry.path());
        auto rel = entry.path().lexically_relative(source);
        relative(text(rel));
        auto dest = destination / rel;
        if (entry.is_directory()) fs::create_directory(dest);
        else {
            require(entry.is_regular_file(), "Only regular files/directories may be staged.");
            const auto size = entry.file_size();
            require(size <= max_bytes - bytes, "Input snapshot exceeds 2 GiB staging limit.");
            bytes += size;
            fs::copy_file(entry.path(), dest, fs::copy_options::none);
        }
    }
}
fs::path guest_script() {
    // Distribution layout: bin/SandboxHost.exe + guest/guest.ps1.
    for (const auto& p : {executable_directory / "guest" / "guest.ps1", executable_directory.parent_path() / "guest" / "guest.ps1"}) {
        if (fs::is_regular_file(p)) { no_reparse(p); return p; }
    }
    throw std::runtime_error("guest/guest.ps1 is missing next to the distribution's bin directory.");
}
fs::path prepare(const Options& o) {
    auto box = initialize(o);
    auto input = absolute_local(o.input.empty() ? box / "ReadOnlyBin" : path(o.input));
    require(input != input.root_path(), "Do not stage an entire drive.");
    auto data = absolute_local(box / "PersistData");
    auto runtime = absolute_local(box / "Runtime");
    require(!contains(input, runtime) && !contains(runtime, input) && !contains(input, data) && !contains(data, input),
            "Input must not overlap Runtime or PersistData.");
    auto entry = absolute_local(input / relative_path(o.app));
    require(contains(input, entry) && fs::is_regular_file(entry), "Target entry is not a regular file under input.");
    const auto script = guest_script();
    const auto script_text = read(script);
    const auto id = run_id();
    auto session = absolute_local(runtime / path(id));
    require(fs::create_directory(session), "Session directory already exists.");
    auto control = session / "control", snapshot = session / "input";
    fs::create_directory(control);
    stage_tree(input, snapshot);
    write(control / "guest.ps1", script_text);
    write(control / "launch.json", manifest(o, id, machine_name()));
    write(session / "runtime.wsb", wsb(o, control, snapshot, data));
    write(box / "last-run.txt", utf8(id) + "\n");
    print_path("Config: ", session / "runtime.wsb");
    print_path("Read-only snapshot: ", snapshot);
    if (o.data != L"none") print_path(o.data == L"write" ? "Writable host data: " : "Read-only host data: ", data);
    std::cout << "Network: " << utf8(o.network) << "; guest identity: " << utf8(o.identity) << '\n';
    if (o.network == L"proxy") std::cout << "Proxy is advisory. Guest admin/SYSTEM can bypass it. Direct networking remains enabled.\n";
    if (o.identity == L"system") std::cout << "SYSTEM executes in a non-interactive task session (no ordinary GUI).\n";
    return session / "runtime.wsb";
}
void launch(const fs::path& config) {
#ifdef _WIN32
    const auto system = environment(L"SystemRoot");
    require(!system.empty(), "SystemRoot is unavailable.");
    auto binary = path(system) / "System32" / "WindowsSandbox.exe";
    require(fs::is_regular_file(binary), "Windows Sandbox executable is unavailable. Run doctor; enable the Windows Sandbox feature.");
    auto args = quote(text(config));
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info); info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = L"open"; info.lpFile = binary.c_str(); info.lpParameters = args.c_str(); info.nShow = SW_SHOWNORMAL;
    require(ShellExecuteExW(&info) != FALSE, "Windows Sandbox launch failed. Inspect the generated .wsb and Windows feature state.");
    if (info.hProcess) CloseHandle(info.hProcess);
    std::cout << "Launch requested. Close the Sandbox desktop to discard its guest system state.\n";
#else
    (void)config;
    throw std::runtime_error("run requires Windows; use prepare for cross-platform configuration tests.");
#endif
}
void doctor() {
#ifdef _WIN32
    auto system = environment(L"SystemRoot");
    auto binary = path(system) / "System32" / "WindowsSandbox.exe";
    print_path("Windows Sandbox executable: ", binary);
    std::cout << "Executable present: " << (fs::is_regular_file(binary) ? "yes" : "no") << '\n';
    std::cout << "Firmware virtualization API flag: " << (IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) ? "yes" : "no/unknown") << '\n';
    std::cout << "This flag alone is not an availability verdict when a hypervisor is active.\n";
    std::cout << "Use Windows 11 Pro/Enterprise/Education, virtualization enabled, and the Windows Sandbox optional feature.\n";
    std::cout << "Administrator setup (one time, may require restart):\n";
    std::cout << "  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All\n";
    std::cout << "For detailed read-only diagnostics run scripts/Doctor.ps1. No host setting was changed.\n";
#else
    std::cout << "Non-Windows test build: configuration preparation and explicit proxy only. Windows Sandbox is unavailable here.\n";
#endif
}
void status(const Options& o) {
    auto box = absolute_local(root_path(o) / path(o.box));
    no_reparse(box / "last-run.txt");
    auto id_text = read(box / "last-run.txt", 128);
    while (!id_text.empty() && (id_text.back() == '\r' || id_text.back() == '\n')) id_text.pop_back();
    require(!id_text.empty(), "No prepared session.");
    for (char c : id_text) require((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') || c == '-', "Invalid saved session ID.");
    auto file = absolute_local(box / "PersistData" / "Runs" / fs::u8path(id_text) / "status.json");
    print_path("Guest status (untrusted telemetry): ", file);
    if (!fs::is_regular_file(file)) { std::cout << "No persisted status. Use --data write, or inspect the guest desktop.\n"; return; }
    auto content = read(file, 65536);
    for (unsigned char c : content) {
        if ((c >= 32 && c != 127) || c == '\n' || c == '\r' || c == '\t') std::cout << static_cast<char>(c);
        else std::cout << '?';
    }
    std::cout << '\n';
}
void help() {
    std::cout << R"HELP(WinSandboxCtl - Windows Sandbox controller (source implementation, no custom driver)

  SandboxHost doctor
  SandboxHost init --box Demo [--root PATH]
  SandboxHost prepare --box Demo --app App.exe [OPTIONS] [-- ARG ...]
  SandboxHost run     --box Demo --app App.exe [OPTIONS] [-- ARG ...]
  SandboxHost status  --box Demo [--root PATH]

OPTIONS:
  --input PATH                   Dedicated input folder (default: ReadOnlyBin)
  --network off|direct|proxy      Default off; proxy mode allows direct bypass
  --proxy IPV4:PORT               Required for proxy; use host virtual NIC IP
  --data none|read|write          Default write, only the dedicated PersistData
  --identity admin|system         Default admin; system is non-interactive
  --appdata Vendor\App            Persist this roaming subfolder (write data)
  --localappdata Vendor\App       Persist this local subfolder (write data)
  --memory MB                    2048..32768, default 4096
  --protected-client on|off       Default on; never silently downgraded
  --root PATH                    Box storage, default LOCALAPPDATA\WinSandboxCtl\Boxes

Explicit HTTPS CONNECT proxy (a separate foreground process):
  SandboxHost proxy --listen IPV4 --clients CIDR --port 18080
                    --allow example.com [--allow *.example.org] [--ports 443]
  Default listener: 127.0.0.1, clients: 127.0.0.0/8; Ctrl+C stops the proxy.
  Remote binding requires explicit client CIDR. No firewall rules are installed.
  --allow-private-upstream is for deliberate private-network tests only.

Read README.zh-CN.md before testing. The controller never executes the target
on the host. The Windows Sandbox VM is the boundary. Guest-writable host data
is exposed to guest programs by design; never use a sensitive directory.
)HELP";
}
int entry(const std::vector<std::wstring>& args) {
    try {
        if (!args.empty() && args[0] == L"proxy") return net::proxy_main({args.begin() + 1, args.end()});
        auto options = parse(args);
        if (options.command == L"help") help();
        else if (options.command == L"doctor") doctor();
        else if (options.command == L"init") {
            auto box = initialize(options);
            print_path("Put target files in: ", box / "ReadOnlyBin");
            print_path("Dedicated data: ", box / "PersistData");
        } else if (options.command == L"status") status(options);
        else {
            auto file = prepare(options);
            if (options.command == L"run") launch(file);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << '\n';
#ifdef _WIN32
        std::cerr << "Win32 last-error (may be unrelated): " << GetLastError() << '\n';
#endif
        return 2;
    }
}
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    wchar_t file[32768]{};
    DWORD n = GetModuleFileNameW(nullptr, file, 32768);
    if (n == 0 || n >= 32768) return 2;
    executable_directory = fs::path(file).parent_path();
    return entry({argv + 1, argv + argc});
}
#else
int main(int argc, char** argv) {
    try {
        executable_directory = fs::absolute(fs::u8path(argv[0])).lexically_normal().parent_path();
        std::vector<std::wstring> args;
        for (int i = 1; i < argc; ++i) args.push_back(wide(argv[i]));
        return entry(args);
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 2; }
}
#endif
