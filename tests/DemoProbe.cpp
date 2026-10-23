// Harmless guest-only integration probe. Refuses to run on the host.
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include "../src/core.hpp"
#include <iostream>

namespace {
std::wstring env(const wchar_t* name) {
    DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring out(size, L'\0');
    DWORD used = GetEnvironmentVariableW(name, out.data(), size);
    if (!used || used >= size) return {};
    out.resize(used); return out;
}
bool write_file(const std::wstring& name, const std::string& content) {
    HANDLE file = CreateFileW(name.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written, nullptr) && written == content.size();
    CloseHandle(file); return ok;
}
}
int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    const auto id = env(L"SANDBOX_RUN_ID"), work = env(L"SANDBOX_WORK_DIR"), data = env(L"SANDBOX_DATA_DIR");
    if (id.empty() || work.compare(0, 16, L"C:\\Sandbox\\Work\\") != 0 || data != L"C:\\Sandbox\\Data") {
        std::cerr << "Guest-only probe: launch via SandboxHost with --data write.\n"; return 10;
    }
    const bool guest_file = write_file(L"C:\\Windows\\WinSandboxCtl-GuestOnly-Canary.txt", "guest-only=" + sa::utf8(id));
    HKEY key = nullptr;
    bool guest_registry = false;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WinSandboxCtl-GuestOnly-Probe", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
        guest_registry = RegSetValueExW(key, L"RunId", 0, REG_SZ, reinterpret_cast<const BYTE*>(id.c_str()), static_cast<DWORD>((id.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
        RegCloseKey(key);
    }
    // Source snapshot is intentionally read-only; this attempt must fail.
    const bool source_modified = write_file(L"C:\\Sandbox\\Input\\readonly-canary.txt", "BAD: writable source");
    auto marker = data + L"\\probe-persist-" + id + L".txt";
    const bool persistent = write_file(marker, "expected persistent output");
    HANDLE token = nullptr;
    bool system = false;
    std::wstring sid_string;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD length = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &length);
        std::vector<unsigned char> buffer(length);
        if (GetTokenInformation(token, TokenUser, buffer.data(), length, &length)) {
            auto user = reinterpret_cast<TOKEN_USER*>(buffer.data());
            LPWSTR sid = nullptr;
            if (ConvertSidToStringSidW(user->User.Sid, &sid)) { sid_string = sid; LocalFree(sid); }
            system = IsWellKnownSid(user->User.Sid, WinLocalSystemSid) != FALSE;
        }
        CloseHandle(token);
    }
    std::ostringstream out;
    out << "{\n\"runId\":" << sa::json(id) << ",\n\"guestWindowsWrite\":" << (guest_file ? "true" : "false")
        << ",\n\"guestHKLMWrite\":" << (guest_registry ? "true" : "false")
        << ",\n\"readOnlyInputProtected\":" << (!source_modified ? "true" : "false")
        << ",\n\"persistentOutputWrite\":" << (persistent ? "true" : "false")
        << ",\n\"isSystem\":" << (system ? "true" : "false") << ",\n\"tokenSid\":" << sa::json(sid_string)
        << ",\n\"arguments\":[";
    for (int i = 1; i < argc; ++i) { if (i > 1) out << ','; out << sa::json(argv[i]); }
    out << "]\n}\n";
    const auto result = out.str();
    std::cout << result;
    if (!write_file(data + L"\\probe-result-" + id + L".json", result)) return 11;
    return guest_file && guest_registry && !source_modified && persistent ? 0 : 12;
}
