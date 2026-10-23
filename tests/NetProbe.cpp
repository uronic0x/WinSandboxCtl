// Guest network probe: dumps adapters, routes, and proxy reachability to
// C:\Sandbox\Data\netprobe.txt (persistent host-visible output, UTF-8).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <fstream>
#include <string>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static std::string u8(const wchar_t* w) {
    if (!w || !*w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

int wmain() {
    std::ofstream out("C:\\Sandbox\\Data\\netprobe.txt", std::ios::trunc | std::ios::binary);
    if (!out) return 10;
    WSADATA wd{};
    WSAStartup(MAKEWORD(2, 2), &wd);
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size);
    std::string buffer(size, '\0');
    auto* aa = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    DWORD arc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, aa, &size);
    out << "GetAdaptersAddresses rc=" << arc << "\n";
    if (arc == NO_ERROR) {
        for (auto* a = aa; a; a = a->Next) {
            out << "adapter=" << u8(a->FriendlyName)
                << " status=" << (a->OperStatus == IfOperStatusUp ? "up" : "down")
                << " dhcp=" << ((a->Flags & IP_ADAPTER_DHCP_ENABLED) ? "on" : "off")
                << " if=" << a->IfIndex << "\n";
            for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
                wchar_t addr[128]{};
                DWORD len = 128;
                WSAAddressToStringW(u->Address.lpSockaddr, u->Address.iSockaddrLength, nullptr, addr, &len);
                out << "  ip=" << u8(addr) << "\n";
            }
            for (auto* g = a->FirstGatewayAddress; g; g = g->Next) {
                wchar_t addr[128]{};
                DWORD len = 128;
                WSAAddressToStringW(g->Address.lpSockaddr, g->Address.iSockaddrLength, nullptr, addr, &len);
                out << "  gw=" << u8(addr) << "\n";
            }
            for (auto* d = a->FirstDnsServerAddress; d; d = d->Next) {
                wchar_t addr[128]{};
                DWORD len = 128;
                WSAAddressToStringW(d->Address.lpSockaddr, d->Address.iSockaddrLength, nullptr, addr, &len);
                out << "  dns=" << u8(addr) << "\n";
            }
        }
    }
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (GetIpForwardTable2(AF_INET, &table) == NO_ERROR) {
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            auto& e = table->Table[i];
            if (e.DestinationPrefix.PrefixLength == 0) {
                wchar_t gw[128]{};
                InetNtopW(AF_INET, &e.NextHop.Ipv4.sin_addr, gw, 128);
                out << "defaultroute via=" << u8(gw) << " if=" << e.InterfaceIndex << "\n";
            }
        }
        FreeMibTable(table);
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(18080);
    InetPtonW(AF_INET, L"172.18.64.1", &sa.sin_addr);
    DWORD start = GetTickCount();
    int rc = connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    out << "connect 172.18.64.1:18080 rc=" << rc << " err=" << WSAGetLastError()
        << " ms=" << (GetTickCount() - start) << "\n";
    closesocket(s);
    out.flush();
    return 0;
}
