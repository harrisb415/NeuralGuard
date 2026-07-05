// ngmon - NeuralGuard Phase 0 spike.
//
// A user-mode monitor that subscribes to Windows Filtering Platform (WFP) net
// events and prints each connection allow/drop with process attribution. No
// kernel driver, no external dependencies - this proves the foundation the
// first several phases build on (see docs/DESIGN.md and docs/ROADMAP.md).
//
// Requires: run elevated. To see ALLOW events (not just drops), enable the
// audit subcategory first:
//   auditpol /set /subcategory:"Filtering Platform Connection" ^
//            /success:enable /failure:enable
//
// Ctrl+C to stop.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <sddl.h>

#include <atomic>
#include <cstdio>
#include <string>

namespace {

std::atomic<bool> g_stop{false};
HANDLE g_stopEvent = nullptr;
unsigned long long g_count = 0;

// WFP net-event header addresses/ports are in host byte order.
std::string IpToStr(const FWPM_NET_EVENT_HEADER3* h, bool remote) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (h->ipVersion == FWP_IP_VERSION_V4) {
        in_addr a{};
        a.s_addr = htonl(remote ? h->remoteAddrV4 : h->localAddrV4);
        InetNtopA(AF_INET, &a, buf, sizeof(buf));
    } else if (h->ipVersion == FWP_IP_VERSION_V6) {
        in6_addr a{};
        memcpy(&a, remote ? h->remoteAddrV6.byteArray16
                          : h->localAddrV6.byteArray16, 16);
        InetNtopA(AF_INET6, &a, buf, sizeof(buf));
    } else {
        return "?";
    }
    return buf;
}

const char* ProtoName(UINT8 p) {
    switch (p) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_ICMPV6: return "ICMPv6";
        default: return "IP";
    }
}

const char* TypeName(FWPM_NET_EVENT_TYPE t) {
    switch (t) {
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:  return "DROP ";
        case FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW: return "ALLOW";
        default: return "OTHER";
    }
}

// appId is the NT device path of the image (e.g. \device\harddiskvolume3\...).
// Phase 0 prints it raw; normalization to C:\ paths + signer/hash comes later.
std::string AppIdToStr(const FWP_BYTE_BLOB* blob) {
    if (!blob || !blob->data || blob->size == 0) return "(no app id)";
    const wchar_t* w = reinterpret_cast<const wchar_t*>(blob->data);
    size_t wlen = blob->size / sizeof(wchar_t);
    while (wlen > 0 && w[wlen - 1] == L'\0') --wlen;
    if (wlen == 0) return "(no app id)";
    int need = WideCharToMultiByte(CP_UTF8, 0, w, (int)wlen, nullptr, 0, nullptr, nullptr);
    std::string s(need, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, (int)wlen, s.data(), need, nullptr, nullptr);
    return s;
}

std::string UserSid(const FWPM_NET_EVENT_HEADER3* h) {
    if (!(h->flags & FWPM_NET_EVENT_FLAG_USER_ID_SET) || !h->userId) return "";
    LPSTR str = nullptr;
    std::string out;
    if (ConvertSidToStringSidA(h->userId, &str) && str) { out = str; LocalFree(str); }
    return out;
}

void CALLBACK OnNetEvent(void* /*context*/, const FWPM_NET_EVENT5* ev) {
    if (!ev) return;
    const FWPM_NET_EVENT_HEADER3* h = &ev->header;

    const bool hasProto = (h->flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) != 0;
    const bool hasLPort = (h->flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET) != 0;
    const bool hasRPort = (h->flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) != 0;

    std::string local  = IpToStr(h, false);
    std::string remote = IpToStr(h, true);
    std::string app = (h->flags & FWPM_NET_EVENT_FLAG_APP_ID_SET)
                          ? AppIdToStr(&h->appId) : "(no app id)";
    std::string sid = UserSid(h);

    SYSTEMTIME st{};
    FileTimeToSystemTime(&h->timeStamp, &st);

    printf("%02d:%02d:%02d.%03d  %s  %-4s  %s:%u -> %s:%u  [%s]%s%s\n",
           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
           TypeName(ev->type),
           hasProto ? ProtoName(h->ipProtocol) : "IP",
           local.c_str(),  hasLPort ? h->localPort  : 0,
           remote.c_str(), hasRPort ? h->remotePort : 0,
           app.c_str(),
           sid.empty() ? "" : "  user=", sid.c_str());
    fflush(stdout);
    ++g_count;
}

BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_stop = true;
        if (g_stopEvent) SetEvent(g_stopEvent);
        return TRUE;
    }
    return FALSE;
}

}  // namespace

int main() {
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    FWPM_SESSION0 session{};
    // NOT dynamic: engine-global options (COLLECT_NET_EVENTS) can't be set from a
    // dynamic session (FWP_E_DYNAMIC_SESSION_IN_PROGRESS). We add no filters, and
    // the event subscription is torn down on FwpmEngineClose0 regardless.
    session.flags = 0;
    session.displayData.name = const_cast<wchar_t*>(L"ngmon");

    HANDLE engine = nullptr;
    DWORD err = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine);
    if (err != ERROR_SUCCESS) {
        fprintf(stderr, "FwpmEngineOpen0 failed: 0x%08lX (are you elevated?)\n", err);
        return 1;
    }

    // Turn on net-event collection and choose which classify events to collect.
    // Without this the engine may deliver NO events at all (collection off) and
    // no ALLOW events (allow keyword not selected). These are engine-global; we
    // leave them enabled on exit (harmless, and usually already on).
    auto setU32 = [&](FWPM_ENGINE_OPTION opt, UINT32 val) {
        FWP_VALUE0 v{};
        v.type = FWP_UINT32;
        v.uint32 = val;
        DWORD e = FwpmEngineSetOption0(engine, opt, &v);
        if (e != ERROR_SUCCESS)
            fprintf(stderr, "warning: FwpmEngineSetOption0(opt=%d) failed: 0x%08lX\n",
                    (int)opt, e);
    };
    setU32(FWPM_ENGINE_COLLECT_NET_EVENTS, 1);
    setU32(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
           FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW |
           FWPM_NET_EVENT_KEYWORD_CAPABILITY_ALLOW |
           FWPM_NET_EVENT_KEYWORD_CAPABILITY_DROP |
           FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST |
           FWPM_NET_EVENT_KEYWORD_INBOUND_BCAST |
           FWPM_NET_EVENT_KEYWORD_PORT_SCANNING_DROP);

    FWPM_NET_EVENT_SUBSCRIPTION0 sub{};
    sub.enumTemplate = nullptr;  // nullptr = subscribe to all net events

    HANDLE subHandle = nullptr;
    err = FwpmNetEventSubscribe4(engine, &sub, OnNetEvent, nullptr, &subHandle);
    if (err != ERROR_SUCCESS) {
        fprintf(stderr, "FwpmNetEventSubscribe4 failed: 0x%08lX\n", err);
        FwpmEngineClose0(engine);
        return 1;
    }

    printf("ngmon - watching WFP net events (Ctrl+C to stop)\n");
    printf("time          verdict proto  local -> remote  [image]\n");
    printf("-----------------------------------------------------------------\n");
    fflush(stdout);

    WaitForSingleObject(g_stopEvent, INFINITE);

    printf("\nStopping... (%llu events observed)\n", g_count);
    FwpmNetEventUnsubscribe0(engine, subHandle);
    FwpmEngineClose0(engine);
    WSACleanup();
    return 0;
}
