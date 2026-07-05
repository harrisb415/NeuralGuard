#include <winsock2.h>
#include <ws2tcpip.h>

#include "core/dns.h"
#include "core/util.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace ng {
namespace {

const wchar_t* kSessionName = L"NeuralGuard-DNS";
constexpr unsigned long long kTtlMs = 30ull * 60 * 1000;   // 30 min
constexpr size_t kMaxEntries = 20000;

// Microsoft-Windows-DNS-Client {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
const GUID kDnsProvider =
    {0x1C95126E, 0x7EEA, 0x49A9, {0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}};

void WINAPI EventCallback(PEVENT_RECORD rec) {
    if (rec && rec->UserContext)
        static_cast<DnsWatcher*>(rec->UserContext)->onRecord(rec);
}

// Extract a string property by name via TDH (uses the manifest schema).
std::wstring GetStringProp(EVENT_RECORD* rec, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = (ULONGLONG)(uintptr_t)name;
    desc.ArrayIndex = 0;
    DWORD size = 0;
    if (TdhGetPropertySize(rec, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS || size == 0)
        return L"";
    std::vector<BYTE> buf(size + sizeof(wchar_t), 0);
    if (TdhGetProperty(rec, 0, nullptr, 1, &desc, size, buf.data()) != ERROR_SUCCESS)
        return L"";
    return std::wstring(reinterpret_cast<wchar_t*>(buf.data()));
}

}  // namespace

void DnsWatcher::remember(const std::string& ip, const std::string& name) {
    std::lock_guard<std::mutex> lk(mapMutex_);
    map_[ip] = {name, GetTickCount64()};
    if (map_.size() > kMaxEntries) {
        unsigned long long now = GetTickCount64();
        for (auto it = map_.begin(); it != map_.end();) {
            if (now - it->second.tick > kTtlMs) it = map_.erase(it); else ++it;
        }
    }
}

std::string DnsWatcher::lookup(const std::string& ip) {
    std::lock_guard<std::mutex> lk(mapMutex_);
    auto it = map_.find(ip);
    if (it == map_.end()) return "";
    if (GetTickCount64() - it->second.tick > kTtlMs) return "";
    return it->second.name;
}

void DnsWatcher::onRecord(void* p) {
    EVENT_RECORD* rec = static_cast<EVENT_RECORD*>(p);
    ++seenTotal_;
    if (rec->EventHeader.EventDescriptor.Id != 3008) return;   // DNS query completed
    ++seen3008_;

    std::wstring wname = GetStringProp(rec, L"QueryName");
    std::wstring wresults = GetStringProp(rec, L"QueryResults");
    if (wname.empty() || wresults.empty()) return;
    std::string name = util::Narrow(wname);

    // QueryResults is a ';'-separated answer list; address records may be bare or
    // prefixed ("type: 1 1.2.3.4"). Split on separators and keep any token that
    // parses as an IP, canonicalizing so it matches the recorder's format.
    std::string r = util::Narrow(wresults);
    for (auto& c : r) if (c == ';' || c == ',') c = ' ';
    size_t i = 0;
    while (i < r.size()) {
        while (i < r.size() && std::isspace((unsigned char)r[i])) ++i;
        size_t j = i;
        while (j < r.size() && !std::isspace((unsigned char)r[j])) ++j;
        std::string tok = r.substr(i, j - i);
        i = j;
        if (tok.empty()) continue;
        char canon[INET6_ADDRSTRLEN];
        in_addr a4{}; in6_addr a6{};
        if (InetPtonA(AF_INET, tok.c_str(), &a4) == 1) {
            InetNtopA(AF_INET, &a4, canon, sizeof(canon));
            remember(canon, name);
        } else if (InetPtonA(AF_INET6, tok.c_str(), &a6) == 1) {
            if (IN6_IS_ADDR_V4MAPPED(&a6)) {
                // DNS answers often encode A records as ::ffff:a.b.c.d; the WFP
                // flow side sees plain IPv4, so store the unwrapped IPv4.
                in_addr v4{}; memcpy(&v4, &a6.s6_addr[12], 4);
                InetNtopA(AF_INET, &v4, canon, sizeof(canon));
            } else {
                InetNtopA(AF_INET6, &a6, canon, sizeof(canon));
            }
            remember(canon, name);
        }
    }
}

bool DnsWatcher::start() {
    size_t nameBytes = (wcslen(kSessionName) + 1) * sizeof(wchar_t);
    size_t bufSize = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
    propsBuf_ = calloc(1, bufSize);
    if (!propsBuf_) return false;
    auto* props = (EVENT_TRACE_PROPERTIES*)propsBuf_;
    props->Wnode.BufferSize = (ULONG)bufSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC timestamps
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    TRACEHANDLE session = 0;
    ULONG st = StartTraceW(&session, kSessionName, props);
    if (st == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
        // props gets overwritten by ControlTrace; reset the fields we set.
        memset(propsBuf_, 0, bufSize);
        props->Wnode.BufferSize = (ULONG)bufSize;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        st = StartTraceW(&session, kSessionName, props);
    }
    if (st != ERROR_SUCCESS) {
        fprintf(stderr, "DNS: StartTrace failed: %lu\n", st);
        free(propsBuf_); propsBuf_ = nullptr;
        return false;
    }
    sessionHandle_ = session;

    // MatchAnyKeyword = all-ones: a manifest provider's events with any non-zero
    // keyword are otherwise filtered out when this is 0 (DNS-Client uses keywords).
    st = EnableTraceEx2(session, &kDnsProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFFull, 0, 0, nullptr);
    if (st != ERROR_SUCCESS) {
        fprintf(stderr, "DNS: EnableTraceEx2 failed: %lu\n", st);
        stop();
        return false;
    }

    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = const_cast<LPWSTR>(kSessionName);
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = &EventCallback;
    log.Context = this;
    TRACEHANDLE trace = OpenTraceW(&log);
    if (trace == INVALID_PROCESSTRACE_HANDLE) {
        fprintf(stderr, "DNS: OpenTrace failed: %lu\n", GetLastError());
        stop();
        return false;
    }
    traceHandle_ = trace;

    thread_ = std::thread([this]() {
        TRACEHANDLE h = (TRACEHANDLE)traceHandle_;
        ULONG pt = ProcessTrace(&h, 1, nullptr, nullptr);  // blocks until CloseTrace
        if (pt != ERROR_SUCCESS && pt != ERROR_CANCELLED)
            fprintf(stderr, "DNS: ProcessTrace returned %lu\n", pt);
    });
    return true;
}

void DnsWatcher::stop() {
    if (stopped_) return;
    stopped_ = true;
    if (traceHandle_) { CloseTrace((TRACEHANDLE)traceHandle_); traceHandle_ = 0; }
    if (thread_.joinable()) thread_.join();
    fprintf(stderr, "DNS: %llu events total, %llu query-complete (3008), %zu ip->domain entries\n",
            seenTotal_, seen3008_, map_.size());
    if (sessionHandle_ && propsBuf_) {
        ControlTraceW((TRACEHANDLE)sessionHandle_, nullptr,
                      (EVENT_TRACE_PROPERTIES*)propsBuf_, EVENT_TRACE_CONTROL_STOP);
        sessionHandle_ = 0;
    }
    if (propsBuf_) { free(propsBuf_); propsBuf_ = nullptr; }
}

}  // namespace ng
