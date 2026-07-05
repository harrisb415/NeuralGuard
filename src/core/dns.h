// DnsWatcher: a real-time ETW consumer of Microsoft-Windows-DNS-Client. It
// watches DNS query-completed events (id 3008), parses the answers, and keeps an
// in-memory IP -> domain map so the recorder can attribute a flow's remote IP to
// the name the application actually resolved. Short TTL, size-capped.
#pragma once

#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace ng {

class DnsWatcher {
public:
    ~DnsWatcher() { stop(); }

    bool start();   // set up the ETW session + consumer thread
    void stop();    // stop the session and join the thread

    // Most recent domain that resolved to `ip` (canonical form), "" if unknown/expired.
    std::string lookup(const std::string& ip);

    // Called by the ETW callback thunk; `rec` is a PEVENT_RECORD.
    void onRecord(void* rec);

private:
    void remember(const std::string& ip, const std::string& name);

    struct Entry { std::string name; unsigned long long tick; };
    std::mutex mapMutex_;
    std::unordered_map<std::string, Entry> map_;

    std::thread thread_;
    unsigned long long sessionHandle_ = 0;  // TRACEHANDLE (session)
    unsigned long long traceHandle_   = 0;  // TRACEHANDLE (OpenTrace)
    bool stopped_ = false;
    unsigned long long seenTotal_ = 0;      // diagnostic: all events delivered
    unsigned long long seen3008_ = 0;       // diagnostic: DNS-complete events seen
    void* propsBuf_ = nullptr;              // EVENT_TRACE_PROPERTIES buffer
};

}  // namespace ng
