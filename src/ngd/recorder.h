// Recorder: opens the WFP engine, enables net-event collection, subscribes, and
// writes each event (attributed via IdentityResolver) into the database.
#pragma once

#include "ngd/coalesce.h"

#include <atomic>

namespace ng {

class Db;
class IdentityResolver;
class DnsWatcher;
class HabitTracker;

class Recorder {
public:
    Recorder(Db& db, IdentityResolver& id, DnsWatcher& dns, HabitTracker& habits)
        : db_(db), id_(id), dns_(dns), habits_(habits) {}

    bool run();   // subscribe and block until stop(); false on setup failure
    void stop();  // signal run() to return (called from a console Ctrl handler)

    // Called by the WFP callback thunk; `ev` is a const FWPM_NET_EVENT5*.
    void handleEvent(const void* ev);

private:
    Db& db_;
    IdentityResolver& id_;
    DnsWatcher& dns_;
    HabitTracker& habits_;
    void* stopEvent_ = nullptr;   // HANDLE
    void* insStmt_   = nullptr;   // sqlite3_stmt*
    std::atomic<unsigned long long> count_{0};
    // Run-time ids of the 4 ALE connect/accept layers, resolved once in run() so
    // handleEvent can map an event's layerId to a definitive direction (0xFFFF
    // = unresolved). See ngwfp::ResolveAleLayers / DirectionOf.
    unsigned short aleConnV4_ = 0xFFFF, aleConnV6_ = 0xFFFF,
                   aleAcceptV4_ = 0xFFFF, aleAcceptV6_ = 0xFFFF;
    EventCoalescer coalescer_;   // suppress rapid identical repeats in the raw log
};

}  // namespace ng
