// EnforceDaemon (Phase 2c / block-notify-retry, automatic): turns ngd into the
// live enforcer. It installs the stable baseline permits + default-deny, then
// watches WFP drop events; when a novel public connection is blocked it prompts
// the tray (off the callback thread) and, on Allow, adds a permit so the app's
// retry succeeds. Reverts (panic) on stop.
#pragma once

#include "ngd/coalesce.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>

namespace ng {

class Db;
class IdentityResolver;
class DnsWatcher;
class Enforcer;
class HabitTracker;
struct Identity;

// Read-only inspector: prints the stable (app, port) permits `ngd enforce` would
// install right now - the same query, including Phase 4d demotion exclusions -
// without opening WFP or needing admin. Returns the permit count. Used by
// `ngd baseline` to see the effect of ML demotions without enforcing.
int PrintBaseline(Db& db);

// Read-only inspector for the INBOUND baseline: prints the (app, local service
// port) pairs that `ngd enforce` would permit to accept inbound connections when
// meta('inbound_mode')='enforce'. This is the "look before you leap" step - watch
// it until it covers your real listening services, THEN enable inbound.
int PrintInboundBaseline(Db& db);

class EnforceDaemon {
public:
    EnforceDaemon(Db& db, IdentityResolver& id, DnsWatcher& dns, Enforcer& enf,
                  HabitTracker& habits)
        : db_(db), id_(id), dns_(dns), enf_(enf), habits_(habits) {}

    bool run(int seconds);   // install, subscribe, block until stop()/timeout, revert
    void stop();

    void handleEvent(const void* ev);  // WFP callback: record every event, then dispatch
    void handleDrop(const void* ev);   // novel-drop -> prompt path

private:
    int  installBaseline();  // permit stable (app, port) pairs; returns count
    int  installInboundBaseline();  // permit stable (app, local port) inbound services
    int  applyRules();       // apply enabled, unexpired rows from the rules table
    void reapply();          // clear + reinstall baseline + default-deny + rules (live edit)
    long long readRulesGen();// meta('rules_gen'), bumped by the dashboard on edit
    int  readAutonomy();     // meta('autonomy'): 0 prompt, 1 auto-allow known, 2 auto-allow all
    std::string readInboundMode();  // meta('inbound_mode'): 'off' (default) | 'enforce'
    bool appKnown(const std::string& key);  // app already has a learned habit
    void recordEvent(const void* ev);  // persist to flow_events + update habits (live feed)
    // Record an inbound connection OUR inbound catch-all blocked, deduped per
    // (app, local port, proto). Returns true the first time a given service is
    // seen, which is when the tray balloons about it (once, never again).
    bool recordInboundBlocked(const Identity& idn, int localPort, int proto,
                              const std::string& peer, const std::string& tsIso);
    void recordFeedback(const Identity& idn, const std::string& dest, int port,
                        const char* decision, int label);  // Phase 4e: log a prompt verdict
    void worker();           // drains the prompt queue (blocking prompts here)

    // A queued piece of user-facing work, drained off the WFP callback thread.
    // notify=true is an inbound balloon (no dialog, no decision); otherwise it's
    // the outbound block-notify-retry prompt.
    struct Req { std::string devPath, dest; int port; bool notify = false; std::string label; };

    Db& db_;
    IdentityResolver& id_;
    DnsWatcher& dns_;
    Enforcer& enf_;
    HabitTracker& habits_;
    void* insStmt_ = nullptr;   // sqlite3_stmt* for the flow_events insert

    std::mutex qmx_;
    std::condition_variable qcv_;
    std::deque<Req> queue_;
    std::unordered_set<std::string> handled_;   // dedup (app|dest|port)

    std::atomic<bool> stop_{false};
    void* stopEvent_ = nullptr;   // HANDLE
    std::thread worker_;
    double nextExpiry_ = 0;       // soonest future timed-allow expiry (epoch), 0 = none
    // Run-time ids of the 4 ALE connect/accept layers (resolved once when the
    // drop subscription's engine opens) so recordEvent attributes direction from
    // the event's layerId. 0xFFFF = unresolved. See ngwfp::ResolveAleLayers.
    unsigned short aleConnV4_ = 0xFFFF, aleConnV6_ = 0xFFFF,
                   aleAcceptV4_ = 0xFFFF, aleAcceptV6_ = 0xFFFF;
    EventCoalescer coalescer_;   // suppress rapid identical repeats in the raw log
};

}  // namespace ng
