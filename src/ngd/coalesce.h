// Rapid-repeat suppressor for the raw flow_events log.
//
// A system-wide WFP recorder sees enormous volumes of near-identical repeats:
// one stuck retry loop can be thousands of drops/hour to the same 5-tuple, and
// mDNS/SSDP/NetBIOS multicast repeats every second or two. Logging every one
// balloons flow_events (observed: ~164k rows/day, most of it repeats), which
// slows every scan over it (Per-app, the enforce baseline) and the recorder's
// own writes.
//
// This collapses "same flow, same verdict, seen again within the window" down to
// one row per window. On a continuous flood it inserts one row every `windowMs`
// (each fresh row still bubbles to the top of the Live view, so the flow stays
// visibly active) instead of one per packet. A 10s window turns a ~2/s retry
// loop into ~1 row / 10s - a 20x cut - while a genuinely new flow is never
// delayed, since its key hasn't been seen.
//
// It gates ONLY the raw-log insert. Habit learning already dedups by 5-tuple
// internally, and the enforce daemon's block-notify / inbound-review logic acts
// per event regardless - both keep running on every event, so suppressing the
// log row loses nothing but redundant rows. The trade-off is that the "Events"
// tallies then count coalesced activity rather than raw packets, which for a
// firewall dashboard is the more meaningful number anyway.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace ng {

class EventCoalescer {
public:
    explicit EventCoalescer(uint64_t windowMs = 10000) : windowMs_(windowMs) {}

    // True if this event should be logged (first sight of the key, or the last
    // logged sight is older than the window). False for a rapid repeat to skip.
    // Not internally locked - callers already hold the db mutex when they call
    // this, which serialises access to the map alongside the insert it guards.
    bool shouldRecord(const std::string& key, uint64_t nowMs) {
        auto it = last_.find(key);
        if (it != last_.end() && nowMs - it->second < windowMs_)
            return false;                       // rapid repeat - suppress the row
        last_[key] = nowMs;
        if (last_.size() > kMaxKeys) prune(nowMs);
        return true;
    }

private:
    // Bound memory: the working set of active flows is small (hundreds), so this
    // trips rarely; when it does, drop every entry already past its window - they
    // can only cause a fresh insert next time, which is correct anyway.
    void prune(uint64_t nowMs) {
        for (auto it = last_.begin(); it != last_.end();) {
            if (nowMs - it->second >= windowMs_) it = last_.erase(it);
            else ++it;
        }
    }

    static constexpr size_t kMaxKeys = 4096;
    uint64_t windowMs_;
    std::unordered_map<std::string, uint64_t> last_;
};

}  // namespace ng
