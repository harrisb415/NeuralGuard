// HabitTracker: maintains the learned baseline. For each distinct
// (process key, destination, port, protocol) it keeps an exponentially-decaying
// observation count plus hour-of-day / day-of-week histograms. This is the
// "boring math" habit engine from docs/DESIGN.md (section 5) - no ML.
//
// Multiple WFP events fire per connection, so observations are de-duplicated by
// 5-tuple within a short window (one connection = one observation).
#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

namespace ng {

class Db;

class HabitTracker {
public:
    explicit HabitTracker(Db& db) : db_(db) {}

    // Record one observed connection. `connToken` is the 5-tuple used for
    // dedup; `tsIso`/`nowEpoch` are the event time; `hour` 0-23, `dow` 0-6 (0=Sun).
    void observe(const std::string& processKey, const std::string& processLabel,
                 const std::string& dest, int port, int proto,
                 const std::string& tsIso, double nowEpoch, int hour, int dow,
                 const std::string& connToken);

private:
    bool newConnection(const std::string& token);

    Db& db_;
    std::mutex connMutex_;
    std::unordered_map<std::string, unsigned long long> recentConns_;  // 5-tuple -> tick
};

}  // namespace ng
