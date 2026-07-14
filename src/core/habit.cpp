#include "core/habit.h"
#include "core/db.h"

#include <windows.h>

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace ng {
namespace {

constexpr double kHalfLifeDays = 14.0;
constexpr unsigned long long kConnDedupMs = 15000;   // one connection = one obs
constexpr size_t kMaxRecentConns = 50000;

std::vector<int> ParseHist(const unsigned char* s, int n) {
    std::vector<int> v(n, 0);
    if (!s) return v;
    const char* p = reinterpret_cast<const char*>(s);
    int idx = 0;
    while (*p && idx < n) {
        v[idx++] = atoi(p);
        const char* c = strchr(p, ',');
        if (!c) break;
        p = c + 1;
    }
    return v;
}

std::string SerHist(const std::vector<int>& v) {
    std::string o;
    for (size_t i = 0; i < v.size(); ++i) { if (i) o += ','; o += std::to_string(v[i]); }
    return o;
}

}  // namespace

bool HabitTracker::newConnection(const std::string& token) {
    std::lock_guard<std::mutex> lk(connMutex_);
    unsigned long long now = GetTickCount64();
    auto it = recentConns_.find(token);
    if (it != recentConns_.end() && now - it->second < kConnDedupMs) {
        it->second = now;
        return false;
    }
    recentConns_[token] = now;
    if (recentConns_.size() > kMaxRecentConns) {
        for (auto j = recentConns_.begin(); j != recentConns_.end();) {
            if (now - j->second > kConnDedupMs) j = recentConns_.erase(j); else ++j;
        }
    }
    return true;
}

void HabitTracker::observe(const std::string& key, const std::string& label,
                           const std::string& dest, int port, int proto, const std::string& direction,
                           const std::string& tsIso, double nowEpoch, int hour, int dow,
                           const std::string& connToken) {
    if (!newConnection(connToken)) return;

    std::lock_guard<std::mutex> lk(db_.mutex());
    sqlite3* h = db_.handle();

    sqlite3_stmt* s = nullptr;
    sqlite3_prepare_v2(h,
        "SELECT id, count, last_epoch, hour_hist, dow_hist FROM habits"
        " WHERE process_key=? AND dest=? AND remote_port=? AND protocol=? AND direction=?;",
        -1, &s, nullptr);
    bindText(s, 1, key);
    bindText(s, 2, dest);
    sqlite3_bind_int(s, 3, port);
    sqlite3_bind_int(s, 4, proto);
    bindText(s, 5, direction);

    if (sqlite3_step(s) == SQLITE_ROW) {
        long long id = sqlite3_column_int64(s, 0);
        double cnt = sqlite3_column_double(s, 1);
        double lastEpoch = sqlite3_column_double(s, 2);
        std::vector<int> hh = ParseHist(sqlite3_column_text(s, 3), 24);
        std::vector<int> dh = ParseHist(sqlite3_column_text(s, 4), 7);
        sqlite3_finalize(s);

        double dtDays = (nowEpoch - lastEpoch) / 86400.0;
        if (dtDays < 0) dtDays = 0;
        double decayed = cnt * std::pow(0.5, dtDays / kHalfLifeDays) + 1.0;
        if (hour >= 0 && hour < 24) ++hh[hour];
        if (dow >= 0 && dow < 7) ++dh[dow];

        sqlite3_stmt* u = nullptr;
        sqlite3_prepare_v2(h,
            "UPDATE habits SET count=?, last_seen=?, last_epoch=?, hour_hist=?, dow_hist=?"
            " WHERE id=?;", -1, &u, nullptr);
        sqlite3_bind_double(u, 1, decayed);
        bindText(u, 2, tsIso);
        sqlite3_bind_double(u, 3, nowEpoch);
        bindText(u, 4, SerHist(hh));
        bindText(u, 5, SerHist(dh));
        sqlite3_bind_int64(u, 6, id);
        sqlite3_step(u);
        sqlite3_finalize(u);
    } else {
        sqlite3_finalize(s);
        std::vector<int> hh(24, 0), dh(7, 0);
        if (hour >= 0 && hour < 24) hh[hour] = 1;
        if (dow >= 0 && dow < 7) dh[dow] = 1;

        sqlite3_stmt* i = nullptr;
        sqlite3_prepare_v2(h,
            "INSERT INTO habits"
            "(process_key,process_label,dest,remote_port,protocol,direction,count,first_seen,last_seen,last_epoch,hour_hist,dow_hist)"
            " VALUES(?,?,?,?,?,?,1,?,?,?,?,?);", -1, &i, nullptr);
        bindText(i, 1, key);
        bindText(i, 2, label);
        bindText(i, 3, dest);
        sqlite3_bind_int(i, 4, port);
        sqlite3_bind_int(i, 5, proto);
        bindText(i, 6, direction);
        bindText(i, 7, tsIso);
        bindText(i, 8, tsIso);
        sqlite3_bind_double(i, 9, nowEpoch);
        bindText(i, 10, SerHist(hh));
        bindText(i, 11, SerHist(dh));
        sqlite3_step(i);
        sqlite3_finalize(i);
    }
}

}  // namespace ng
