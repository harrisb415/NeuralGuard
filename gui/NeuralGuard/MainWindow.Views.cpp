#include "pch.h"
#include "MainWindow.xaml.h"

#include "Db.h"
#include "Row.h"
#include "ColWidths.h"
#include "core/updater.h"
#include "core/version.h"
#include "SemBrush.h"
#include "core/cmd.h"
#include "Tray.h"
#include "MainWindow.Shared.h"

#include <microsoft.ui.xaml.window.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string_view>
#include <thread>

using namespace winrt;
using namespace winrt::Windows::Foundation;
using namespace winrt::Microsoft::UI::Xaml;
using namespace winrt::Microsoft::UI::Xaml::Controls;
using namespace winrt::Microsoft::UI::Xaml::Controls::Primitives;
using namespace winrt::Microsoft::UI::Xaml::Input;
using namespace winrt::Microsoft::UI::Xaml::Media;

namespace winrt::NeuralGuard::implementation
{

    void MainWindow::RefreshCurrent()
    {
        struct RowData { int64_t id; hstring c[5]; };
        std::vector<RowData> rows;
        ng::Db d;
        bool ok = d.open(DbPathU8().c_str());

        if (curView_ == L"live")
        {
            SetHeaders(L"Time", L"Verdict", L"Application", L"Destination", L"Port");
            std::string sql =
                "SELECT fe.id, fe.ts_utc, fe.verdict,"
                " COALESCE(pi.signer, pi.image_path, fe.image_path),"
                " COALESCE(fe.remote_domain, fe.remote_addr), fe.remote_port"
                " FROM flow_events fe LEFT JOIN process_identity pi ON fe.image_id=pi.id "
                "ORDER BY fe.id DESC LIMIT 300;";
            if (ok) d.each(sql.c_str(), [&](sqlite3_stmt* s) {
                std::string ts = ng::Db::ColText(s, 1);
                std::string tm = ts.size() >= 19 ? ts.substr(11, 8) : ts;
                rows.push_back({ sqlite3_column_int64(s, 0),
                                 { U8(tm), U8(ng::Db::ColText(s, 2)), U8(ng::Db::ColText(s, 3)),
                                   U8(ng::Db::ColText(s, 4)), to_hstring(sqlite3_column_int(s, 5)) } });
            });
        }
        else if (curView_ == L"habits")
        {
            SetHeaders(L"Count", L"Port", L"Application", L"Destination", L"");
            if (ok) d.each("SELECT process_label, dest, remote_port, round(count,1) FROM habits"
                           " ORDER BY count DESC LIMIT 1000;", [&](sqlite3_stmt* s) {
                rows.push_back({ 0, { to_hstring(sqlite3_column_double(s, 3)), to_hstring(sqlite3_column_int(s, 2)),
                                      U8(ng::Db::ColText(s, 0)), U8(ng::Db::ColText(s, 1)), L"" } });
            });
        }
        else if (curView_ == L"apps")
        {
            SetHeaders(L"Events", L"Blocked", L"Dests", L"Application", L"");
            // Reads the app_stats/app_dests rollup the daemon maintains, not the
            // raw flow_events - so this is O(#apps + #distinct-dests) and stays
            // fast no matter how large the event log grows. Same columns as before
            // (signer-grouped, distinct destinations). events/blocked and the
            // distinct-dest count are aggregated in SEPARATE CTEs and joined on the
            // app label - joining app_stats to app_dests directly would fan the
            // one-to-many out and multiply events by each app's dest count.
            // Unattributed (no image_id) events aren't apps and don't appear here
            // (they're still in Live).
            if (ok) d.each(
                "WITH stats AS ("
                "  SELECT COALESCE(pi.signer, pi.image_path, '(unknown)') app,"
                "         SUM(s.events) ev, SUM(s.blocked) bl"
                "  FROM app_stats s LEFT JOIN process_identity pi ON s.image_id = pi.id GROUP BY app),"
                " dests AS ("
                "  SELECT COALESCE(pi.signer, pi.image_path, '(unknown)') app,"
                "         COUNT(DISTINCT ad.remote_addr) dests"
                "  FROM app_dests ad LEFT JOIN process_identity pi ON ad.image_id = pi.id GROUP BY app)"
                " SELECT stats.app, COALESCE(dests.dests,0), stats.ev, stats.bl"
                " FROM stats LEFT JOIN dests ON stats.app = dests.app"
                " ORDER BY stats.ev DESC LIMIT 500;", [&](sqlite3_stmt* s) {
                rows.push_back({ 0, { to_hstring(sqlite3_column_int(s, 2)), to_hstring(sqlite3_column_int(s, 3)),
                                      to_hstring(sqlite3_column_int(s, 1)), U8(ng::Db::ColText(s, 0)), L"" } });
            });
        }
        else if (curView_ == L"rules")
        {
            SetHeaders(L"Action", L"Port", L"Info", L"Target (app / IP)", L"");
            if (ok) d.each("SELECT id, action, COALESCE(app_path, remote_addr, '(any)'),"
                           " COALESCE(remote_port,0), enabled, COALESCE(expires_epoch,0)"
                           " FROM rules ORDER BY id DESC;", [&](sqlite3_stmt* s) {
                int port = sqlite3_column_int(s, 3);
                std::string info = sqlite3_column_int(s, 4) ? "" : "disabled";
                if (sqlite3_column_double(s, 5) > 0) info += info.empty() ? "timed" : ", timed";
                rows.push_back({ sqlite3_column_int64(s, 0),
                                 { U8(ng::Db::ColText(s, 1)), port ? to_hstring(port) : hstring(L"any"),
                                   U8(info), U8(ng::Db::ColText(s, 2)), L"" } });
            });
        }
        else if (curView_ == L"flows")
        {
            // Phase 4: completed flows with their shadow-mode ML scores. Sortable
            // by clicking Anomaly (lower = more anomalous) or P(malicious).
            SetHeaders(L"Time", L"Application", L"Destination", L"Anomaly", L"P(malicious)");
            if (ok) d.each("SELECT ts_utc, COALESCE(process_label,''), COALESCE(dest,''), remote_port,"
                           " anomaly_score, malicious_score FROM flow_features ORDER BY id DESC LIMIT 300;",
                           [&](sqlite3_stmt* s) {
                std::string ts = ng::Db::ColText(s, 0);
                std::string tm = ts.size() >= 19 ? ts.substr(11, 8) : ts;
                std::string dest = ng::Db::ColText(s, 2) + ":" + std::to_string(sqlite3_column_int(s, 3));
                char anom[24] = "-", mal[24] = "-";
                if (sqlite3_column_type(s, 4) != SQLITE_NULL) snprintf(anom, sizeof anom, "%+.3f", sqlite3_column_double(s, 4));
                if (sqlite3_column_type(s, 5) != SQLITE_NULL) snprintf(mal, sizeof mal, "%.2f", sqlite3_column_double(s, 5));
                rows.push_back({ 0, { U8(tm), U8(ng::Db::ColText(s, 1)), U8(dest), U8(anom), U8(mal) } });
            });
        }
        else if (curView_ == L"flags")
        {
            // Phase 4d: active-mode demotions + anomaly review flags. Right-click a
            // row to remove it; "Clear all flags" is in the toolbar.
            SetHeaders(L"Time", L"Kind", L"Score", L"Application", L"Destination");
            if (ok) d.each("SELECT id, ts_utc, kind, printf('%.2f', score), COALESCE(process_label,''),"
                           " COALESCE(dest,'')||':'||remote_port FROM ml_flags ORDER BY id DESC LIMIT 500;",
                           [&](sqlite3_stmt* s) {
                std::string ts = ng::Db::ColText(s, 1);
                std::string tm = ts.size() >= 19 ? ts.substr(11, 8) : ts;
                rows.push_back({ sqlite3_column_int64(s, 0),
                                 { U8(tm), U8(ng::Db::ColText(s, 2)), U8(ng::Db::ColText(s, 3)),
                                   U8(ng::Db::ColText(s, 4)), U8(ng::Db::ColText(s, 5)) } });
            });
        }
        else if (curView_ == L"inbound")
        {
            // Inbound services WE blocked, for passive review. Inbound is never
            // prompted (a remote party must not be able to pop a dialog), so this
            // list is where the tray balloon sends you: right-click to allow.
            // C0 is the state, which TplGeneric renders as a pill - "blocked" hits
            // the Block palette (red), "ALLOWED" the Allow palette (green).
            SetHeaders(L"State", L"Port", L"Attempts", L"Application", L"Last peer");
            if (ok) d.each("SELECT id, allowed, local_port, attempts,"
                           " COALESCE(NULLIF(process_label,''), app_path), COALESCE(last_peer,'')"
                           " FROM inbound_blocked ORDER BY allowed, attempts DESC LIMIT 500;",
                           [&](sqlite3_stmt* s) {
                rows.push_back({ sqlite3_column_int64(s, 0),
                                 { sqlite3_column_int(s, 1) ? hstring{ L"ALLOWED" } : hstring{ L"blocked" },
                                   to_hstring(sqlite3_column_int(s, 2)),
                                   to_hstring(sqlite3_column_int(s, 3)),
                                   U8(ng::Db::ColText(s, 4)), U8(ng::Db::ColText(s, 5)) } });
            });
        }
        else if (curView_ == L"feedback")
        {
            // Phase 4e: prompt verdicts as training labels (read-only view).
            SetHeaders(L"Time", L"Decision", L"Label", L"Application", L"Destination");
            if (ok) d.each("SELECT ts_utc, decision, CASE label WHEN 1 THEN 'malicious' ELSE 'benign' END,"
                           " COALESCE(process_label,''), COALESCE(dest,'')||':'||remote_port"
                           " FROM feedback_labels ORDER BY id DESC LIMIT 500;", [&](sqlite3_stmt* s) {
                std::string ts = ng::Db::ColText(s, 0);
                std::string tm = ts.size() >= 19 ? ts.substr(11, 8) : ts;
                rows.push_back({ 0, { U8(tm), U8(ng::Db::ColText(s, 1)), U8(ng::Db::ColText(s, 2)),
                                      U8(ng::Db::ColText(s, 3)), U8(ng::Db::ColText(s, 4)) } });
            });
        }
        else if (curView_ == L"baseline")
        {
            // Phase 4d: the stable (app, port) permits enforce would install, with
            // each one's demote state. Right-click to distrust / re-trust an app.
            SetHeaders(L"Port", L"Conns", L"State", L"Application", L"Proto");
            if (ok) d.each(
                "SELECT fe.remote_port, COUNT(DISTINCT fe.local_port||'|'||fe.remote_addr) AS conns,"
                " EXISTS(SELECT 1 FROM ml_flags m WHERE m.kind='demote' AND m.app_path=pi.image_path"
                "   AND m.remote_port=fe.remote_port AND m.protocol=fe.protocol) AS demoted,"
                " pi.image_path, fe.protocol"
                " FROM flow_events fe JOIN process_identity pi ON fe.image_id=pi.id"
                " WHERE fe.remote_port>0 AND fe.remote_port<49152 AND pi.image_path LIKE '_:\\%'"
                "   AND fe.verdict IN ('ALLOW','CAPALLOW')"
                " GROUP BY pi.image_path, fe.protocol, fe.remote_port HAVING conns>=3"
                " ORDER BY demoted DESC, conns DESC LIMIT 500;", [&](sqlite3_stmt* s) {
                bool demoted = sqlite3_column_int(s, 2) != 0;
                int proto = sqlite3_column_int(s, 4);
                hstring pname = proto == 6 ? L"TCP" : proto == 17 ? L"UDP" : to_hstring(proto);
                // Stash the protocol in the row Id so a demote targets the exact
                // (app, port, proto) - the same key the enforce baseline groups by.
                rows.push_back({ proto, { to_hstring(sqlite3_column_int(s, 0)), to_hstring(sqlite3_column_int(s, 1)),
                                          demoted ? hstring(L"DEMOTED") : hstring(L"permitted"),
                                          U8(ng::Db::ColText(s, 3)), pname } });
            });
        }
        else if (curView_ == L"app-detail")
        {
            // Destination breakdown for one app: filter the raw log to this app's
            // image_id(s) (a signer can span several binaries) and group by
            // destination + port + type. Fast via idx_flow_events_image_id.
            SetHeaders(L"Destination", L"Port", L"Type", L"Events", L"Blocked");
            std::string label = to_string(detailApp_);
            if (ok)
            {
                sqlite3_stmt* s = nullptr;
                if (sqlite3_prepare_v2(d.handle(),
                        "SELECT COALESCE(fe.remote_domain, fe.remote_addr, '(none)'),"
                        " COALESCE(fe.remote_port, 0), fe.protocol, fe.direction,"
                        " COUNT(*), SUM(CASE WHEN fe.verdict LIKE '%DROP%' OR fe.verdict='BLOCK' THEN 1 ELSE 0 END)"
                        " FROM flow_events fe"
                        " WHERE fe.image_id IN (SELECT id FROM process_identity"
                        "   WHERE COALESCE(signer, image_path, '(unknown)') = ?)"
                        " GROUP BY 1, 2, fe.protocol, fe.direction"
                        " ORDER BY 5 DESC LIMIT 500;", -1, &s, nullptr) == SQLITE_OK)
                {
                    sqlite3_bind_text(s, 1, label.c_str(), (int)label.size(), SQLITE_TRANSIENT);
                    while (sqlite3_step(s) == SQLITE_ROW)
                    {
                        int proto = sqlite3_column_int(s, 2);
                        std::string dir = ng::Db::ColText(s, 3);
                        hstring pname = proto == 6 ? L"TCP" : proto == 17 ? L"UDP"
                                      : proto == 1 ? L"ICMP" : proto == 58 ? L"ICMPv6"
                                      : proto ? to_hstring(proto) : hstring(L"");
                        // "TCP out" / "UDP in" / just the proto if direction unknown.
                        hstring type = dir.empty() ? pname
                                     : pname + L" " + U8(dir);
                        rows.push_back({ 0, { U8(ng::Db::ColText(s, 0)), to_hstring(sqlite3_column_int(s, 1)),
                                              type, to_hstring(sqlite3_column_int(s, 4)),
                                              to_hstring(sqlite3_column_int(s, 5)) } });
                    }
                    sqlite3_finalize(s);
                }
            }

            // Header: totals (reused from the clicked row) + trust signals.
            std::string firstSeen, lastSeen;
            if (ok) d.each_bind(
                "SELECT MIN(ts_utc), MAX(ts_utc) FROM flow_events"
                " WHERE image_id IN (SELECT id FROM process_identity"
                "   WHERE COALESCE(signer, image_path, '(unknown)') = ?);",
                label, [&](sqlite3_stmt* s) {
                std::string mn = ng::Db::ColText(s, 0), mx = ng::Db::ColText(s, 1);
                firstSeen = mn.size() >= 19 ? mn.substr(11, 8) : mn;
                lastSeen  = mx.size() >= 19 ? mx.substr(11, 8) : mx;
            });
            int habits = 0, mlflags = 0;
            if (ok) d.each_bind("SELECT COUNT(*) FROM habits WHERE process_label = ?;", label,
                                [&](sqlite3_stmt* s) { habits = sqlite3_column_int(s, 0); });
            if (ok) d.each_bind(
                "SELECT COUNT(*) FROM ml_flags WHERE app_path IN (SELECT image_path FROM process_identity"
                "  WHERE COALESCE(signer, image_path, '(unknown)') = ?);", label,
                [&](sqlite3_stmt* s) { mlflags = sqlite3_column_int(s, 0); });

            AppDetailTotals().Text(U8(to_string(detailEvents_) + " events · " + to_string(detailBlocked_) +
                                      " blocked · " + to_string(detailDests_) + " destinations" +
                                      (lastSeen.empty() ? "" : "  ·  last seen " + lastSeen) +
                                      "   (last 14 days)"));
            AppDetailTrust().Text(U8("Learned habits: " + std::to_string(habits) +
                                     "    ML flags: " + (mlflags ? std::to_string(mlflags) : std::string("none"))));
        }
        // (the Settings and Digest views use their own panels, not the data table)

        if (!filter_.empty())
        {
            std::string f = to_string(filter_);
            for (auto& ch : f) ch = (char)tolower((unsigned char)ch);
            rows.erase(std::remove_if(rows.begin(), rows.end(), [&](RowData const& r) {
                for (int i = 0; i < 5; ++i)
                {
                    std::string c = to_string(r.c[i]);
                    for (auto& ch : c) ch = (char)tolower((unsigned char)ch);
                    if (c.find(f) != std::string::npos) return false;   // a column matches - keep
                }
                return true;   // nothing matched - drop
            }), rows.end());
        }

        if (rows.empty())
            rows.push_back({ 0, { L"", L"", !filter_.empty() ? hstring(L"(no matches)")
                                          : ok ? hstring(L"(no rows yet)")
                                               : U8("(DB not found at " + DbPathU8() + ")"), L"", L"" } });

        if (sortCol_ >= 0 && sortCol_ < 5)
        {
            int col = sortCol_; bool asc = sortAsc_;
            std::stable_sort(rows.begin(), rows.end(), [col, asc](RowData const& a, RowData const& b) {
                std::string sa = to_string(a.c[col]), sb = to_string(b.c[col]);
                char* ea = nullptr; char* eb = nullptr;
                double da = std::strtod(sa.c_str(), &ea), db = std::strtod(sb.c_str(), &eb);
                bool na = !sa.empty() && ea && *ea == 0, nb = !sb.empty() && eb && *eb == 0;
                int cmp;
                if (na && nb) cmp = da < db ? -1 : da > db ? 1 : 0;
                else {
                    for (auto& ch : sa) ch = (char)tolower((unsigned char)ch);
                    for (auto& ch : sb) ch = (char)tolower((unsigned char)ch);
                    int c = sa.compare(sb); cmp = c < 0 ? -1 : c > 0 ? 1 : 0;
                }
                return asc ? cmp < 0 : cmp > 0;
            });
        }

        // Remember the selected row (by id) and the scroll position, so both
        // survive the wholesale rebuild below - a live-updating list (Live
        // refreshes every second) is otherwise unscrollable, since replacing
        // ItemsSource resets a ListView's ScrollViewer to the top on every tick.
        int64_t selId = 0;
        if (auto sel = DataList().SelectedItem().try_as<NeuralGuard::Row>()) selId = sel.Id();
        auto scroller = FindScrollViewer(DataList());
        double vOffset = scroller ? scroller.VerticalOffset() : 0;

        // Live refreshes once a second; a wholesale ItemsSource replacement (every
        // other view's approach, still used below) flickers every tick, since a
        // new ItemsSource is entirely new content to WinUI even when only a
        // couple of rows actually changed. While Live's already-realized
        // collection is valid (liveItemsValid_ - cleared on every tab switch by
        // ShowView), mutate it in place instead.
        //
        // A naive index-aligned prefix/suffix diff does NOT work here: the query
        // is capped at LIMIT 300, so once the feed is full, every new row at the
        // front pushes one off the back - which shifts every surviving row's
        // INDEX by however many new ones arrived. Comparing old[i] to new[i]
        // then finds nothing matching anywhere, degenerating to "remove all,
        // insert all" - worse than the ItemsSource swap it was meant to replace.
        //
        // The right model exploits what this feed actually is: zero or more
        // brand-new rows prepended at the front, then the SAME old rows in the
        // same relative order, with some possibly trimmed off the tail by the
        // LIMIT. So: find where the old list's first row reappears in the new
        // list (that position is how many rows are genuinely new), then verify
        // the rest really does line up before trusting it - if a filter or sort
        // is active this won't hold, and falling through to a full rebuild is
        // correct instead of applying a wrong patch.
        if (curView_ == L"live" && liveItemsValid_ && !liveIds_.empty())
        {
            std::vector<int64_t> newIds;
            newIds.reserve(rows.size());
            for (auto const& r : rows) newIds.push_back(r.id);

            size_t oldN = liveIds_.size(), newN = newIds.size();
            size_t k = 0;
            while (k < newN && newIds[k] != liveIds_[0]) ++k;

            bool aligned = k < newN;
            size_t overlap = 0;
            if (aligned)
            {
                overlap = (oldN < newN - k) ? oldN : (newN - k);
                for (size_t i = 0; i < overlap; ++i)
                    if (newIds[k + i] != liveIds_[i]) { aligned = false; break; }
            }

            if (aligned)
            {
                for (size_t i = 0; i < k; ++i)
                {
                    auto const& r = rows[i];
                    liveItems_.InsertAt((uint32_t)i, MakeRow(r.id, r.c[0], r.c[1], r.c[2], r.c[3], r.c[4]));
                }
                while (liveItems_.Size() > (uint32_t)newN) liveItems_.RemoveAt(liveItems_.Size() - 1);
                liveIds_ = std::move(newIds);

                if (selId != 0)
                {
                    uint32_t idx = 0;
                    for (auto const& it : liveItems_)
                    {
                        if (auto r = it.try_as<NeuralGuard::Row>(); r && r.Id() == selId)
                        {
                            DataList().SelectedIndex((int32_t)idx);
                            break;
                        }
                        ++idx;
                    }
                }
                // No scroll-offset restore needed here: inserting/removing
                // individual items doesn't reset the ScrollViewer the way a full
                // ItemsSource replacement does.
                return;
            }
            // Not aligned (filter/sort active, or a burst bigger than the page) -
            // fall through to the full rebuild below.
        }

        auto items = single_threaded_observable_vector<IInspectable>();
        for (auto const& r : rows)
            items.Append(MakeRow(r.id, r.c[0], r.c[1], r.c[2], r.c[3], r.c[4]));
        DataList().ItemsSource(items);

        if (curView_ == L"live")
        {
            // First landing on Live (or the tick right after a tab switch): seed
            // the persisted collection so subsequent ticks can diff against it.
            liveItems_ = items;
            liveIds_.clear();
            liveIds_.reserve(rows.size());
            for (auto const& r : rows) liveIds_.push_back(r.id);
            liveItemsValid_ = true;
        }

        if (selId != 0)
        {
            uint32_t idx = 0;
            for (auto const& it : items)
            {
                if (auto r = it.try_as<NeuralGuard::Row>(); r && r.Id() == selId)
                {
                    DataList().SelectedIndex((int32_t)idx);
                    break;
                }
                ++idx;
            }
        }

        // Restoring immediately would race the layout pass that the new
        // ItemsSource still needs to run (the ScrollViewer's scrollable extent
        // isn't updated yet) - defer to the next UI-thread tick, by which point
        // WinUI has measured/arranged the new items.
        if (vOffset > 0)
        {
            DispatcherQueue().TryEnqueue([this, vOffset] {
                if (auto sv = FindScrollViewer(DataList()))
                    sv.ChangeView(nullptr, box_value(vOffset).as<IReference<double>>(), nullptr, true);
            });
        }
    }
}
