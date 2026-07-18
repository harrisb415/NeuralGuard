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

    // The view branches call this per refresh; forward to the table control.
    void MainWindow::SetHeaders(hstring const& h0, hstring const& h1, hstring const& h2,
                                hstring const& h3, hstring const& h4)
    {
        winrt::get_self<implementation::DataTable>(Tbl())->SetHeaders({ h0, h1, h2, h3, h4 });
    }

    void MainWindow::RefreshCurrent()
    {
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

            hstring totals = U8(to_string(detailEvents_) + " events · " + to_string(detailBlocked_) +
                                " blocked · " + to_string(detailDests_) + " destinations" +
                                (lastSeen.empty() ? "" : "  ·  last seen " + lastSeen) +
                                "   (last 14 days)");
            hstring trust = U8("Learned habits: " + std::to_string(habits) +
                               "    ML flags: " + (mlflags ? std::to_string(mlflags) : std::string("none")));
            winrt::get_self<implementation::DataTable>(Tbl())->SetAppDetail(true, totals, trust);
        }
        // (Settings/Insights use their own panels, not this table.)

        hstring emptyText = ok ? hstring(L"(no rows yet)") : U8("(DB not found at " + DbPathU8() + ")");
        winrt::get_self<implementation::DataTable>(Tbl())->SetRows(rows, curView_ == L"live", emptyText);
    }
}
