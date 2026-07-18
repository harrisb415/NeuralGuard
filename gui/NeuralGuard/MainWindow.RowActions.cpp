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

    // Direct-DB helpers (same pattern as the rules editor: write + bump rules_gen
    // so a running enforce daemon re-applies the baseline live).
    void MainWindow::DemoteApp(hstring const& appPath, int port, int proto)
    {
        ng::Db d;
        if (!d.open(DbPathU8().c_str())) return;
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(d.handle(),
            "INSERT OR IGNORE INTO ml_flags(ts_utc,kind,process_key,process_label,app_path,dest,"
            "remote_port,protocol,score) VALUES(strftime('%Y-%m-%dT%H:%M:%SZ','now'),'demote','',"
            "'(manual)',?,'(manual)',?,?,1.0);", -1, &s, nullptr);
        std::string p = to_string(appPath);
        sqlite3_bind_text(s, 1, p.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 2, port);
        sqlite3_bind_int(s, 3, proto);
        sqlite3_step(s); sqlite3_finalize(s);
        sqlite3_exec(d.handle(), "UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='rules_gen';", nullptr, nullptr, nullptr);
        Notify(L"Demoted - it will prompt on its next connection.", InfoBarSeverity::Success);
    }

    void MainWindow::RetrustApp(hstring const& appPath, int port, int proto)
    {
        ng::Db d;
        if (!d.open(DbPathU8().c_str())) return;
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(d.handle(),
            "DELETE FROM ml_flags WHERE kind='demote' AND app_path=? AND remote_port=? AND protocol=?;",
            -1, &s, nullptr);
        std::string p = to_string(appPath);
        sqlite3_bind_text(s, 1, p.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 2, port);
        sqlite3_bind_int(s, 3, proto);
        sqlite3_step(s); sqlite3_finalize(s);
        sqlite3_exec(d.handle(), "UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='rules_gen';", nullptr, nullptr, nullptr);
        Notify(L"Re-trusted - it auto-permits again next time enforcement runs.", InfoBarSeverity::Success);
    }

    void MainWindow::RemoveFlag(int64_t id)
    {
        ng::Db d;
        if (!d.open(DbPathU8().c_str())) return;
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(d.handle(), "DELETE FROM ml_flags WHERE id=?;", -1, &s, nullptr);
        sqlite3_bind_int64(s, 1, id);
        sqlite3_step(s); sqlite3_finalize(s);
        sqlite3_exec(d.handle(), "UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='rules_gen';", nullptr, nullptr, nullptr);
        Notify(L"Flag removed.", InfoBarSeverity::Success);
    }

    // Permit (or revoke) an inbound service from the blocked-inbound review list.
    // Bumping rules_gen makes a running enforce daemon re-apply, which rebuilds the
    // inbound baseline including this row - so it takes effect without a restart.
    void MainWindow::SetInboundAllowed(int64_t id, bool allowed)
    {
        ng::Db d;
        if (!d.open(DbPathU8().c_str())) return;
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(d.handle(), "UPDATE inbound_blocked SET allowed=? WHERE id=?;", -1, &s, nullptr);
        sqlite3_bind_int(s, 1, allowed ? 1 : 0);
        sqlite3_bind_int64(s, 2, id);
        sqlite3_step(s); sqlite3_finalize(s);
        sqlite3_exec(d.handle(), "UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='rules_gen';", nullptr, nullptr, nullptr);
        Notify(allowed ? L"Inbound service allowed (applies live)."
                       : L"Inbound service blocked again (applies live).",
               InfoBarSeverity::Success);
    }

    // Raised by the DataTable control with the clicked row, its container (menu
    // anchor) and the pointer position. The control already selected the row; we
    // build the per-view context menu and show it.
    void MainWindow::ShowRowMenu(NeuralGuard::Row const& row, FrameworkElement const& anchor, Point const& pos)
    {
        ctxRow_ = row;

        MenuFlyout menu;
        auto add = [&](hstring const& text, std::function<void()> action) {
            MenuFlyoutItem it;
            it.Text(text);
            it.Click([action](IInspectable const&, RoutedEventArgs const&) { action(); });
            menu.Items().Append(it);
        };

        if (curView_ == L"rules")
        {
            if (ctxRow_.Id() == 0) return;
            add(L"Delete rule", [this] { DelRule(ctxRow_.Id()); RefreshCurrent(); });
        }
        else if (curView_ == L"live")
        {
            int64_t id = ctxRow_.Id();
            add(L"Block this destination", [this, id] { AddRuleFromEvent(id, true, false, 0); });
            add(L"Allow this destination", [this, id] { AddRuleFromEvent(id, false, false, 0); });
            add(L"Allow this destination for 1 hour", [this, id] { AddRuleFromEvent(id, false, false, 3600); });
            add(L"Allow this app (any port)", [this, id] { AddRuleFromEvent(id, false, true, 0); });
        }
        else if (curView_ == L"inbound")
        {
            int64_t id = ctxRow_.Id();
            if (id == 0) return;
            const bool allowed = (ctxRow_.C0() == L"ALLOWED");
            if (allowed)
                add(L"Block this service again", [this, id] { SetInboundAllowed(id, false); RefreshCurrent(); });
            else
                add(L"Allow this service", [this, id] { SetInboundAllowed(id, true); RefreshCurrent(); });
        }
        else if (curView_ == L"baseline")
        {
            hstring path = ctxRow_.C3();
            int port = _wtoi(ctxRow_.C0().c_str());
            int proto = (int)ctxRow_.Id();   // stashed protocol (6=TCP, 17=UDP)
            if (path.empty() || port == 0) return;
            if (ctxRow_.C2() == L"DEMOTED")
                add(L"Re-trust this app", [this, path, port, proto] { RetrustApp(path, port, proto); RefreshCurrent(); });
            else
                add(L"Distrust (demote) this app", [this, path, port, proto] { DemoteApp(path, port, proto); RefreshCurrent(); });
        }
        else if (curView_ == L"flags")
        {
            int64_t id = ctxRow_.Id();
            if (id == 0) return;
            add(L"Remove this flag", [this, id] { RemoveFlag(id); RefreshCurrent(); });
        }
        else if (curView_ == L"apps")
        {
            auto r = ctxRow_;
            if (r.C3().empty()) return;   // the "(no rows yet)" placeholder
            add(L"View destinations", [this, r] { OpenAppDetail(r); });
        }
        if (menu.Items().Size() == 0) return;

        menuOpen_ = true;               // pause the live refresh so the menu isn't torn down
        menu.Closed([this](auto&&, auto&&) { menuOpen_ = false; });

        FlyoutShowOptions opt;
        opt.Position(pos);
        menu.ShowAt(anchor, opt);
    }

    // Double-click a Per-app row = the same drill-in as the right-click "View
    // destinations" item, as a shortcut. Raised by the DataTable control.
    void MainWindow::OnRowInvoked(NeuralGuard::Row const& row)
    {
        if (curView_ == L"apps" && !row.C3().empty()) OpenAppDetail(row);
    }

    void MainWindow::OnAppDetailBack(IInspectable const&, RoutedEventArgs const&)
    {
        ShowView(L"apps");
    }

    // Stash the clicked row's app label + its totals (so the header needs no
    // re-query), then switch to the detail view which renders the breakdown.
    void MainWindow::OpenAppDetail(NeuralGuard::Row const& row)
    {
        detailApp_     = row.C3();   // Application column
        detailEvents_  = row.C0();
        detailBlocked_ = row.C1();
        detailDests_   = row.C2();
        ShowView(L"app-detail");
    }

    void MainWindow::DelRule(int64_t id)
    {
        ng::Db d;
        if (!d.open(DbPathU8().c_str())) return;
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(d.handle(), "DELETE FROM rules WHERE id=?;", -1, &s, nullptr);
        sqlite3_bind_int64(s, 1, id);
        sqlite3_step(s); sqlite3_finalize(s);
        sqlite3_exec(d.handle(), "UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='rules_gen';", nullptr, nullptr, nullptr);
        Notify(L"Rule deleted (applies live).", InfoBarSeverity::Success);
    }

    void MainWindow::AddRuleFromEvent(int64_t eventId, bool block, bool useApp, int ttlSeconds)
    {
        ng::Db d;
        if (!d.open(DbPathU8().c_str())) return;

        std::string ip, path; int port = 0;
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(d.handle(),
            "SELECT fe.remote_addr, fe.remote_port, COALESCE(pi.image_path, fe.image_path)"
            " FROM flow_events fe LEFT JOIN process_identity pi ON fe.image_id=pi.id WHERE fe.id=?;",
            -1, &s, nullptr);
        sqlite3_bind_int64(s, 1, eventId);
        if (sqlite3_step(s) == SQLITE_ROW)
        {
            ip = ng::Db::ColText(s, 0);
            port = sqlite3_column_int(s, 1);
            path = ng::Db::ColText(s, 2);
        }
        sqlite3_finalize(s);

        if (!useApp && ip.find('.') == std::string::npos) { Notify(L"That row has no IPv4 destination.", InfoBarSeverity::Warning); return; }
        if (useApp && (path.size() < 3 || path[1] != ':')) { Notify(L"That row has no app path.", InfoBarSeverity::Warning); return; }

        sqlite3_stmt* ins = nullptr;
        sqlite3_prepare_v2(d.handle(),
            "INSERT INTO rules(action,app_path,remote_addr,remote_port,protocol,enabled,expires_epoch,created_at)"
            " VALUES(?,?,?,?,?,1,?,datetime('now'));", -1, &ins, nullptr);
        std::string action = block ? "block" : "permit";
        sqlite3_bind_text(ins, 1, action.c_str(), -1, SQLITE_TRANSIENT);
        if (useApp)
        {
            sqlite3_bind_text(ins, 2, path.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_null(ins, 3); sqlite3_bind_null(ins, 4); sqlite3_bind_null(ins, 5);
        }
        else
        {
            sqlite3_bind_null(ins, 2);
            sqlite3_bind_text(ins, 3, ip.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(ins, 4, port); sqlite3_bind_int(ins, 5, 6);
        }
        if (ttlSeconds > 0) sqlite3_bind_double(ins, 6, (double)time(nullptr) + ttlSeconds);
        else sqlite3_bind_null(ins, 6);
        sqlite3_step(ins); sqlite3_finalize(ins);
        sqlite3_exec(d.handle(), "UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='rules_gen';", nullptr, nullptr, nullptr);

        hstring what = useApp ? U8(path) : U8(ip + ":" + std::to_string(port));
        Notify((block ? L"Blocked " : L"Allowed ") + what + L" (applies live).", InfoBarSeverity::Success);
    }
}
