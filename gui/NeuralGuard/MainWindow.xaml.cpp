#include "pch.h"
#include "MainWindow.xaml.h"
#if __has_include("MainWindow.g.cpp")
#include "MainWindow.g.cpp"
#endif

#include "Db.h"
#include "Row.h"
#include "ColWidths.h"
#include "core/updater.h"              // shared in-app updater (compiled from src/core)
#include "core/version.h"              // NG_VERSION, for the About section
#include "SemBrush.h"                  // SemBrush::SetLightTheme (converter can't see ActualTheme)
#include "core/cmd.h"                  // command pipe to the running service
#include "Tray.h"                      // the tray icon, formerly ngtray.exe
#include "MainWindow.Shared.h"

#include <microsoft.ui.xaml.window.h>   // IWindowNative -> HWND for the file dialogs

#include <algorithm>
#include <array>
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

    MainWindow::MainWindow()
    {
        InitializeComponent();
        Title(L"NeuralGuard");
        SystemBackdrop(MicaBackdrop{});

        // Integrated neon title bar: draw our own bar in the caption area and make
        // its empty space draggable. Caption buttons blend with the dark surface.
        ExtendsContentIntoTitleBar(true);
        SetTitleBar(DragRegion());
        // Caption colours are applied by ApplyCaptionColors (called from
        // SyncThemeDependents) - they're an AppWindow API, not XAML resources,
        // so they can't follow ThemeResource and must be re-set per theme.

        // Window/taskbar icon: AppWindow doesn't inherit the exe's embedded .rc
        // icon on its own, so point it at the loose copy deployed next to the
        // exe (NeuralGuard.rc covers Explorer/shortcut icons; this covers the
        // live window, taskbar, and Alt-Tab).
        {
            wchar_t exePath[MAX_PATH]{};
            GetModuleFileNameW(nullptr, exePath, MAX_PATH);
            std::wstring dir(exePath);
            size_t p = dir.find_last_of(L"\\/");
            if (p != std::wstring::npos) dir = dir.substr(0, p);
            AppWindow().SetIcon(dir + L"\\NeuralGuard.ico");
        }

        // Wire the data table's row actions back to us (it owns the list; the menus
        // and DB writes stay here).
        {
            auto tbl = winrt::get_self<implementation::DataTable>(Tbl());
            tbl->SetOnContext([this](NeuralGuard::Row row, FrameworkElement anchor, Point pos) {
                ShowRowMenu(row, anchor, pos);
            });
            tbl->SetOnInvoke([this](NeuralGuard::Row row) { OnRowInvoked(row); });
        }

        // Apply the persisted theme before first paint. Defaults to dark - the
        // designed look - so nothing changes for anyone who never touches the
        // setting; App.xaml no longer forces Dark app-wide (see the note there).
        ApplyTheme(MetaGet("theme", "dark"));

        StartTray();

        timer_ = DispatcherTimer{};
        timer_.Interval(std::chrono::seconds(1));
        timer_.Tick({ this, &MainWindow::OnTick });
        timer_.Start();

        toastTimer_ = DispatcherTimer{};
        toastTimer_.Interval(std::chrono::seconds(6));
        toastTimer_.Tick([this](IInspectable const&, IInspectable const&) {
            toastTimer_.Stop();
            Toast().IsOpen(false);
        });

        UpdateMode();
        ShowView(L"live");
        NavList().SelectedIndex(0);   // highlight Live in the sidebar
    }

    // The dashboard always lives in a "dashboard\" subfolder of the install
    // root (ngd.exe, ngctl.exe, and ngpolicy.db live one level up - see
    // ngtray's ExeDir()+"\\dashboard" convention). Derive that root from our
    // own module path instead of assuming a fixed %USERPROFILE%\NeuralGuard
    // location, so the app works wherever it's installed.
    std::wstring MainWindow::NgDir()
    {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::wstring dir(path);
        size_t p = dir.find_last_of(L"\\/");
        dir = (p == std::wstring::npos) ? L"." : dir.substr(0, p);          // ...\dashboard
        size_t q = dir.find_last_of(L"\\/");
        return (q == std::wstring::npos) ? dir : dir.substr(0, q);          // install root
    }

    std::string MainWindow::DbPathU8()
    {
        std::wstring w = NgDir() + L"\\ngpolicy.db";
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string s(n, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
        return s;
    }

    void MainWindow::Log(hstring const& line)
    {
        Notify(line, InfoBarSeverity::Informational);
    }
    void MainWindow::Notify(hstring const& message, InfoBarSeverity severity)
    {
        hstring title = L"NeuralGuard";
        switch (severity)
        {
            case InfoBarSeverity::Success: title = L"Success";  break;
            case InfoBarSeverity::Warning: title = L"Heads up";  break;
            case InfoBarSeverity::Error:   title = L"Error";     break;
            default:                       title = L"NeuralGuard"; break;
        }
        Toast().Title(title);
        Toast().Severity(severity);
        Toast().Message(message);
        Toast().IsOpen(true);
        toastTimer_.Stop();
        toastTimer_.Start();   // restart the auto-dismiss countdown
    }

    void MainWindow::UpdateMode()
    {
        ng::Db d;
        std::string mode = "idle";
        if (d.open(DbPathU8().c_str()))
        {
            std::string m = d.scalar("SELECT v FROM meta WHERE k='mode';");
            if (!m.empty()) mode = m;
        }
        ModeText().Text(to_hstring(mode));
        ngtray::SetMode(mode);   // one poller drives both the status bar and the tray icon
    }

    // Own the tray icon in this process. It used to be a whole separate executable
    // (ngtray.exe) purely because a LocalSystem service can't show UI - but that
    // never meant the frontend had to be two programs. Two of them meant two mode
    // pollers, two panic paths that drifted, and a tray whose Status could only
    // shell out to a cmd.exe window, having no UI of its own to render into.
    void MainWindow::StartTray()
    {
        ngtray::Callbacks cb;
        cb.openDashboard = [this] { ShowFromTray(); };
        cb.quit = [this] { ExitApp(); };

        // Status and Panic now render in-app instead of spawning a console.
        cb.showStatus = [this] {
            bool ok = false;
            const std::string reply = ng::CmdSend("STATUS", &ok);
            ShowFromTray();
            Notify(ok ? U8(reply) : hstring{ L"Service not reachable (not installed or not running)." },
                   ok ? InfoBarSeverity::Informational : InfoBarSeverity::Warning);
        };
        cb.panic = [this] { OnPanic(nullptr, nullptr); };

        // Runs on the pipe thread, so it must not touch XAML. MessageBoxW is
        // thread-safe and is what the block-notify-retry flow has always used.
        cb.prompt = [](std::wstring const& app, std::wstring const& dest, std::wstring const& port) -> char {
            std::wstring text = app + L"\n\nwants to connect to  " + dest + L":" + port +
                L"\n\nYes = Always allow this app on this port"
                L"\nNo = Allow once"
                L"\nCancel = Block";
            int r = MessageBoxW(nullptr, text.c_str(), L"NeuralGuard",
                                MB_YESNOCANCEL | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND);
            return (r == IDYES) ? 'A' : (r == IDNO) ? 'O' : 'B';
        };

        ngtray::Start(GetModuleHandleW(nullptr), cb);

        // Closing the window hides to tray. The tray icon is the app's real
        // lifetime now: an installed service with no frontend running would leave
        // nothing to answer ngd's prompts or show you what it's doing.
        AppWindow().Closing([this](auto&&, Microsoft::UI::Windowing::AppWindowClosingEventArgs const& args) {
            args.Cancel(true);
            AppWindow().Hide();
        });
    }

    void MainWindow::ShowFromTray()
    {
        AppWindow().Show();
        HWND h = WindowHandle();
        if (h) { ShowWindow(h, SW_RESTORE); SetForegroundWindow(h); }
    }

    void MainWindow::ExitApp()
    {
        ngtray::Stop();          // pull the icon before the process goes, or it ghosts
        Application::Current().Exit();
    }

    void MainWindow::ShowView(hstring const& tag)
    {
        curView_ = tag;
        viewReady_ = true;
        hstring title = L"Live";
        if (tag == L"rules") title = L"Rules";
        else if (tag == L"habits") title = L"Habits";
        else if (tag == L"apps") title = L"Per-app";
        else if (tag == L"flows") title = L"Flows";
        else if (tag == L"flags") title = L"Flags";
        else if (tag == L"baseline") title = L"Baseline";
        else if (tag == L"inbound") title = L"Inbound";
        else if (tag == L"feedback") title = L"Feedback";
        else if (tag == L"insights") title = L"Insights";
        else if (tag == L"settings") title = L"Settings";
        else if (tag == L"app-detail") title = detailApp_;   // the drilled-into app
        ViewTitle().Text(title);

        // app-detail is a sub-view of Per-app: its back button shows only here (the
        // trust card lives in the DataTable control, set by RefreshCurrent).
        bool appDetail = (tag == L"app-detail");
        AppDetailBack().Visibility(appDetail ? Visibility::Visible : Visibility::Collapsed);

        bool settings = (tag == L"settings");
        bool insights = (tag == L"insights");
        bool table = !settings && !insights;   // the shared sortable data table
        Tbl().Visibility(table ? Visibility::Visible : Visibility::Collapsed);
        SettingsPanel().Visibility(settings ? Visibility::Visible : Visibility::Collapsed);
        InsightsPanel().Visibility(insights ? Visibility::Visible : Visibility::Collapsed);
        SearchBox().Visibility(table ? Visibility::Visible : Visibility::Collapsed);
        RulesTools().Visibility((tag == L"rules") ? Visibility::Visible : Visibility::Collapsed);
        FlagsTools().Visibility((tag == L"flags") ? Visibility::Visible : Visibility::Collapsed);
        FeedbackTools().Visibility((tag == L"feedback") ? Visibility::Visible : Visibility::Collapsed);
        SearchBox().Text(L"");   // reset the filter when switching views (fires OnSearchChanged)
        if (settings) LoadSettings();
        else if (insights)
        {
            // The Insights tab is its own UserControl now; reach its impl (same
            // project) to inject navigation and rebuild its cards from the DB.
            auto v = winrt::get_self<implementation::InsightsView>(InsightsPanel());
            v->SetNavigate([this](hstring tag) { NavTo(tag); });
            v->Refresh(DbPathU8());
        }
        else
        {
            // Pick the row template for this view - pill badges where verdict/state/
            // kind/label tokens live, red Blocked for Per-app, plain otherwise.
            hstring tpl = L"TplGeneric";
            if (tag == L"live" || tag == L"flags") tpl = L"TplLive";
            else if (tag == L"baseline") tpl = L"TplBaseline";
            else if (tag == L"feedback") tpl = L"TplFeedback";
            else if (tag == L"apps") tpl = L"TplPerApp";
            else if (tag == L"flows") tpl = L"TplFlows";
            // app-detail uses the plain generic template (destination breakdown).

            // Per-view column widths (the * column fills; 0 = unused 5th column).
            std::array<double, 5> w{ 130, 128, -1, 210, 84 };
            if (tag == L"flags")           w = { 120, 120, 90, -1, 240 };
            else if (tag == L"baseline")   w = { 80, 90, 130, -1, 80 };
            else if (tag == L"feedback")   w = { 120, 120, 120, -1, 220 };
            else if (tag == L"apps")       w = { 120, 110, 100, -1, 0 };
            else if (tag == L"flows")      w = { 120, -1, 230, 110, 110 };
            else if (tag == L"rules")      w = { 120, 90, 120, -1, 0 };
            else if (tag == L"inbound")    w = { 110, 80, 90, -1, 150 };
            else if (tag == L"habits")     w = { 110, 90, -1, 260, 0 };
            else if (tag == L"app-detail") w = { -1, 80, 130, 110, 90 };

            auto tbl = winrt::get_self<implementation::DataTable>(Tbl());
            tbl->SetView(tpl, w);
            // Flows right-aligns its two numeric headers over the right-aligned score cells.
            tbl->SetHeaderRightAlign(tag == L"flows", tag == L"flows");
            if (!appDetail) tbl->SetAppDetail(false, L"", L"");   // clear trust card unless drilling in
            RefreshCurrent();
        }
    }

    void MainWindow::OnSearchChanged(Controls::AutoSuggestBox const& box,
                                     Controls::AutoSuggestBoxTextChangedEventArgs const&)
    {
        if (curView_ == L"settings" || curView_ == L"insights") return;
        winrt::get_self<implementation::DataTable>(Tbl())->SetFilter(box.Text());
    }

    HWND MainWindow::WindowHandle()
    {
        HWND h = nullptr;
        if (auto native = this->try_as<::IWindowNative>())
            native->get_WindowHandle(&h);
        return h;
    }

    // key is always a hardcoded constant here (no user input -> no injection risk).
    std::string MainWindow::MetaGet(const char* key, const char* dflt)
    {
        ng::Db d;
        if (d.open(DbPathU8().c_str()))
        {
            std::string v = d.scalar((std::string("SELECT v FROM meta WHERE k='") + key + "';").c_str());
            if (!v.empty()) return v;
        }
        return dflt;
    }
    void MainWindow::MetaSet(const char* key, const char* val)
    {
        ng::Db d;
        if (!d.open(DbPathU8().c_str())) return;
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(d.handle(),
            "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v;",
            -1, &s, nullptr);
        sqlite3_bind_text(s, 1, key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 2, val, -1, SQLITE_TRANSIENT);
        sqlite3_step(s); sqlite3_finalize(s);
    }

    // Select a sidebar item by tag (in either list); the SelectionChanged handler
    // then switches the view, so the highlight follows the jump.
    void MainWindow::NavTo(hstring const& tag)
    {
        for (auto lv : { NavList(), NavFooter() })
            for (auto const& it : lv.Items())
                if (auto lvi = it.try_as<ListViewItem>();
                    lvi && unbox_value_or<hstring>(lvi.Tag(), L"") == tag) {
                    lv.SelectedItem(lvi);
                    return;
                }
    }

    void MainWindow::OnTick(IInspectable const&, IInspectable const&)
    {
        if (menuOpen_) return;   // don't rebuild while a row context menu is open
        UpdateMode();
        if (curView_ == L"live") RefreshCurrent();
        else if (curView_ == L"settings") RefreshServiceStatus();   // reflect install/remove

        // Piggyback the periodic update check on this same once-a-second timer
        // instead of running a second one. First check ~10s after launch (let
        // the window paint before any network call); then once a day for as
        // long as the tray stays up, which - since it now starts at login and
        // stays running (see the Phase C/D tray merge) - is the only way an
        // update would ever be noticed without the user remembering to check.
        ++tickCount_;
        constexpr int64_t kFirstCheck = 10;
        constexpr int64_t kCheckInterval = 24LL * 60 * 60;
        if (tickCount_ == kFirstCheck ||
            (tickCount_ > kFirstCheck && (tickCount_ - kFirstCheck) % kCheckInterval == 0))
            CheckForUpdateInBackground();
    }

    void MainWindow::OnNavSelect(IInspectable const& sender, SelectionChangedEventArgs const&)
    {
        if (navSyncing_) return;
        auto lv = sender.try_as<ListView>();
        if (!lv) return;
        auto item = lv.SelectedItem().try_as<ListViewItem>();
        if (!item) return;   // deselected (from clearing the other list) - ignore
        // Single-select across both sidebar lists: clear the other one.
        navSyncing_ = true;
        (lv == NavList() ? NavFooter() : NavList()).SelectedItem(nullptr);
        navSyncing_ = false;
        ShowView(unbox_value_or<hstring>(item.Tag(), L"live"));
    }

    // Ask the running service to change mode. It's already up and already
    // elevated, so this needs no UAC and no new process - where these buttons used
    // to launch a whole second ngd.exe that knew nothing about the installed
    // service and fought it for the same WFP provider. If no service is installed
    // we fall back to the old foreground worker, so a service-less setup still
    // works exactly as before.
    bool MainWindow::SetMode(const char* mode, hstring const& okMsg)
    {
        bool ok = false;
        const std::string reply = ng::CmdSend(std::string("MODE ") + mode, &ok);
        if (ok)
        {
            const bool good = reply.rfind("OK", 0) == 0;
            Notify(good ? okMsg : U8(reply), good ? InfoBarSeverity::Success : InfoBarSeverity::Error);
            UpdateMode();
            return good;
        }
        return false;   // service not reachable; caller decides on a fallback
    }

    void MainWindow::OnEnforce(IInspectable const&, RoutedEventArgs const&)
    {
        if (SetMode("enforcing", L"Enforcing (default-deny + prompts).")) return;
        if (RunTool(L"ngd.exe", L"enforce \"" + NgDir() + L"\\ngpolicy.db\" 0"))
            Notify(L"Enforce started (no service installed - running in the foreground).",
                   InfoBarSeverity::Success);
    }
    void MainWindow::OnLearn(IInspectable const&, RoutedEventArgs const&)
    {
        if (SetMode("learning", L"Learning (recording baseline, enforcing nothing).")) return;
        if (RunTool(L"ngd.exe", L"record \"" + NgDir() + L"\\ngpolicy.db\""))
            Notify(L"Learn started (no service installed - running in the foreground).",
                   InfoBarSeverity::Success);
    }
    void MainWindow::OnStop(IInspectable const&, RoutedEventArgs const&)
    {
        if (SetMode("idle", L"Stopped; filters removed (failing open). Stays off across reboots."))
            return;
        StopDaemons();   // no service: kill the foreground worker instead
        Notify(L"Stopping NeuralGuard (failing open).", InfoBarSeverity::Informational);
    }
    void MainWindow::OnPanic(IInspectable const&, RoutedEventArgs const&)
    {
        // Prefer the service's own panic: a local one only rips the filters out
        // from under a daemon that keeps running and still thinks it's enforcing.
        bool ok = false;
        const std::string reply = ng::CmdSend("PANIC", &ok);
        if (ok)
        {
            Notify(L"PANIC - filters removed, enforcement off (and stays off).",
                   InfoBarSeverity::Warning);
            UpdateMode();
            return;
        }
        StopDaemons();
        if (RunTool(L"ngctl.exe", L"panic"))
            Notify(L"PANIC - all NeuralGuard filters removed.", InfoBarSeverity::Warning);
    }

    // panic() only pulls the WFP filters; the ngd worker keeps running and would
    // keep meta('mode') pinned at 'enforcing'/'learning', so the status bar lied.
    // Stop the worker(s) so Stop/Panic are honest.
    //
    // This delegates to `ngd stop` rather than killing ngd.exe by image name here,
    // because that kill was wrong for the one process it was most likely to hit:
    // if the background service is installed, its process is called ngd.exe too,
    // and terminating it looks like a crash to the SCM - whose restart-on-failure
    // policy brought it straight back up enforcing. ngd owns the distinction (SCM
    // stop for the service, kill for a foreground worker) and, being the thing
    // that actually performs the stop, is also the only thing that can honestly
    // set meta('mode')=idle afterwards - so we no longer write that here.
    void MainWindow::StopDaemons()
    {
        // --off = "and stay off": pressing Stop is a decision, so it has to outlive
        // the process. The service is auto-start, and without a persisted intent it
        // would come back enforcing at the next boot as if Stop never happened.
        RunTool(L"ngd.exe", L"stop \"" + NgDir() + L"\\ngpolicy.db\" --off");
        UpdateMode();   // the 2s tick settles it once ngd has actually finished
    }
}
