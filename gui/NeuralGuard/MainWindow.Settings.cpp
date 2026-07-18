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

    // Rules are exported/imported as pipe-delimited text, one rule per line:
    //   action|app_path|remote_addr|remote_port|protocol|enabled|expires_epoch
    void MainWindow::OnExportRules(IInspectable const&, RoutedEventArgs const&)
    {
        wchar_t file[MAX_PATH] = L"neuralguard-rules.txt";
        OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = WindowHandle();
        ofn.lpstrFilter = L"Rules (*.txt)\0*.txt\0All files\0*.*\0";
        ofn.lpstrFile = file; ofn.nMaxFile = MAX_PATH;
        ofn.lpstrDefExt = L"txt";
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        if (!GetSaveFileNameW(&ofn)) return;   // cancelled

        ng::Db d;
        if (!d.open(DbPathU8().c_str())) { Notify(L"Couldn't open the policy database.", InfoBarSeverity::Error); return; }
        std::string out;
        int n = 0;
        d.each("SELECT action, COALESCE(app_path,''), COALESCE(remote_addr,''), COALESCE(remote_port,0),"
               " COALESCE(protocol,0), enabled, CAST(COALESCE(expires_epoch,0) AS INTEGER)"
               " FROM rules ORDER BY id;", [&](sqlite3_stmt* s) {
            out += ng::Db::ColText(s, 0); out += '|';
            out += ng::Db::ColText(s, 1); out += '|';
            out += ng::Db::ColText(s, 2); out += '|';
            out += std::to_string(sqlite3_column_int(s, 3)); out += '|';
            out += std::to_string(sqlite3_column_int(s, 4)); out += '|';
            out += std::to_string(sqlite3_column_int(s, 5)); out += '|';
            out += std::to_string(sqlite3_column_int64(s, 6)); out += "\r\n";
            ++n;
        });

        HANDLE h = CreateFileW(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { Notify(L"Couldn't write that file.", InfoBarSeverity::Error); return; }
        DWORD wr = 0; WriteFile(h, out.data(), (DWORD)out.size(), &wr, nullptr); CloseHandle(h);
        Notify(L"Exported " + to_hstring(n) + L" rule(s).", InfoBarSeverity::Success);
    }

    void MainWindow::OnImportRules(IInspectable const&, RoutedEventArgs const&)
    {
        wchar_t file[MAX_PATH] = L"";
        OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = WindowHandle();
        ofn.lpstrFilter = L"Rules (*.txt)\0*.txt\0All files\0*.*\0";
        ofn.lpstrFile = file; ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        if (!GetOpenFileNameW(&ofn)) return;

        HANDLE h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { Notify(L"Couldn't read that file.", InfoBarSeverity::Error); return; }
        std::string content; char buf[4096]; DWORD rd = 0;
        while (ReadFile(h, buf, sizeof(buf), &rd, nullptr) && rd > 0) content.append(buf, rd);
        CloseHandle(h);

        ng::Db d;
        if (!d.open(DbPathU8().c_str())) { Notify(L"Couldn't open the policy database.", InfoBarSeverity::Error); return; }
        sqlite3_stmt* ins = nullptr;
        sqlite3_prepare_v2(d.handle(),
            "INSERT INTO rules(action,app_path,remote_addr,remote_port,protocol,enabled,expires_epoch,created_at)"
            " VALUES(?,?,?,?,?,?,?,datetime('now'));", -1, &ins, nullptr);
        int n = 0;
        double now = (double)time(nullptr);
        size_t pos = 0;
        while (pos < content.size())
        {
            size_t eol = content.find('\n', pos);
            std::string line = content.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
            pos = (eol == std::string::npos) ? content.size() : eol + 1;
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
            if (line.empty()) continue;

            std::vector<std::string> f;
            size_t p = 0;
            for (;;) { size_t bar = line.find('|', p);
                       f.push_back(line.substr(p, bar == std::string::npos ? std::string::npos : bar - p));
                       if (bar == std::string::npos) break; p = bar + 1; }
            if (f.size() < 7) continue;
            if (f[0] != "permit" && f[0] != "block") continue;   // skip headers / junk

            sqlite3_reset(ins);
            sqlite3_bind_text(ins, 1, f[0].c_str(), -1, SQLITE_TRANSIENT);
            if (f[1].empty()) sqlite3_bind_null(ins, 2); else sqlite3_bind_text(ins, 2, f[1].c_str(), -1, SQLITE_TRANSIENT);
            if (f[2].empty()) sqlite3_bind_null(ins, 3); else sqlite3_bind_text(ins, 3, f[2].c_str(), -1, SQLITE_TRANSIENT);
            int port = atoi(f[3].c_str());   if (port)  sqlite3_bind_int(ins, 4, port);  else sqlite3_bind_null(ins, 4);
            int proto = atoi(f[4].c_str());  if (proto) sqlite3_bind_int(ins, 5, proto); else sqlite3_bind_null(ins, 5);
            sqlite3_bind_int(ins, 6, atoi(f[5].c_str()) ? 1 : 0);
            double exp = atof(f[6].c_str()); if (exp > now) sqlite3_bind_double(ins, 7, exp); else sqlite3_bind_null(ins, 7);
            if (sqlite3_step(ins) == SQLITE_DONE) ++n;
        }
        sqlite3_finalize(ins);
        sqlite3_exec(d.handle(), "UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='rules_gen';", nullptr, nullptr, nullptr);
        Notify(L"Imported " + to_hstring(n) + L" rule(s).", InfoBarSeverity::Success);
        if (curView_ == L"rules") RefreshCurrent();
    }

    void MainWindow::LoadSettings()
    {
        loadingSettings_ = true;   // syncing the controls must not write back / toast
        std::string theme = MetaGet("theme", "dark");
        Theme0().IsChecked(theme == "dark");
        Theme1().IsChecked(theme == "light");
        Theme2().IsChecked(theme == "system");
        int a = ReadAutonomy();
        Auto0().IsChecked(a == 0);
        Auto1().IsChecked(a == 1);
        Auto2().IsChecked(a == 2);
        FeatureToggle().IsOn(MetaGet("feature_archive", "0") == "1");
        std::string mode = MetaGet("ml_mode", "shadow");
        Ml0().IsChecked(mode == "off");
        Ml1().IsChecked(mode == "shadow");
        Ml2().IsChecked(mode == "active");
        MalThresh().Value(std::strtod(MetaGet("ml_malicious_threshold", "0.9").c_str(), nullptr));
        AnomThresh().Value(std::strtod(MetaGet("ml_anomaly_threshold", "-0.15").c_str(), nullptr));
        GatesPanel().Visibility(mode == "active" ? Visibility::Visible : Visibility::Collapsed);
        loadingSettings_ = false;
        RefreshServiceStatus();
        AboutVersion().Text(U8("v" + std::string(NG_VERSION)));
    }

    int MainWindow::ReadAutonomy()
    {
        ng::Db d;
        if (d.open(DbPathU8().c_str()))
        {
            std::string v = d.scalar("SELECT v FROM meta WHERE k='autonomy';");
            if (!v.empty()) return atoi(v.c_str());
        }
        return 0;
    }

    void MainWindow::WriteAutonomy(int level)
    {
        ng::Db d;
        if (!d.open(DbPathU8().c_str())) return;
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(d.handle(),
            "INSERT INTO meta(k,v) VALUES('autonomy',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v;",
            -1, &s, nullptr);
        std::string lv = std::to_string(level);
        sqlite3_bind_text(s, 1, lv.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(s); sqlite3_finalize(s);
    }

    void MainWindow::OnAutonomyChanged(IInspectable const& sender, RoutedEventArgs const&)
    {
        if (loadingSettings_) return;
        int level = TagInt(sender);
        WriteAutonomy(level);   // enforce daemon re-reads meta('autonomy') live per drop
        hstring msg = level == 0 ? L"Autonomy: prompt on every new connection."
                    : level == 1 ? L"Autonomy: auto-allow apps you already use."
                                 : L"Autonomy: auto-allow everything (log only).";
        Notify(msg, InfoBarSeverity::Success);
    }

    void MainWindow::OnFeatureToggle(IInspectable const&, RoutedEventArgs const&)
    {
        if (loadingSettings_) return;
        bool on = FeatureToggle().IsOn();
        MetaSet("feature_archive", on ? "1" : "0");
        Notify(on ? L"Flow feature collection ON — applies next time enforcement or learning runs."
                  : L"Flow feature collection OFF.", InfoBarSeverity::Success);
    }
    // Theme goes on the root FrameworkElement, not the Application: an app-level
    // RequestedTheme is fixed for the process lifetime, while an element-level one
    // can change live. ElementTheme::Default means "inherit from the app", and the
    // app no longer forces Dark, so Default = follow the Windows setting - which
    // is also what makes the 'system' option track an OS theme change without any
    // listener of our own.
    void MainWindow::ApplyTheme(std::string const& theme)
    {
        auto root = Content().try_as<FrameworkElement>();
        if (!root) return;
        root.RequestedTheme(theme == "light"  ? ElementTheme::Light
                          : theme == "system" ? ElementTheme::Default
                                              : ElementTheme::Dark);

        // ActualTheme, not the requested one: 'system' resolves to whatever
        // Windows is currently set to, and SemBrush needs the concrete answer.
        SyncThemeDependents();

        // 'system' means the theme can change without us: hook ActualThemeChanged
        // once so SemBrush + the caption buttons follow an OS switch too. (The
        // token brushes are ThemeResource and re-resolve on their own.)
        if (!themeHooked_)
        {
            themeHooked_ = true;
            root.ActualThemeChanged([this](FrameworkElement const&, IInspectable const&) {
                SyncThemeDependents();
            });
        }
    }

    // Minimize/maximize/close glyphs. Transparent backgrounds either way so the
    // custom title bar shows through; only the glyph colour flips. Hardcoded to
    // match NG.Color.Text.Primary per theme - these are set through an AppWindow
    // API that can't read XAML resources.
    void MainWindow::ApplyCaptionColors(bool light)
    {
        auto tb = AppWindow().TitleBar();
        if (!tb) return;
        using winrt::Windows::UI::Color;
        const Color fg     = light ? Color{ 255, 17, 21, 28 }    : Color{ 255, 232, 236, 244 };
        const Color fgIdle = light ? Color{ 120, 17, 21, 28 }    : Color{ 120, 232, 236, 244 };
        const Color hover  = light ? Color{ 26, 0, 0, 0 }        : Color{ 40, 255, 255, 255 };
        const Color hoverFg= light ? Color{ 255, 0, 0, 0 }       : Color{ 255, 255, 255, 255 };

        tb.ButtonBackgroundColor(Color{ 0, 0, 0, 0 });
        tb.ButtonInactiveBackgroundColor(Color{ 0, 0, 0, 0 });
        tb.ButtonForegroundColor(fg);
        tb.ButtonInactiveForegroundColor(fgIdle);
        tb.ButtonHoverBackgroundColor(hover);
        tb.ButtonHoverForegroundColor(hoverFg);
    }

    // The two things that don't follow ThemeResource on their own: the SemBrush
    // converter (no element, so it can't see ActualTheme) and the caption
    // buttons (an AppWindow TitleBar API, not part of the XAML resource system).
    void MainWindow::SyncThemeDependents()
    {
        auto root = Content().try_as<FrameworkElement>();
        const bool light = root && root.ActualTheme() == ElementTheme::Light;

        // Row bakes its brushes at construction, so it needs the theme before any
        // rows are built. (SemBrush is currently unreferenced by any XAML - the
        // pills come from Row - but it's still registered in App.xaml, so keep it
        // in sync rather than leave a stale trap for whoever wires it up.)
        Row::SetLightTheme(light);
        SemBrush::SetLightTheme(light);
        ApplyCaptionColors(light);

        // Existing rows were built with the old brushes; the converter only runs
        // on (re)binding, so force a rebuild to repaint the verdict pills.
        // Guarded: ApplyTheme runs from the constructor, before ShowView() has
        // established a view - refreshing then would query for a view that isn't
        // set up yet. The initial ShowView paints with the right theme anyway,
        // since SetLightTheme has already landed by that point.
        liveItemsValid_ = false;
        if (!curView_.empty() && viewReady_) RefreshCurrent();
    }

    void MainWindow::OnThemeChanged(IInspectable const& sender, RoutedEventArgs const&)
    {
        if (loadingSettings_) return;
        auto fe = sender.try_as<FrameworkElement>();
        std::string theme = fe ? to_string(unbox_value_or<hstring>(fe.Tag(), L"dark")) : "dark";
        MetaSet("theme", theme.c_str());
        ApplyTheme(theme);
    }

    void MainWindow::OnMlModeChanged(IInspectable const& sender, RoutedEventArgs const&)
    {
        if (loadingSettings_) return;
        auto fe = sender.try_as<FrameworkElement>();
        std::string mode = fe ? to_string(unbox_value_or<hstring>(fe.Tag(), L"shadow")) : "shadow";
        if (mode != MetaGet("ml_mode", "shadow")) {
            MetaSet("ml_mode", mode.c_str());
            // Record when the mode last changed, for the Insights Status card.
            ng::Db d;
            if (d.open(DbPathU8().c_str()))
                d.each("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now');", [&](sqlite3_stmt* s) {
                    MetaSet("ml_mode_since", ng::Db::ColText(s, 0).c_str());
                });
        }
        GatesPanel().Visibility(mode == "active" ? Visibility::Visible : Visibility::Collapsed);
        if (mode == "active")
            Notify(L"Active scoring on. A strongly-malicious score can now demote a trusted app so it "
                   L"prompts again (it never auto-blocks). Takes effect next time enforcement runs. "
                   L"Use trained models, not the placeholders.", InfoBarSeverity::Warning);
        else
            Notify(L"ML scoring mode: " + to_hstring(mode) + L".", InfoBarSeverity::Success);
    }

    void MainWindow::OnMlThresholdChanged(Controls::NumberBox const& sender,
                                          Controls::NumberBoxValueChangedEventArgs const&)
    {
        if (loadingSettings_) return;
        double v = sender.Value();
        if (v != v) return;   // NaN = the box was cleared; ignore
        char buf[32]; snprintf(buf, sizeof buf, "%.3f", v);
        MetaSet(sender.Name() == L"MalThresh" ? "ml_malicious_threshold" : "ml_anomaly_threshold", buf);
        Notify(L"Confidence gate updated (takes effect next time enforcement runs).", InfoBarSeverity::Success);
    }

    void MainWindow::OnClearFlags(IInspectable const&, RoutedEventArgs const&)
    {
        ClearMlFlags();
        if (curView_ == L"flags" || curView_ == L"baseline" || curView_ == L"inbound") RefreshCurrent();
    }

    void MainWindow::OnExportFeedback(IInspectable const&, RoutedEventArgs const&)
    {
        wchar_t file[MAX_PATH] = L"neuralguard-feedback.csv";
        OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = WindowHandle();
        ofn.lpstrFilter = L"CSV (*.csv)\0*.csv\0All files\0*.*\0";
        ofn.lpstrFile = file; ofn.nMaxFile = MAX_PATH;
        ofn.lpstrDefExt = L"csv";
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        if (!GetSaveFileNameW(&ofn)) return;

        ng::Db d;
        if (!d.open(DbPathU8().c_str())) { Notify(L"Couldn't open the policy database.", InfoBarSeverity::Error); return; }
        std::string out = "duration_ms,bytes_in,bytes_out,remote_port,label\r\n";
        int n = 0;
        d.each("SELECT COALESCE(MAX(ff.duration_ms),0), COALESCE(MAX(ff.bytes_in),0),"
               " COALESCE(MAX(ff.bytes_out),0), fl.remote_port, fl.label FROM feedback_labels fl"
               " LEFT JOIN flow_features ff ON ff.process_key=fl.process_key AND ff.dest=fl.dest"
               "   AND ff.remote_port=fl.remote_port GROUP BY fl.id;", [&](sqlite3_stmt* s) {
            out += std::to_string(sqlite3_column_int(s, 0)) + "," +
                   std::to_string(sqlite3_column_int64(s, 1)) + "," +
                   std::to_string(sqlite3_column_int64(s, 2)) + "," +
                   std::to_string(sqlite3_column_int(s, 3)) + "," +
                   std::to_string(sqlite3_column_int(s, 4)) + "\r\n";
            ++n;
        });
        HANDLE h = CreateFileW(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { Notify(L"Couldn't write that file.", InfoBarSeverity::Error); return; }
        DWORD wr = 0; WriteFile(h, out.data(), (DWORD)out.size(), &wr, nullptr); CloseHandle(h);
        Notify(L"Exported " + to_hstring(n) + L" label(s).", InfoBarSeverity::Success);
    }

    // --- Software updates (Settings card) -----------------------------------
    // Shared ng::Updater runs on a background thread; UI is touched only back on
    // the dispatcher. SCAFFOLD: capturing `this` in a detached thread assumes the
    // window outlives the check - fine for now, revisit with a weak ref / cancel
    // token if this ships. Not yet exercised against a real release.
    void MainWindow::OnCheckUpdate(IInspectable const&, RoutedEventArgs const&)
    {
        UpdateStatus().Text(L"Checking for updates...");
        InstallUpdateBtn().IsEnabled(false);
        UpdateNotesLink().Visibility(Visibility::Collapsed);
        auto dq = DispatcherQueue();
        std::thread([this, dq]() {
            ng::UpdateInfo info = ng::Updater().check();
            dq.TryEnqueue([this, info]() {
                if (!info.error.empty()) {
                    UpdateStatus().Text(to_hstring("Check failed: " + info.error));
                } else if (info.available) {
                    UpdateStatus().Text(to_hstring("Update available: " + info.latestVersion +
                                                   "  (you have " + info.currentVersion + ")"));
                    InstallUpdateBtn().IsEnabled(true);
                    if (!info.notes.empty()) {
                        UpdateNotesLink().NavigateUri(Windows::Foundation::Uri{ to_hstring(info.notes) });
                        UpdateNotesLink().Visibility(Visibility::Visible);
                    }
                } else {
                    UpdateStatus().Text(to_hstring("You are up to date (" + info.currentVersion + ")."));
                }
            });
        }).detach();
    }

    void MainWindow::OnInstallUpdate(IInspectable const&, RoutedEventArgs const&)
    {
        InstallUpdateBtn().IsEnabled(false);
        UpdateProgress().IsIndeterminate(true);
        UpdateProgress().Visibility(Visibility::Visible);
        UpdateStatus().Text(L"Preparing...");
        auto dq = DispatcherQueue();
        std::thread([this, dq]() {
            ng::Updater up;
            ng::UpdateInfo info = up.check();
            if (info.error.empty() && info.available) {
                auto prog = [this, dq](ng::UpdateStage, int pct, std::string const& msg) {
                    dq.TryEnqueue([this, pct, msg]() {
                        if (pct >= 0) { UpdateProgress().IsIndeterminate(false); UpdateProgress().Value(pct); }
                        else UpdateProgress().IsIndeterminate(true);
                        if (!msg.empty()) UpdateStatus().Text(to_hstring(msg));
                    });
                };
                std::string path = up.download(info, prog);
                bool launched = !path.empty() && up.apply(path, prog);
                if (launched) {
                    dq.TryEnqueue([this]() {
                        UpdateStatus().Text(L"Installer launched - closing NeuralGuard to finish updating...");
                    });
                    // Give the user a beat to read it, then exit so our files unlock
                    // for the silent installer (which also force-closes us as a backstop).
                    Sleep(1500);
                    dq.TryEnqueue([]() {
                        if (auto app = Application::Current()) app.Exit();
                    });
                } else {
                    dq.TryEnqueue([this]() {
                        UpdateStatus().Text(L"Update failed (download or verify). Try again later.");
                        UpdateProgress().Visibility(Visibility::Collapsed);
                        InstallUpdateBtn().IsEnabled(true);
                    });
                }
            } else {
                dq.TryEnqueue([this]() {
                    UpdateStatus().Text(L"Nothing to install - run Check for updates first.");
                    UpdateProgress().Visibility(Visibility::Collapsed);
                });
            }
        }).detach();
    }

    void MainWindow::ClearMlFlags()
    {
        ng::Db d;
        if (!d.open(DbPathU8().c_str())) return;
        sqlite3_exec(d.handle(), "DELETE FROM ml_flags;", nullptr, nullptr, nullptr);
        sqlite3_exec(d.handle(), "UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='rules_gen';", nullptr, nullptr, nullptr);
        Notify(L"Cleared all ML flags; demoted apps are trusted again.", InfoBarSeverity::Success);
    }

    void MainWindow::RefreshServiceStatus()
    {
        hstring text = L"Not installed.";
        if (SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT))
        {
            if (SC_HANDLE svc = OpenServiceW(scm, L"NeuralGuard", SERVICE_QUERY_STATUS))
            {
                SERVICE_STATUS st{};
                if (QueryServiceStatus(svc, &st))
                    text = (st.dwCurrentState == SERVICE_RUNNING) ? hstring(L"Installed and running.")
                                                                  : hstring(L"Installed (stopped).");
                else
                    text = L"Installed.";
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }
        SvcStatus().Text(text);
    }

    void MainWindow::OnServiceInstall(IInspectable const&, RoutedEventArgs const&)
    {
        if (RunTool(L"ngd.exe", L"install \"" + NgDir() + L"\\ngpolicy.db\""))
            Notify(L"Installing the NeuralGuard service...", InfoBarSeverity::Informational);
    }

    void MainWindow::OnServiceRemove(IInspectable const&, RoutedEventArgs const&)
    {
        if (RunTool(L"ngd.exe", L"uninstall"))
            Notify(L"Removing the NeuralGuard service...", InfoBarSeverity::Informational);
    }

    // ngd/ngctl manage WFP filters, which needs administrator rights. If this
    // process is already elevated we launch the tool directly; otherwise we ask
    // for elevation via the "runas" verb (one UAC prompt). Returns true only if
    // the tool actually started, so callers don't post a false "started" toast.
    bool MainWindow::RunTool(std::wstring const& exe, std::wstring const& args)
    {
        std::wstring dir  = NgDir();
        std::wstring file = dir + L"\\" + exe;

        bool elevated = false;
        HANDLE tok = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        {
            TOKEN_ELEVATION te{}; DWORD cb = 0;
            if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &cb))
                elevated = te.TokenIsElevated != 0;
            CloseHandle(tok);
        }

        SHELLEXECUTEINFOW sei{}; sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
        sei.lpVerb = elevated ? L"open" : L"runas";
        sei.lpFile = file.c_str();
        sei.lpParameters = args.c_str();
        sei.lpDirectory = dir.c_str();
        sei.nShow = SW_HIDE;
        if (ShellExecuteExW(&sei))
        {
            if (sei.hProcess) CloseHandle(sei.hProcess);
            return true;
        }

        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED)
            Notify(L"Elevation cancelled; " + hstring(exe) + L" not started.", InfoBarSeverity::Warning);
        else
            Notify(L"Couldn't launch " + hstring(exe), InfoBarSeverity::Error);
        return false;
    }

    // Same network check OnCheckUpdate runs, just unattended. Updates the
    // Settings panel regardless of which tab is showing (harmless if it's not
    // visible right now), and balloons through the tray - but only once per
    // newly-seen version, via meta('update_notified_version'), so a daily
    // recheck doesn't nag about the same release the user already saw and
    // hasn't gotten around to installing yet.
    void MainWindow::CheckForUpdateInBackground()
    {
        auto dq = DispatcherQueue();
        std::thread([this, dq]() {
            ng::UpdateInfo info = ng::Updater().check();
            if (info.error.empty() && info.available) {
                dq.TryEnqueue([this, info]() {
                    UpdateStatus().Text(to_hstring("Update available: " + info.latestVersion +
                                                   "  (you have " + info.currentVersion + ")"));
                    InstallUpdateBtn().IsEnabled(true);
                    if (!info.notes.empty()) {
                        UpdateNotesLink().NavigateUri(Windows::Foundation::Uri{ to_hstring(info.notes) });
                        UpdateNotesLink().Visibility(Visibility::Visible);
                    }
                    if (MetaGet("update_notified_version", "") != info.latestVersion) {
                        MetaSet("update_notified_version", info.latestVersion.c_str());
                        hstring msg = U8("v" + info.latestVersion + " is available (you're on v" +
                                         info.currentVersion + "). Open Settings to install.");
                        ngtray::Balloon(L"NeuralGuard update available", std::wstring(msg.c_str()));
                    }
                });
            }
        }).detach();
    }
}
