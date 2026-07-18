#pragma once

#include "MainWindow.g.h"
#include "ColumnGrip.h"      // XAML-activated custom control; XamlTypeInfo needs the full type
#include "InsightsView.xaml.h"   // <local:InsightsView> hosted in MainWindow.xaml; same reason
#include "DataTable.xaml.h"      // <local:DataTable> hosted in MainWindow.xaml; same reason

namespace winrt::NeuralGuard::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow();

        void OnEnforce(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnLearn(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnStop(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnPanic(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnNavSelect(winrt::Windows::Foundation::IInspectable const&,
                         winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const&);
        void OnAppDetailBack(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        // Row-action callbacks the DataTable control raises (it owns the list; the
        // menus and DB writes stay here). ShowRowMenu builds the per-view context
        // menu at the clicked row; OnRowInvoked handles a double-click.
        void ShowRowMenu(winrt::NeuralGuard::Row const& row,
                         winrt::Microsoft::UI::Xaml::FrameworkElement const& anchor,
                         winrt::Windows::Foundation::Point const& pos);
        void OnRowInvoked(winrt::NeuralGuard::Row const& row);
        void OnAutonomyChanged(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnServiceInstall(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnServiceRemove(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnSearchChanged(winrt::Microsoft::UI::Xaml::Controls::AutoSuggestBox const&,
                             winrt::Microsoft::UI::Xaml::Controls::AutoSuggestBoxTextChangedEventArgs const&);
        void OnExportRules(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnImportRules(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnFeatureToggle(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnMlModeChanged(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnThemeChanged(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnMlThresholdChanged(winrt::Microsoft::UI::Xaml::Controls::NumberBox const&,
                                  winrt::Microsoft::UI::Xaml::Controls::NumberBoxValueChangedEventArgs const&);
        void OnClearFlags(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnExportFeedback(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnCheckUpdate(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnInstallUpdate(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::RoutedEventArgs const&);
        // Background check on the same cadence as OnTick (see tickCount_): once
        // ~10s after launch, then once a day for as long as the tray stays up.
        void CheckForUpdateInBackground();

        // The tray icon lives in this process now (see Tray.h). Closing the window
        // hides to tray rather than exiting - the tray is the app's real lifetime.
        void StartTray();
        void ShowFromTray();
        void ExitApp();
        // Ask the running service to switch mode. False = service not reachable,
        // so the caller can fall back to a foreground worker.
        bool SetMode(const char* mode, winrt::hstring const& okMsg);

    private:
        void DemoteApp(winrt::hstring const& appPath, int port, int proto);   // Phase 4d: manual distrust
        void RetrustApp(winrt::hstring const& appPath, int port, int proto);  // remove a demote flag
        void RemoveFlag(int64_t id);                               // delete one ml_flags row
        void SetInboundAllowed(int64_t id, bool allowed);          // permit/revoke a blocked inbound service
        void ClearMlFlags();                                       // delete all ml_flags
        HWND WindowHandle();
        void LoadSettings();
        void ApplyTheme(std::string const& theme);   // 'dark' | 'light' | 'system' -> root RequestedTheme
        void SyncThemeDependents();                  // things ThemeResource can't reach (SemBrush, caption buttons)
        void ApplyCaptionColors(bool light);
        void RefreshServiceStatus();
        int  ReadAutonomy();
        void WriteAutonomy(int level);
        std::string MetaGet(const char* key, const char* dflt);
        void MetaSet(const char* key, const char* val);
        void AddRuleFromEvent(int64_t eventId, bool block, bool useApp, int ttlSeconds);
        void DelRule(int64_t ruleId);
        void OnTick(winrt::Windows::Foundation::IInspectable const&, winrt::Windows::Foundation::IInspectable const&);
        void ShowView(winrt::hstring const& tag);
        void NavTo(winrt::hstring const& tag);   // select a sidebar item by tag (jump-links)
        // Drill into a Per-app row's destination breakdown. `row` is the tapped
        // apps row; its C3 is the app label and C0/C1/C2 the events/blocked/dests
        // totals, reused in the detail header so they don't need re-querying.
        void OpenAppDetail(winrt::NeuralGuard::Row const& row);
        void RefreshCurrent();
        void SetHeaders(winrt::hstring const& h0, winrt::hstring const& h1, winrt::hstring const& h2,
                        winrt::hstring const& h3, winrt::hstring const& h4);   // forwards to the DataTable control
        void UpdateMode();
        void StopDaemons();   // terminate ngd workers + reset meta('mode') so the status bar is honest
        bool RunTool(std::wstring const& exe, std::wstring const& args);
        void Log(winrt::hstring const& line);
        void Notify(winrt::hstring const& message,
                    winrt::Microsoft::UI::Xaml::Controls::InfoBarSeverity severity);
        std::wstring NgDir();
        std::string DbPathU8();

        winrt::Microsoft::UI::Xaml::DispatcherTimer timer_{ nullptr };
        winrt::Microsoft::UI::Xaml::DispatcherTimer toastTimer_{ nullptr };  // auto-dismiss the toast
        winrt::hstring curView_{ L"live" };
        // app-detail view state: the app label being drilled into, plus the
        // events/blocked/dests totals grabbed from the clicked row for the header.
        winrt::hstring detailApp_, detailEvents_, detailBlocked_, detailDests_;
        winrt::NeuralGuard::Row ctxRow_{ nullptr };   // row the context menu acts on
        bool loadingSettings_{ false };               // suppress the autonomy handler while syncing radios
        bool navSyncing_{ false };                    // guard while clearing the other sidebar list's selection
        bool menuOpen_{ false };                      // a row context menu is open - pause the live refresh

        // OnTick fires once a second; this counts those ticks so the periodic
        // update check can ride the existing timer instead of needing its own.
        int64_t tickCount_{ 0 };

        bool themeHooked_{ false };   // ActualThemeChanged wired once (see ApplyTheme)
        bool viewReady_{ false };     // first ShowView() done; before that there's nothing to refresh
    };
}

namespace winrt::NeuralGuard::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
