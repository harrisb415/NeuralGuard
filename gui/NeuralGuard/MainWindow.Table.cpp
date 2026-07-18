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

        colW_ = Application::Current().Resources().Lookup(box_value(L"ColW")).as<NeuralGuard::ColWidths>();

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

    winrt::Microsoft::UI::Xaml::Controls::TextBlock MainWindow::HdrBlock(int i)
    {
        switch (i) { case 0: return H0(); case 1: return H1(); case 2: return H2(); case 3: return H3(); default: return H4(); }
    }
    double MainWindow::GetW(int i)
    {
        switch (i) { case 0: return colW_.W0().Value; case 1: return colW_.W1().Value; case 2: return colW_.W2().Value;
                     case 3: return colW_.W3().Value; default: return colW_.W4().Value; }
    }
    void MainWindow::SetW(int i, double px)
    {
        GridLength gl{ px, GridUnitType::Pixel };
        // Keep the value so freshly-realized rows pick it up via their one-time binding.
        switch (i) { case 0: colW_.W0(gl); break; case 1: colW_.W1(gl); break; case 2: colW_.W2(gl); break;
                     case 3: colW_.W3(gl); break; default: colW_.W4(gl); break; }
        // ColumnDefinition.Width bindings don't update live in WinUI, so set widths directly:
        // the header column by name, and every already-realized row via its container.
        switch (i) { case 0: HCol0().Width(gl); break; case 1: HCol1().Width(gl); break;
                     case 2: HCol2().Width(gl); break; case 3: HCol3().Width(gl); break;
                     default: HCol4().Width(gl); break; }
        uint32_t n = DataList().Items() ? DataList().Items().Size() : 0;
        for (uint32_t k = 0; k < n; ++k)
        {
            auto c = DataList().ContainerFromIndex(k).try_as<ListViewItem>();
            if (!c) continue;
            if (auto g = c.ContentTemplateRoot().try_as<Grid>())
                if ((uint32_t)i < g.ColumnDefinitions().Size())
                    g.ColumnDefinitions().GetAt(i).Width(gl);
        }
    }
    void MainWindow::ApplyHeaderText()
    {
        for (int i = 0; i < 5; ++i)
        {
            std::wstring u{ baseHdr_[i] };
            for (auto& c : u) c = (wchar_t)::towupper(c);   // uppercase column labels
            hstring t{ u };
            if (i == sortCol_ && !u.empty())
            {
                wchar_t arrow[2] = { (wchar_t)(sortAsc_ ? 0x25B2 : 0x25BC), 0 };
                t = t + L"  " + hstring(arrow);
            }
            HdrBlock(i).Text(t);
        }
    }
    void MainWindow::OnHeaderTap(IInspectable const& sender, TappedRoutedEventArgs const&)
    {
        int col = TagInt(sender);
        if (baseHdr_[col].empty()) return;   // blank column - not sortable
        if (col == sortCol_) sortAsc_ = !sortAsc_; else { sortCol_ = col; sortAsc_ = true; }
        ApplyHeaderText();
        RefreshCurrent();
    }
    // Manual column resize measured against ContentRoot (which does NOT move as columns
    // resize), so there's no feedback loop. Handled() stops the ListView/ScrollViewer
    // from stealing the pointer. Each column has an independent pixel width.
    void MainWindow::OnGripPressed(IInspectable const& sender, PointerRoutedEventArgs const& e)
    {
        resizeCol_ = TagInt(sender);
        dragStartX_ = e.GetCurrentPoint(ContentRoot()).Position().X;
        dragStartW_ = GetW(resizeCol_);
        if (auto b = sender.try_as<UIElement>()) b.CapturePointer(e.Pointer());
        e.Handled(true);
    }
    void MainWindow::OnGripMoved(IInspectable const&, PointerRoutedEventArgs const& e)
    {
        if (resizeCol_ < 0) return;
        double x = e.GetCurrentPoint(ContentRoot()).Position().X;
        double w = dragStartW_ + (x - dragStartX_);
        if (w < 44) w = 44;
        if (w > 1200) w = 1200;
        SetW(resizeCol_, w);
        e.Handled(true);
    }
    void MainWindow::OnGripReleased(IInspectable const& sender, PointerRoutedEventArgs const& e)
    {
        resizeCol_ = -1;
        if (auto b = sender.try_as<UIElement>()) b.ReleasePointerCapture(e.Pointer());
    }
    // Each row's Grid is rebuilt whenever the ItemsSource is replaced (every refresh),
    // so re-apply the current column widths as each container is realized. This is what
    // makes a resize survive the periodic refresh instead of snapping back to the
    // template's default widths.
    void MainWindow::OnContainerChanging(ListViewBase const&, ContainerContentChangingEventArgs const& args)
    {
        if (args.InRecycleQueue()) return;
        auto container = args.ItemContainer();
        if (!container) return;
        if (auto g = container.ContentTemplateRoot().try_as<Grid>())
        {
            auto cols = g.ColumnDefinitions();
            if (cols.Size() >= 5)
            {
                // Keep each row's columns in lockstep with the (per-view) header.
                cols.GetAt(0).Width(HCol0().Width()); cols.GetAt(1).Width(HCol1().Width());
                cols.GetAt(2).Width(HCol2().Width()); cols.GetAt(3).Width(HCol3().Width());
                cols.GetAt(4).Width(HCol4().Width());
            }
        }
    }

    // Per-view column widths for the header (rows follow via OnContainerChanging).
    // A negative value means a star (fills remaining space) column.
    void MainWindow::SetCols(double a, double b, double c, double d, double e)
    {
        auto gl = [](double v) {
            return v < 0 ? GridLength{ 1, GridUnitType::Star } : GridLength{ v, GridUnitType::Pixel };
        };
        HCol0().Width(gl(a)); HCol1().Width(gl(b)); HCol2().Width(gl(c));
        HCol3().Width(gl(d)); HCol4().Width(gl(e));
    }

    void MainWindow::SetHeaders(hstring const& h0, hstring const& h1, hstring const& h2,
                                hstring const& h3, hstring const& h4)
    {
        baseHdr_[0] = h0; baseHdr_[1] = h1; baseHdr_[2] = h2; baseHdr_[3] = h3; baseHdr_[4] = h4;
        ApplyHeaderText();
    }
}
