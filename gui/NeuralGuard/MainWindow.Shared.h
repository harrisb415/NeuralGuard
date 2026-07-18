#pragma once
// Small helpers shared across the MainWindow.*.cpp implementation files (the
// class body is split by concern across several translation units; only
// MainWindow.xaml.cpp pulls in the generated MainWindow.g.cpp glue). These were
// file-static in the single old MainWindow.xaml.cpp; promoted to inline here so
// every part sees one definition. Fully qualified on purpose - they must not
// depend on which `using namespace` directives a given .cpp has in scope.
#include "Row.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace winrt::NeuralGuard::implementation
{
    // UTF-8 std::string (e.g. sqlite text) -> hstring.
    inline winrt::hstring U8(std::string const& s)
    {
        return winrt::to_hstring(std::string_view(s));
    }

    inline winrt::Windows::Foundation::IInspectable MakeRow(
        int64_t id, winrt::hstring const& a, winrt::hstring const& b,
        winrt::hstring const& c, winrt::hstring const& d, winrt::hstring const& e)
    {
        return winrt::make<Row>(id, a, b, c, d, e);
    }

    // A ListView's default template contains a ScrollViewer, but it isn't a named
    // part we can reach directly - only findable by walking the realized visual
    // tree. Used to save/restore scroll position across a refresh, since resetting
    // ItemsSource (RefreshCurrent's wholesale-rebuild approach - same reason it
    // already re-finds the selected row by id) snaps the view to the top otherwise.
    inline winrt::Microsoft::UI::Xaml::Controls::ScrollViewer FindScrollViewer(
        winrt::Microsoft::UI::Xaml::DependencyObject const& root)
    {
        namespace mux = winrt::Microsoft::UI::Xaml;
        int n = mux::Media::VisualTreeHelper::GetChildrenCount(root);
        for (int i = 0; i < n; ++i)
        {
            auto child = mux::Media::VisualTreeHelper::GetChild(root, i);
            if (auto sv = child.try_as<mux::Controls::ScrollViewer>()) return sv;
            if (auto found = FindScrollViewer(child)) return found;
        }
        return nullptr;
    }

    inline int TagInt(winrt::Windows::Foundation::IInspectable const& sender)
    {
        if (auto fe = sender.try_as<winrt::Microsoft::UI::Xaml::FrameworkElement>())
        {
            std::string t = winrt::to_string(winrt::unbox_value_or<winrt::hstring>(fe.Tag(), L"0"));
            return t.empty() ? 0 : atoi(t.c_str());
        }
        return 0;
    }
}
