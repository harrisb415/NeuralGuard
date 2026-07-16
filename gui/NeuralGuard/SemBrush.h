#pragma once

#include "SemBrush.g.h"

namespace winrt::NeuralGuard::implementation
{
    struct SemBrush : SemBrushT<SemBrush>
    {
        SemBrush() = default;

        // Which theme dictionary Convert() resolves brushes from. An
        // IValueConverter has no element to read ActualTheme off, and its
        // Application.Resources lookup follows the APP theme - which no longer
        // changes, since the theme is applied per-window (MainWindow::ApplyTheme).
        // So the window pushes its resolved ActualTheme in here instead. Process-
        // wide, which is fine: there is exactly one window.
        static void SetLightTheme(bool light);

        winrt::Windows::Foundation::IInspectable Convert(
            winrt::Windows::Foundation::IInspectable const& value,
            winrt::Windows::UI::Xaml::Interop::TypeName const& targetType,
            winrt::Windows::Foundation::IInspectable const& parameter,
            winrt::hstring const& language);

        winrt::Windows::Foundation::IInspectable ConvertBack(
            winrt::Windows::Foundation::IInspectable const& value,
            winrt::Windows::UI::Xaml::Interop::TypeName const& targetType,
            winrt::Windows::Foundation::IInspectable const& parameter,
            winrt::hstring const& language);
    };
}

namespace winrt::NeuralGuard::factory_implementation
{
    struct SemBrush : SemBrushT<SemBrush, implementation::SemBrush>
    {
    };
}
