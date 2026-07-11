#pragma once

#include "SemBrush.g.h"

namespace winrt::NeuralGuard::implementation
{
    struct SemBrush : SemBrushT<SemBrush>
    {
        SemBrush() = default;

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
