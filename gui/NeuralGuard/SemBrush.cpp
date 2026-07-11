#include "pch.h"
#include "SemBrush.h"
#include "SemBrush.g.cpp"

#include <cwctype>
#include <string>

using namespace winrt;
using namespace Microsoft::UI::Xaml;

namespace winrt::NeuralGuard::implementation
{
    // Resolve an app-level brush resource by key (null if absent).
    static Media::Brush LookupBrush(hstring const& key)
    {
        auto res = Application::Current().Resources();
        auto k = box_value(key);
        return res.HasKey(k) ? res.Lookup(k).try_as<Media::Brush>() : nullptr;
    }

    // Cell text -> semantic brush key. Tokens are distinct words, so a plain
    // substring match (case-insensitive) never collides with ports / counts /
    // timestamps / hostnames, which return the default and stay theme-colored.
    static hstring KeyFor(std::wstring const& upper)
    {
        auto has = [&](std::wstring_view s) { return upper.find(s) != std::wstring::npos; };
        if (has(L"CAPALLOW"))                 return L"NG.Brush.Verdict.CapAllow";  // before ALLOW
        if (has(L"MALICIOUS"))                return L"NG.Brush.Verdict.Block";     // before ALLOW-in-... n/a
        if (has(L"ALLOW"))                    return L"NG.Brush.Verdict.Allow";     // ALLOW / allow / auto-allow
        if (has(L"BLOCK") || has(L"DROP") || has(L"DEMOTE")) return L"NG.Brush.Verdict.Block"; // block/DEMOTED/demote
        if (has(L"MONITOR") || has(L"REVIEW")) return L"NG.Brush.Verdict.Monitor";
        if (has(L"PERMIT"))                   return L"NG.Brush.Verdict.Permitted"; // permitted / permit
        if (has(L"BENIGN"))                   return L"NG.Brush.Verdict.Allow";
        return hstring{};
    }

    Windows::Foundation::IInspectable SemBrush::Convert(
        Windows::Foundation::IInspectable const& value,
        Windows::UI::Xaml::Interop::TypeName const&,
        Windows::Foundation::IInspectable const&,
        hstring const&)
    {
        std::wstring text{ unbox_value_or<hstring>(value, L"") };
        for (auto& c : text) c = (wchar_t)std::towupper((wint_t)c);

        if (hstring key = KeyFor(text); !key.empty())
            if (auto b = LookupBrush(key)) return b;

        // Default: primary text brush, so converter-bound cells still theme correctly.
        if (auto d = LookupBrush(L"NG.Brush.Text.Primary")) return d;
        return nullptr;
    }

    Windows::Foundation::IInspectable SemBrush::ConvertBack(
        Windows::Foundation::IInspectable const&,
        Windows::UI::Xaml::Interop::TypeName const&,
        Windows::Foundation::IInspectable const&,
        hstring const&)
    {
        throw hresult_not_implemented();
    }
}
