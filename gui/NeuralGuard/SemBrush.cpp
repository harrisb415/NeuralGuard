#include "pch.h"
#include "SemBrush.h"
#include "SemBrush.g.cpp"

#include <cwctype>
#include <string>

using namespace winrt;
using namespace Microsoft::UI::Xaml;

namespace winrt::NeuralGuard::implementation
{
    // Set by MainWindow::ApplyTheme. See the note on SemBrush::SetLightTheme.
    static bool g_light = false;

    void SemBrush::SetLightTheme(bool light) { g_light = light; }

    // Resolve a brush by key from the ACTIVE theme dictionary.
    //
    // Plain Application.Resources.Lookup() would resolve against the app-level
    // theme, which is deliberately never set now (see App.xaml) - so it would
    // always hand back the same dictionary regardless of the window's theme, and
    // every verdict pill would keep its dark neon colour on a light background.
    // Walk the merged dictionaries to the one carrying ThemeDictionaries
    // (NeuralGuardColors.xaml) and index it explicitly instead.
    static Media::Brush LookupBrush(hstring const& key)
    {
        auto k = box_value(key);
        auto themeKey = box_value(g_light ? hstring{ L"Light" } : hstring{ L"Dark" });
        auto appRes = Application::Current().Resources();

        for (auto const& merged : appRes.MergedDictionaries())
        {
            auto themes = merged.ThemeDictionaries();
            if (!themes || !themes.HasKey(themeKey)) continue;
            auto dict = themes.Lookup(themeKey).try_as<ResourceDictionary>();
            if (dict && dict.HasKey(k))
                if (auto b = dict.Lookup(k).try_as<Media::Brush>()) return b;
        }
        // Fall back to a flat app-level lookup so a key that isn't themed (or a
        // restructured dictionary) still resolves rather than rendering nothing.
        return appRes.HasKey(k) ? appRes.Lookup(k).try_as<Media::Brush>() : nullptr;
    }

    static Media::Brush Transparent()
    {
        return Media::SolidColorBrush{ Windows::UI::Color{ 0, 0, 0, 0 } };
    }

    // Cell text -> verdict/state key suffix ("Allow" / "CapAllow" / "Block" /
    // "Monitor" / "Permitted"), or empty for non-token text (ports, counts, ...).
    // Substring, case-insensitive: tokens are distinct words that never collide.
    static std::wstring KeyFor(std::wstring const& upper)
    {
        auto has = [&](std::wstring_view s) { return upper.find(s) != std::wstring::npos; };
        if (has(L"CAPALLOW"))                                return L"CapAllow";  // before ALLOW
        if (has(L"MALICIOUS"))                               return L"Block";
        if (has(L"ALLOW"))                                   return L"Allow";     // ALLOW / auto-allow
        if (has(L"BLOCK") || has(L"DROP") || has(L"DEMOTE")) return L"Block";     // block/DROP/DEMOTED/demote
        if (has(L"MONITOR") || has(L"REVIEW"))               return L"Monitor";
        if (has(L"PERMIT"))                                  return L"Permitted"; // permitted / permit
        if (has(L"BENIGN"))                                  return L"Allow";
        return L"";
    }

    // ConverterParameter selects what to return for a cell:
    //   fg (default) - bright token color, else primary text
    //   bg           - dim token fill,     else transparent (pill background)
    //   border       - bright token color, else transparent (pill border)
    //   blocked      - Per-app Blocked count: red when > 0, else muted
    Windows::Foundation::IInspectable SemBrush::Convert(
        Windows::Foundation::IInspectable const& value,
        Windows::UI::Xaml::Interop::TypeName const&,
        Windows::Foundation::IInspectable const& parameter,
        hstring const&)
    {
        std::wstring param{ unbox_value_or<hstring>(parameter, L"fg") };
        std::wstring text{ unbox_value_or<hstring>(value, L"") };

        if (param == L"blocked")
        {
            int n = 0; try { n = std::stoi(text); } catch (...) {}
            auto b = LookupBrush(n > 0 ? L"NG.Brush.Verdict.Block" : L"NG.Brush.Text.Muted");
            return b ? b : Transparent();
        }
        // Flows: anomaly score amber when negative, else default text.
        if (param == L"anomaly")
        {
            double v = 0; try { v = std::stod(text); } catch (...) {}
            auto b = LookupBrush(v < 0 ? L"NG.Brush.Verdict.Monitor" : L"NG.Brush.Text.Primary");
            return b ? b : Transparent();
        }
        // Flows: P(malicious) red at/above 0.5, else default text.
        if (param == L"malicious")
        {
            double v = 0; try { v = std::stod(text); } catch (...) {}
            auto b = LookupBrush(v >= 0.5 ? L"NG.Brush.Verdict.Block" : L"NG.Brush.Text.Primary");
            return b ? b : Transparent();
        }

        std::wstring upper = text;
        for (auto& c : upper) c = (wchar_t)std::towupper((wint_t)c);
        std::wstring key = KeyFor(upper);

        if (key.empty())
        {
            if (param == L"bg" || param == L"border") return Transparent();
            if (auto d = LookupBrush(L"NG.Brush.Text.Primary")) return d;
            return Transparent();
        }

        hstring base = hstring{ L"NG.Brush.Verdict." } + hstring{ key };
        if (param == L"bg")
        {
            if (auto b = LookupBrush(base + L".BG")) return b;
            return Transparent();
        }
        // fg and border both use the bright token brush
        if (auto b = LookupBrush(base)) return b;
        return Transparent();
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
