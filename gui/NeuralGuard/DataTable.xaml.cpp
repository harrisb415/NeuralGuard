#include "pch.h"
#include "DataTable.xaml.h"
#if __has_include("DataTable.g.cpp")
#include "DataTable.g.cpp"
#endif

#include "Row.h"
#include "MainWindow.Shared.h"   // U8, MakeRow, FindScrollViewer, TagInt

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <string>

using namespace winrt;
using namespace winrt::Windows::Foundation;
using namespace winrt::Microsoft::UI::Xaml;
using namespace winrt::Microsoft::UI::Xaml::Controls;
using namespace winrt::Microsoft::UI::Xaml::Input;
using namespace winrt::Microsoft::UI::Xaml::Media;

namespace winrt::NeuralGuard::implementation
{
    TextBlock DataTable::HdrBlock(int i)
    {
        switch (i) { case 0: return H0(); case 1: return H1(); case 2: return H2(); case 3: return H3(); default: return H4(); }
    }

    void DataTable::ApplyHeaderText()
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

    void DataTable::SetView(hstring const& templateKey, std::array<double, 5> const& widths)
    {
        if (Resources().HasKey(box_value(templateKey)))
            DataList().ItemTemplate(Resources().Lookup(box_value(templateKey)).as<DataTemplate>());
        auto gl = [](double v) {
            return v < 0 ? GridLength{ 1, GridUnitType::Star } : GridLength{ v, GridUnitType::Pixel };
        };
        HCol0().Width(gl(widths[0])); HCol1().Width(gl(widths[1])); HCol2().Width(gl(widths[2]));
        HCol3().Width(gl(widths[3])); HCol4().Width(gl(widths[4]));
        liveItemsValid_ = false;   // force one full rebuild before the live diff resumes
    }

    void DataTable::SetHeaders(std::array<hstring, 5> const& headers)
    {
        for (int i = 0; i < 5; ++i) baseHdr_[i] = headers[i];
        ApplyHeaderText();
    }

    void DataTable::SetHeaderRightAlign(bool col3, bool col4)
    {
        using winrt::Microsoft::UI::Xaml::TextAlignment;
        H3().TextAlignment(col3 ? TextAlignment::Right : TextAlignment::Left);
        H4().TextAlignment(col4 ? TextAlignment::Right : TextAlignment::Left);
        H3().Margin(col3 ? Thickness{ 0, 0, 22, 0 } : Thickness{ 0, 0, 0, 0 });
        H4().Margin(col4 ? Thickness{ 0, 0, 4, 0 } : Thickness{ 0, 0, 0, 0 });
    }

    void DataTable::SetRows(std::vector<RowData> const& rows, bool live, hstring const& emptyText)
    {
        lastRows_ = rows;
        live_ = live;
        emptyText_ = emptyText;
        Render();
    }

    void DataTable::SetFilter(hstring const& f)
    {
        filter_ = f;
        Render();
    }

    void DataTable::SetAppDetail(bool show, hstring const& totals, hstring const& trust)
    {
        AppDetailCard().Visibility(show ? Visibility::Visible : Visibility::Collapsed);
        AppDetailTotals().Text(totals);
        AppDetailTrust().Text(trust);
    }

    void DataTable::SelectRow(NeuralGuard::Row const& row)
    {
        DataList().SelectedItem(row);
    }

    void DataTable::OnHeaderTap(IInspectable const& sender, TappedRoutedEventArgs const&)
    {
        int col = TagInt(sender);
        if (baseHdr_[col].empty()) return;   // blank column - not sortable
        if (col == sortCol_) sortAsc_ = !sortAsc_; else { sortCol_ = col; sortAsc_ = true; }
        ApplyHeaderText();
        Render();
    }

    // Each row's Grid is rebuilt whenever the ItemsSource is replaced (every refresh),
    // so re-apply the current column widths as each container is realized - this is
    // what keeps the per-view column layout instead of the template's default widths.
    void DataTable::OnContainerChanging(ListViewBase const&, ContainerContentChangingEventArgs const& args)
    {
        if (args.InRecycleQueue()) return;
        auto container = args.ItemContainer();
        if (!container) return;
        if (auto g = container.ContentTemplateRoot().try_as<Grid>())
        {
            auto cols = g.ColumnDefinitions();
            if (cols.Size() >= 5)
            {
                cols.GetAt(0).Width(HCol0().Width()); cols.GetAt(1).Width(HCol1().Width());
                cols.GetAt(2).Width(HCol2().Width()); cols.GetAt(3).Width(HCol3().Width());
                cols.GetAt(4).Width(HCol4().Width());
            }
        }
    }

    static ListViewItem ContainerUnder(IInspectable const& originalSource)
    {
        DependencyObject src = originalSource.try_as<DependencyObject>();
        while (src)
        {
            if (auto lvi = src.try_as<ListViewItem>()) return lvi;
            src = VisualTreeHelper::GetParent(src);
        }
        return nullptr;
    }

    void DataTable::OnRowRightTapped(IInspectable const&, RightTappedRoutedEventArgs const& e)
    {
        auto container = ContainerUnder(e.OriginalSource());
        if (!container) return;
        auto row = DataList().ItemFromContainer(container).try_as<NeuralGuard::Row>();
        if (!row) return;
        DataList().SelectedItem(row);   // highlight the row the menu acts on
        if (onContext_) onContext_(row, container, e.GetPosition(container));
    }

    void DataTable::OnRowDoubleTapped(IInspectable const&, DoubleTappedRoutedEventArgs const& e)
    {
        auto container = ContainerUnder(e.OriginalSource());
        if (!container) return;
        auto row = DataList().ItemFromContainer(container).try_as<NeuralGuard::Row>();
        if (row && onInvoke_) onInvoke_(row);
    }

    // Turn lastRows_ into the on-screen list: filter, sort, then either patch the
    // Live feed in place (no flicker) or rebuild wholesale, preserving the selected
    // row (by id) and the scroll position across the rebuild.
    void DataTable::Render()
    {
        std::vector<RowData> rows = lastRows_;

        if (!filter_.empty())
        {
            std::string f = to_string(filter_);
            for (auto& ch : f) ch = (char)tolower((unsigned char)ch);
            rows.erase(std::remove_if(rows.begin(), rows.end(), [&](RowData const& r) {
                for (int i = 0; i < 5; ++i)
                {
                    std::string c = to_string(r.c[i]);
                    for (auto& ch : c) ch = (char)tolower((unsigned char)ch);
                    if (c.find(f) != std::string::npos) return false;   // a column matches - keep
                }
                return true;   // nothing matched - drop
            }), rows.end());
        }

        if (rows.empty())
            rows.push_back({ 0, { L"", L"", !filter_.empty() ? hstring(L"(no matches)") : emptyText_, L"", L"" } });

        if (sortCol_ >= 0 && sortCol_ < 5)
        {
            int col = sortCol_; bool asc = sortAsc_;
            std::stable_sort(rows.begin(), rows.end(), [col, asc](RowData const& a, RowData const& b) {
                std::string sa = to_string(a.c[col]), sb = to_string(b.c[col]);
                char* ea = nullptr; char* eb = nullptr;
                double da = std::strtod(sa.c_str(), &ea), db = std::strtod(sb.c_str(), &eb);
                bool na = !sa.empty() && ea && *ea == 0, nb = !sb.empty() && eb && *eb == 0;
                int cmp;
                if (na && nb) cmp = da < db ? -1 : da > db ? 1 : 0;
                else {
                    for (auto& ch : sa) ch = (char)tolower((unsigned char)ch);
                    for (auto& ch : sb) ch = (char)tolower((unsigned char)ch);
                    int c = sa.compare(sb); cmp = c < 0 ? -1 : c > 0 ? 1 : 0;
                }
                return asc ? cmp < 0 : cmp > 0;
            });
        }

        int64_t selId = 0;
        if (auto sel = DataList().SelectedItem().try_as<NeuralGuard::Row>()) selId = sel.Id();
        auto scroller = FindScrollViewer(DataList());
        double vOffset = scroller ? scroller.VerticalOffset() : 0;

        // Live: zero or more brand-new rows prepended, then the same old rows in the
        // same order (some trimmed off the tail by the LIMIT). Find where the old
        // list's first row reappears (= how many are new), verify the rest lines up,
        // and patch in place; if a filter/sort broke the alignment, fall through to
        // a full rebuild. (See the long note this was moved from.)
        if (live_ && liveItemsValid_ && !liveIds_.empty())
        {
            std::vector<int64_t> newIds;
            newIds.reserve(rows.size());
            for (auto const& r : rows) newIds.push_back(r.id);

            size_t oldN = liveIds_.size(), newN = newIds.size();
            size_t k = 0;
            while (k < newN && newIds[k] != liveIds_[0]) ++k;

            bool aligned = k < newN;
            size_t overlap = 0;
            if (aligned)
            {
                overlap = (oldN < newN - k) ? oldN : (newN - k);
                for (size_t i = 0; i < overlap; ++i)
                    if (newIds[k + i] != liveIds_[i]) { aligned = false; break; }
            }

            if (aligned)
            {
                for (size_t i = 0; i < k; ++i)
                {
                    auto const& r = rows[i];
                    liveItems_.InsertAt((uint32_t)i, MakeRow(r.id, r.c[0], r.c[1], r.c[2], r.c[3], r.c[4]));
                }
                while (liveItems_.Size() > (uint32_t)newN) liveItems_.RemoveAt(liveItems_.Size() - 1);
                liveIds_ = std::move(newIds);

                if (selId != 0)
                {
                    uint32_t idx = 0;
                    for (auto const& it : liveItems_)
                    {
                        if (auto r = it.try_as<NeuralGuard::Row>(); r && r.Id() == selId)
                        {
                            DataList().SelectedIndex((int32_t)idx);
                            break;
                        }
                        ++idx;
                    }
                }
                return;   // in-place patch resets no scroll
            }
            // not aligned - fall through to the full rebuild below
        }

        auto items = single_threaded_observable_vector<IInspectable>();
        for (auto const& r : rows)
            items.Append(MakeRow(r.id, r.c[0], r.c[1], r.c[2], r.c[3], r.c[4]));
        DataList().ItemsSource(items);

        if (live_)
        {
            liveItems_ = items;
            liveIds_.clear();
            liveIds_.reserve(rows.size());
            for (auto const& r : rows) liveIds_.push_back(r.id);
            liveItemsValid_ = true;
        }

        if (selId != 0)
        {
            uint32_t idx = 0;
            for (auto const& it : items)
            {
                if (auto r = it.try_as<NeuralGuard::Row>(); r && r.Id() == selId)
                {
                    DataList().SelectedIndex((int32_t)idx);
                    break;
                }
                ++idx;
            }
        }

        // Defer the scroll restore: the new ItemsSource still needs a layout pass
        // before the ScrollViewer's extent is valid.
        if (vOffset > 0)
        {
            DispatcherQueue().TryEnqueue([this, vOffset] {
                if (auto sv = FindScrollViewer(DataList()))
                    sv.ChangeView(nullptr, box_value(vOffset).as<IReference<double>>(), nullptr, true);
            });
        }
    }
}
