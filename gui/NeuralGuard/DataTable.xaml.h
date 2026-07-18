#pragma once

#include "DataTable.g.h"
#include "RowData.h"

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

namespace winrt::NeuralGuard::implementation
{
    struct DataTable : DataTableT<DataTable>
    {
        DataTable() { InitializeComponent(); }

        // --- driven by MainWindow (via winrt::get_self) ---
        // Configure columns for a view: pick the row DataTemplate by key and set the
        // five header column widths (a negative width = star / fills remaining). Also
        // clears the live-diff state so the next SetRows does one full rebuild.
        void SetView(winrt::hstring const& templateKey, std::array<double, 5> const& widths);
        // Header labels (a sort arrow is appended to the active sort column).
        void SetHeaders(std::array<winrt::hstring, 5> const& headers);
        // Right-align headers 3/4 over right-aligned numeric cells (Flows); else left.
        void SetHeaderRightAlign(bool col3, bool col4);
        // Push the current view's rows. `live` enables the in-place incremental
        // update (Live feed). `emptyText` shows when there are no rows and no filter.
        void SetRows(std::vector<RowData> const& rows, bool live, winrt::hstring const& emptyText);
        // Case-insensitive filter across all columns; re-renders the cached rows.
        void SetFilter(winrt::hstring const& f);
        // The Per-app drill-down trust card above the table.
        void SetAppDetail(bool show, winrt::hstring const& totals, winrt::hstring const& trust);
        // Drop the live-diff cache so the next SetRows rebuilds every row from
        // scratch (used after a theme change, which rebakes the row pill brushes).
        void InvalidateRows() { liveItemsValid_ = false; }

        // Row actions bubble back to MainWindow (which owns the DB writes / menus).
        void SetOnContext(std::function<void(winrt::NeuralGuard::Row,
                          winrt::Microsoft::UI::Xaml::FrameworkElement,
                          winrt::Windows::Foundation::Point)> f) { onContext_ = std::move(f); }
        void SetOnInvoke(std::function<void(winrt::NeuralGuard::Row)> f) { onInvoke_ = std::move(f); }
        // Highlight a row (MainWindow calls this before showing a context menu).
        void SelectRow(winrt::NeuralGuard::Row const& row);

        // --- XAML event handlers ---
        void OnHeaderTap(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::Input::TappedRoutedEventArgs const&);
        void OnContainerChanging(winrt::Microsoft::UI::Xaml::Controls::ListViewBase const&,
                                 winrt::Microsoft::UI::Xaml::Controls::ContainerContentChangingEventArgs const&);
        void OnRowRightTapped(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::Input::RightTappedRoutedEventArgs const&);
        void OnRowDoubleTapped(winrt::Windows::Foundation::IInspectable const&, winrt::Microsoft::UI::Xaml::Input::DoubleTappedRoutedEventArgs const&);

    private:
        winrt::Microsoft::UI::Xaml::Controls::TextBlock HdrBlock(int i);
        void ApplyHeaderText();
        void Render();   // filter + sort + selection/scroll preservation + live-diff-or-rebuild
        winrt::NeuralGuard::Row RowUnder(winrt::Windows::Foundation::IInspectable const& originalSource);

        std::function<void(winrt::NeuralGuard::Row, winrt::Microsoft::UI::Xaml::FrameworkElement, winrt::Windows::Foundation::Point)> onContext_;
        std::function<void(winrt::NeuralGuard::Row)> onInvoke_;

        winrt::hstring baseHdr_[5];        // header text without the sort arrow
        int  sortCol_{ -1 };               // sorted column, -1 = unsorted
        bool sortAsc_{ true };
        winrt::hstring filter_;            // case-insensitive filter for the current view
        winrt::hstring emptyText_{ L"(no rows yet)" };
        std::vector<RowData> lastRows_;    // rows as pushed by SetRows (pre filter/sort)
        bool live_{ false };

        // Live feed: mutate this collection in place across ticks instead of
        // replacing ItemsSource (which flickers); liveIds_ mirrors it by row id so
        // the next tick can diff. liveItemsValid_ is cleared by SetView (tab switch).
        winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Foundation::IInspectable> liveItems_{ nullptr };
        std::vector<int64_t> liveIds_;
        bool liveItemsValid_{ false };
    };
}

namespace winrt::NeuralGuard::factory_implementation
{
    struct DataTable : DataTableT<DataTable, implementation::DataTable>
    {
    };
}
