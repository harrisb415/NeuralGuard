#pragma once
// The plain data a view produces for one table row: a hidden DB id (used by
// row actions) + five display-column strings. MainWindow's RefreshCurrent builds
// a vector of these per view and hands them to the DataTable control, which turns
// them into Row objects for display. Shared so both sides agree on the shape.
#include <cstdint>
#include <winrt/Windows.Foundation.h>

namespace winrt::NeuralGuard::implementation
{
    struct RowData
    {
        int64_t id;
        winrt::hstring c[5];
    };
}
