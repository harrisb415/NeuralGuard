// NeuralGuard config dashboard - a native Win32 window (Common Controls), hosted
// by the tray. No WebView2/HTML. Increment 1: tabbed shell with Rules + Habits
// ListViews (read from the DB) and a status-bar live mode indicator (polls the
// mode ngd writes to meta). More tabs (Live feed, Apps, History, Settings) and
// rule editing land in following increments.
#include "ngtray/dashboard.h"

#include "core/db.h"

#include <windows.h>
#include <commctrl.h>

#include <string>

namespace ng {
namespace {

enum { TAB_RULES = 0, TAB_HABITS = 1, TAB_COUNT = 2 };

HWND g_dash = nullptr, g_tabs = nullptr, g_status = nullptr;
HWND g_lv[TAB_COUNT] = {};
int  g_cur = 0;

std::wstring ExeDir() {
    wchar_t p[MAX_PATH]; GetModuleFileNameW(nullptr, p, MAX_PATH);
    std::wstring s = p; size_t i = s.find_last_of(L"\\/");
    return (i == std::wstring::npos) ? L"." : s.substr(0, i);
}
std::string DbPathU8() {
    std::wstring w = ExeDir() + L"\\ngpolicy.db";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}
std::wstring Widen(const char* s) {
    if (!s) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), n);
    if (!w.empty() && w.back() == 0) w.pop_back();
    return w;
}

void AddCol(HWND lv, int i, const wchar_t* t, int cx) {
    LVCOLUMNW c{}; c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = const_cast<LPWSTR>(t); c.cx = cx; c.iSubItem = i;
    ListView_InsertColumn(lv, i, &c);
}
void SetCell(HWND lv, int row, int col, const char* u8) {
    std::wstring w = Widen(u8);
    LVITEMW it{}; it.mask = LVIF_TEXT; it.iItem = row; it.iSubItem = col;
    it.pszText = const_cast<LPWSTR>(w.c_str());
    if (col == 0) ListView_InsertItem(lv, &it); else ListView_SetItem(lv, &it);
}

void FillHabits(HWND lv) {
    ListView_DeleteAllItems(lv);
    Db d; if (!d.open(DbPathU8().c_str())) return;
    sqlite3_stmt* s = nullptr;
    sqlite3_prepare_v2(d.handle(),
        "SELECT process_label, dest, remote_port, round(count,1) FROM habits"
        " ORDER BY count DESC LIMIT 1000;", -1, &s, nullptr);
    int row = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        SetCell(lv, row, 0, (const char*)sqlite3_column_text(s, 0));
        SetCell(lv, row, 1, (const char*)sqlite3_column_text(s, 1));
        SetCell(lv, row, 2, std::to_string(sqlite3_column_int(s, 2)).c_str());
        SetCell(lv, row, 3, std::to_string(sqlite3_column_int(s, 3)).c_str());
        ++row;
    }
    sqlite3_finalize(s);
}

void FillRules(HWND lv) {
    ListView_DeleteAllItems(lv);
    Db d; if (!d.open(DbPathU8().c_str())) return;
    sqlite3_stmt* s = nullptr;
    sqlite3_prepare_v2(d.handle(),
        "SELECT pi.image_path, fe.remote_port,"
        " COUNT(DISTINCT fe.local_port || '|' || fe.remote_addr) AS c"
        " FROM flow_events fe JOIN process_identity pi ON fe.image_id = pi.id"
        " WHERE fe.remote_port > 0 AND fe.remote_port < 49152 AND pi.image_path LIKE '_:\\%'"
        "   AND fe.verdict IN ('ALLOW','CAPALLOW')"
        " GROUP BY pi.image_path, fe.remote_port HAVING c >= 3 ORDER BY c DESC;", -1, &s, nullptr);
    int row = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        SetCell(lv, row, 0, (const char*)sqlite3_column_text(s, 0));
        SetCell(lv, row, 1, std::to_string(sqlite3_column_int(s, 1)).c_str());
        SetCell(lv, row, 2, std::to_string(sqlite3_column_int(s, 2)).c_str());
        ++row;
    }
    sqlite3_finalize(s);
}

std::wstring ReadMode() {
    Db d; if (!d.open(DbPathU8().c_str())) return L"unknown";
    sqlite3_stmt* s = nullptr; std::wstring m = L"idle";
    sqlite3_prepare_v2(d.handle(), "SELECT v FROM meta WHERE k='mode';", -1, &s, nullptr);
    if (sqlite3_step(s) == SQLITE_ROW) m = Widen((const char*)sqlite3_column_text(s, 0));
    sqlite3_finalize(s);
    return m;
}

void UpdateStatus() {
    std::wstring t = L"  Mode:  " + ReadMode();
    SendMessageW(g_status, SB_SETTEXTW, 0, (LPARAM)t.c_str());
}

void LayoutChildren() {
    RECT rc; GetClientRect(g_dash, &rc);
    SendMessageW(g_status, WM_SIZE, 0, 0);
    RECT sb; GetWindowRect(g_status, &sb);
    int sbh = sb.bottom - sb.top;
    MoveWindow(g_tabs, 0, 0, rc.right, rc.bottom - sbh, TRUE);
    RECT disp = {0, 0, rc.right, rc.bottom - sbh};
    TabCtrl_AdjustRect(g_tabs, FALSE, &disp);
    for (int i = 0; i < TAB_COUNT; ++i)
        MoveWindow(g_lv[i], disp.left, disp.top, disp.right - disp.left, disp.bottom - disp.top, TRUE);
}

void ShowTab(int i) {
    g_cur = i;
    for (int k = 0; k < TAB_COUNT; ++k) ShowWindow(g_lv[k], k == i ? SW_SHOW : SW_HIDE);
    if (i == TAB_RULES) FillRules(g_lv[TAB_RULES]);
    else                FillHabits(g_lv[TAB_HABITS]);
}

LRESULT CALLBACK Proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_NOTIFY: {
            LPNMHDR n = (LPNMHDR)l;
            if (n->hwndFrom == g_tabs && n->code == TCN_SELCHANGE) ShowTab(TabCtrl_GetCurSel(g_tabs));
            return 0;
        }
        case WM_SIZE:  LayoutChildren(); return 0;
        case WM_TIMER: UpdateStatus();   return 0;
        case WM_DESTROY: KillTimer(h, 1); g_dash = nullptr; return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

}  // namespace

void OpenDashboard(HINSTANCE hInst) {
    if (g_dash) { SetForegroundWindow(g_dash); return; }

    INITCOMMONCONTROLSEX ic{sizeof(ic), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    InitCommonControlsEx(&ic);

    static bool reg = false;
    if (!reg) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = Proc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"ngDashWnd";
        RegisterClassW(&wc);
        reg = true;
    }
    g_dash = CreateWindowW(L"ngDashWnd", L"NeuralGuard", WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 840, 600, nullptr, nullptr, hInst, nullptr);

    g_tabs = CreateWindowW(WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE,
                           0, 0, 0, 0, g_dash, nullptr, hInst, nullptr);
    TCITEMW ti{}; ti.mask = TCIF_TEXT;
    ti.pszText = const_cast<LPWSTR>(L"Rules");  TabCtrl_InsertItem(g_tabs, TAB_RULES, &ti);
    ti.pszText = const_cast<LPWSTR>(L"Habits"); TabCtrl_InsertItem(g_tabs, TAB_HABITS, &ti);

    DWORD lvStyle = WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS;
    for (int i = 0; i < TAB_COUNT; ++i) {
        g_lv[i] = CreateWindowW(WC_LISTVIEWW, L"", lvStyle, 0, 0, 0, 0, g_dash, nullptr, hInst, nullptr);
        ListView_SetExtendedListViewStyle(g_lv[i], LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    }
    AddCol(g_lv[TAB_RULES], 0, L"Application (permitted)", 420);
    AddCol(g_lv[TAB_RULES], 1, L"Port", 70);
    AddCol(g_lv[TAB_RULES], 2, L"Connections", 110);
    AddCol(g_lv[TAB_HABITS], 0, L"Application", 240);
    AddCol(g_lv[TAB_HABITS], 1, L"Destination", 320);
    AddCol(g_lv[TAB_HABITS], 2, L"Port", 70);
    AddCol(g_lv[TAB_HABITS], 3, L"Count", 70);

    g_status = CreateWindowW(STATUSCLASSNAMEW, L"", WS_CHILD | WS_VISIBLE,
                             0, 0, 0, 0, g_dash, nullptr, hInst, nullptr);

    LayoutChildren();
    ShowTab(TAB_RULES);
    UpdateStatus();
    SetTimer(g_dash, 1, 2000, nullptr);
    ShowWindow(g_dash, SW_SHOW);
}

}  // namespace ng
