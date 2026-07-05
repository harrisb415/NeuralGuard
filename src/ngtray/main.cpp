// ngtray - NeuralGuard system-tray app (Phase 2c, minimal).
//
// A native Win32 tray icon that runs in the interactive user session (a
// LocalSystem service can't show UI - session-0 isolation, see docs/DESIGN.md).
// It is deliberately thin: it shells out to ngctl for the privileged WFP actions
// (with a UAC elevation prompt), so the tray is pure UI. Right-click gives
// Status, the mandatory Panic (fail-open), and Quit.
//
// This first cut covers the icon + menu + panic. Actionable toast prompts for
// blocked connections (the block-notify-retry flow) need the ngd->tray pipe and
// come next.

#include <windows.h>
#include <shellapi.h>

#include <string>

namespace {

constexpr UINT WM_TRAY = WM_APP + 1;
enum { ID_STATUS = 1, ID_PANIC = 2, ID_QUIT = 3 };

NOTIFYICONDATAW g_nid{};

std::wstring ExeDir() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring s = path;
    size_t p = s.find_last_of(L"\\/");
    return (p == std::wstring::npos) ? L"." : s.substr(0, p);
}

// Run `ngctl <cmd>` elevated, keeping a console open so the output is visible.
void RunCtl(const wchar_t* sub) {
    std::wstring args = L"/k \"\"" + ExeDir() + L"\\ngctl.exe\" " + sub + L"\"";
    ShellExecuteW(nullptr, L"runas", L"cmd.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
}

LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_TRAY:
            if (LOWORD(l) == WM_RBUTTONUP || LOWORD(l) == WM_CONTEXTMENU) {
                POINT pt; GetCursorPos(&pt);
                HMENU m = CreatePopupMenu();
                AppendMenuW(m, MF_STRING, ID_STATUS, L"Status");
                AppendMenuW(m, MF_STRING, ID_PANIC, L"Panic (fail open)");
                AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(m, MF_STRING, ID_QUIT, L"Quit");
                SetForegroundWindow(h);  // so the menu dismisses on click-away
                TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, nullptr);
                DestroyMenu(m);
            }
            return 0;
        case WM_COMMAND:
            switch (LOWORD(w)) {
                case ID_STATUS: RunCtl(L"status"); break;
                case ID_PANIC:  RunCtl(L"panic");  break;
                case ID_QUIT:   DestroyWindow(h);  break;
            }
            return 0;
        case WM_DESTROY:
            Shell_NotifyIconW(NIM_DELETE, &g_nid);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(h, msg, w, l);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    // Single instance - don't stack tray icons.
    CreateMutexW(nullptr, TRUE, L"NeuralGuard_ngtray_singleton");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"ngtrayWnd";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowW(L"ngtrayWnd", L"ngtray", 0, 0, 0, 0, 0,
                              HWND_MESSAGE, nullptr, hInst, nullptr);

    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon = LoadIconW(nullptr, IDI_SHIELD);  // stock shield - fits a firewall
    wcscpy_s(g_nid.szTip, L"NeuralGuard");
    Shell_NotifyIconW(NIM_ADD, &g_nid);

    // Startup balloon so it's obvious the tray came up.
    g_nid.uFlags |= NIF_INFO;
    wcscpy_s(g_nid.szInfoTitle, L"NeuralGuard");
    wcscpy_s(g_nid.szInfo, L"Tray running. Right-click for Panic.");
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
