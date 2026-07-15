#include "pch.h"
#include "Tray.h"

#include <shellapi.h>

#include <atomic>
#include <thread>

namespace ngtray {
namespace {

constexpr UINT WM_TRAY = WM_APP + 1;
enum { ID_DASHBOARD = 1, ID_STATUS = 2, ID_PANIC = 3, ID_QUIT = 4 };

// Icon resource ids, mirrored from the old ngtray.rc into NeuralGuard.rc so the
// four live tray-state glyphs travel with the frontend that now owns them.
enum { IDI_TRAY_LEARNING = 10, IDI_TRAY_ENFORCING = 11, IDI_TRAY_PANIC = 12, IDI_TRAY_OFFLINE = 13 };

NOTIFYICONDATAW g_nid{};
HINSTANCE g_inst = nullptr;
HWND g_hwnd = nullptr;
Callbacks g_cb;
int g_curIconId = 0;
std::atomic<bool> g_hold{false};
std::atomic<bool> g_stopping{false};
std::thread g_pipe;

std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

void ApplyIcon(int id, const wchar_t* label) {
    if (id == g_curIconId) return;
    g_curIconId = id;
    g_nid.hIcon = LoadIconW(g_inst, MAKEINTRESOURCEW(id));
    swprintf_s(g_nid.szTip, L"NeuralGuard - %s", label);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

// Show a balloon and an actionable dialog for a blocked connection, returning the
// user's decision. (A true inline-button toast on an unpackaged Win32 app needs a
// COM activator; balloon + dialog gives the same choice with far less plumbing.)
char PromptUser(const std::string& msg) {
    // "NOTIFY\t<label>\t<port>" = balloon only, never a dialog. Inbound connections
    // are triggered by a REMOTE party, so they must not be able to put a modal on
    // the user's screen. We say it once, quietly; they permit the service at their
    // leisure in the Inbound view.
    if (msg.rfind("NOTIFY\t", 0) == 0) {
        std::string rest = msg.substr(7);
        std::string label = rest, port;
        size_t t = rest.find('\t');
        if (t != std::string::npos) { label = rest.substr(0, t); port = rest.substr(t + 1); }
        Balloon(L"NeuralGuard - inbound blocked",
                Widen(label) + L" on port " + Widen(port) +
                    L"\nOpen the dashboard to allow this service.");
        return 'N';
    }

    // msg is "app\tdest\tport"
    std::string app = msg, dest, port;
    size_t t1 = msg.find('\t');
    if (t1 != std::string::npos) {
        app = msg.substr(0, t1);
        size_t t2 = msg.find('\t', t1 + 1);
        if (t2 != std::string::npos) { dest = msg.substr(t1 + 1, t2 - t1 - 1); port = msg.substr(t2 + 1); }
    }
    Balloon(L"NeuralGuard - new connection",
            Widen(app) + L" -> " + Widen(dest) + L":" + Widen(port));
    return g_cb.prompt ? g_cb.prompt(Widen(app), Widen(dest), Widen(port)) : 'B';
}

// ngd (and ngctl notify) connect here to ask the user about a connection. This is
// the OPPOSITE direction from the command pipe in core/cmd.h, where ngd is the
// server - which is exactly why the two can't share a name.
void PipeServer() {
    const wchar_t* kPipe = L"\\\\.\\pipe\\neuralguard";
    while (!g_stopping) {
        HANDLE pipe = CreateNamedPipeW(kPipe, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 4096, 4096, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }

        BOOL ok = ConnectNamedPipe(pipe, nullptr) ? TRUE
                                                  : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (ok && !g_stopping) {
            char buf[1024] = {};
            DWORD n = 0;
            if (ReadFile(pipe, buf, sizeof(buf) - 1, &n, nullptr) && n > 0) {
                char decision = PromptUser(std::string(buf, n));
                DWORD wr = 0;
                WriteFile(pipe, &decision, 1, &wr, nullptr);
                FlushFileBuffers(pipe);
            }
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_TRAY:
            if (LOWORD(l) == WM_LBUTTONDBLCLK) {
                if (g_cb.openDashboard) g_cb.openDashboard();
            } else if (LOWORD(l) == WM_RBUTTONUP || LOWORD(l) == WM_CONTEXTMENU) {
                POINT pt; GetCursorPos(&pt);
                HMENU m = CreatePopupMenu();
                AppendMenuW(m, MF_STRING, ID_DASHBOARD, L"Dashboard");
                AppendMenuW(m, MF_STRING, ID_STATUS, L"Status");
                AppendMenuW(m, MF_STRING, ID_PANIC, L"Panic (fail open)");
                AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(m, MF_STRING, ID_QUIT, L"Quit");
                SetForegroundWindow(h);   // so the menu dismisses on click-away
                TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, nullptr);
                DestroyMenu(m);
            }
            return 0;
        case WM_COMMAND:
            switch (LOWORD(w)) {
                case ID_DASHBOARD: if (g_cb.openDashboard) g_cb.openDashboard(); break;
                case ID_STATUS:    if (g_cb.showStatus) g_cb.showStatus();       break;
                case ID_PANIC:     if (g_cb.panic) g_cb.panic();                 break;
                case ID_QUIT:      if (g_cb.quit) g_cb.quit();                   break;
            }
            return 0;
    }
    return DefWindowProcW(h, msg, w, l);
}

}  // namespace

bool Start(HINSTANCE inst, const Callbacks& cb) {
    g_inst = inst;
    g_cb = cb;

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.lpszClassName = L"NeuralGuardTrayWnd";
    RegisterClassW(&wc);
    g_hwnd = CreateWindowW(L"NeuralGuardTrayWnd", L"ngtray", 0, 0, 0, 0, 0,
                           HWND_MESSAGE, nullptr, inst, nullptr);
    if (!g_hwnd) return false;

    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_curIconId = IDI_TRAY_OFFLINE;
    g_nid.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(IDI_TRAY_OFFLINE));
    wcscpy_s(g_nid.szTip, L"NeuralGuard - idle");
    Shell_NotifyIconW(NIM_ADD, &g_nid);

    g_pipe = std::thread(PipeServer);
    return true;
}

void Stop() {
    g_stopping = true;
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    // The pipe thread is parked in ConnectNamedPipe; connecting to our own pipe
    // releases it so it can see g_stopping and return.
    HANDLE h = CreateFileW(L"\\\\.\\pipe\\neuralguard", GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (g_pipe.joinable()) g_pipe.join();
    if (g_hwnd) { DestroyWindow(g_hwnd); g_hwnd = nullptr; }
}

void SetMode(const std::string& mode) {
    if (g_hold.load()) return;
    if (mode == "learning")       ApplyIcon(IDI_TRAY_LEARNING, L"learning");
    else if (mode == "enforcing") ApplyIcon(IDI_TRAY_ENFORCING, L"enforcing");
    else                          ApplyIcon(IDI_TRAY_OFFLINE, L"idle");
}

void HoldMode(bool hold) {
    g_hold = hold;
    if (hold) ApplyIcon(IDI_TRAY_PANIC, L"panic");
}

void Balloon(const std::wstring& title, const std::wstring& text) {
    g_nid.uFlags |= NIF_INFO;
    wcsncpy_s(g_nid.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(g_nid.szInfo, text.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
}

}  // namespace ngtray
