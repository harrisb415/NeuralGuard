#include "ngtray/dashboard.h"

#include "core/db.h"

#include <windows.h>
#include <shellapi.h>
#include <wrl.h>
#include "WebView2.h"

#include <string>

using namespace Microsoft::WRL;

namespace ng {
namespace {

HWND g_dashHwnd = nullptr;
ComPtr<ICoreWebView2Controller> g_controller;
ComPtr<ICoreWebView2> g_webview;

std::wstring ExeDir() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring s = path;
    size_t p = s.find_last_of(L"\\/");
    return (p == std::wstring::npos) ? L"." : s.substr(0, p);
}

std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

std::string JsonEsc(const char* s) {
    std::string o;
    for (const char* p = s ? s : ""; *p; ++p) {
        if (*p == '"' || *p == '\\') { o += '\\'; o += *p; }
        else if (*p == '\n') o += "\\n";
        else o += *p;
    }
    return o;
}

// Read the learned baseline from the DB and return it as a JSON string for the UI.
std::string BuildStatusJson() {
    std::string db = std::string();
    {
        std::wstring p = ExeDir() + L"\\ngpolicy.db";
        int n = WideCharToMultiByte(CP_UTF8, 0, p.c_str(), (int)p.size(), nullptr, 0, nullptr, nullptr);
        db.resize(n);
        WideCharToMultiByte(CP_UTF8, 0, p.c_str(), (int)p.size(), db.data(), n, nullptr, nullptr);
    }
    ng::Db d;
    if (!d.open(db.c_str()))
        return "{\"ok\":false,\"error\":\"no database\"}";
    sqlite3* h = d.handle();

    std::string json = "{\"ok\":true,";
    sqlite3_stmt* s = nullptr;
    sqlite3_prepare_v2(h, "SELECT (SELECT count(*) FROM habits),"
                          " (SELECT count(DISTINCT process_label) FROM habits),"
                          " (SELECT count(*) FROM flow_events);", -1, &s, nullptr);
    if (sqlite3_step(s) == SQLITE_ROW)
        json += "\"habits\":" + std::to_string(sqlite3_column_int(s, 0)) +
                ",\"apps\":" + std::to_string(sqlite3_column_int(s, 1)) +
                ",\"events\":" + std::to_string(sqlite3_column_int(s, 2)) + ",";
    sqlite3_finalize(s);

    json += "\"top\":[";
    sqlite3_prepare_v2(h, "SELECT process_label, dest, remote_port, round(count,1) FROM habits"
                          " ORDER BY count DESC LIMIT 20;", -1, &s, nullptr);
    bool first = true;
    while (sqlite3_step(s) == SQLITE_ROW) {
        if (!first) json += ",";
        first = false;
        json += "{\"app\":\"" + JsonEsc((const char*)sqlite3_column_text(s, 0)) +
                "\",\"dest\":\"" + JsonEsc((const char*)sqlite3_column_text(s, 1)) +
                "\",\"port\":" + std::to_string(sqlite3_column_int(s, 2)) +
                ",\"count\":" + std::to_string(sqlite3_column_double(s, 3)) + "}";
    }
    sqlite3_finalize(s);
    json += "]}";
    return json;
}

// Run `ngctl <sub>` or `ngd <sub>` elevated (UAC), visible so output shows.
void RunElevated(const wchar_t* tool, const wchar_t* sub) {
    std::wstring args = L"/k \"\"" + ExeDir() + L"\\" + tool + L"\" " + sub + L"\"";
    ShellExecuteW(nullptr, L"runas", L"cmd.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
}

const wchar_t* kHtml = LR"HTML(<!doctype html><html><head><meta charset="utf-8">
<style>
 body{font-family:Segoe UI,sans-serif;background:#0f1720;color:#e6edf3;margin:0;padding:16px}
 h1{font-size:18px;margin:0 0 4px} .sub{color:#8b98a5;font-size:12px;margin-bottom:12px}
 .row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
 button{background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:8px 14px;font-size:13px;cursor:pointer}
 button.warn{background:#b62324} button.ghost{background:#21313f}
 .card{background:#161f2b;border:1px solid #21313f;border-radius:8px;padding:12px;margin-bottom:12px}
 table{width:100%;border-collapse:collapse;font-size:12px} td,th{text-align:left;padding:4px 6px;border-bottom:1px solid #21313f}
 th{color:#8b98a5;font-weight:600} .num{text-align:right;color:#9fd0ff}
 .stat{display:inline-block;margin-right:18px} .stat b{font-size:18px;color:#fff}
</style></head><body>
 <h1>NeuralGuard</h1><div class="sub">habit-learning firewall - config dashboard</div>
 <div class="row">
   <button onclick="send('enforce')">Enforce</button>
   <button class="ghost" onclick="send('learn')">Learn</button>
   <button class="warn" onclick="send('panic')">Panic</button>
   <button class="ghost" onclick="send('refresh')">Refresh</button>
 </div>
 <div class="card" id="stats">loading…</div>
 <div class="card"><table id="top"><thead><tr><th>app</th><th>destination</th><th class="num">port</th><th class="num">count</th></tr></thead><tbody></tbody></table></div>
<script>
 const wv = window.chrome.webview;
 function send(c){ wv.postMessage(c); }
 wv.addEventListener('message', e => {
   let d; try{ d = JSON.parse(e.data); }catch{ return; }
   if(!d.ok){ document.getElementById('stats').textContent = d.error||'error'; return; }
   document.getElementById('stats').innerHTML =
     '<span class="stat"><b>'+d.habits+'</b><br>habits</span>'+
     '<span class="stat"><b>'+d.apps+'</b><br>apps</span>'+
     '<span class="stat"><b>'+d.events+'</b><br>events</span>';
   const tb = document.querySelector('#top tbody'); tb.innerHTML='';
   (d.top||[]).forEach(r=>{ const tr=document.createElement('tr');
     tr.innerHTML='<td>'+r.app+'</td><td>'+r.dest+'</td><td class="num">'+r.port+'</td><td class="num">'+r.count+'</td>'; tb.appendChild(tr); });
 });
 send('refresh');
</script></body></html>)HTML";

void OnMessage(const std::wstring& cmd) {
    if (cmd == L"refresh") {
        if (g_webview) g_webview->PostWebMessageAsString(Widen(BuildStatusJson()).c_str());
    } else if (cmd == L"panic") {
        RunElevated(L"ngctl.exe", L"panic");
    } else if (cmd == L"enforce") {
        RunElevated(L"ngd.exe", L"enforce ngpolicy.db 0");
    } else if (cmd == L"learn") {
        RunElevated(L"ngd.exe", L"record ngpolicy.db");
    }
}

void InitWebView(HWND hwnd) {
    std::wstring dataDir = ExeDir() + L"\\wv2data";
    CreateCoreWebView2EnvironmentWithOptions(nullptr, dataDir.c_str(), nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [hwnd](HRESULT, ICoreWebView2Environment* env) -> HRESULT {
                env->CreateCoreWebView2Controller(hwnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [hwnd](HRESULT, ICoreWebView2Controller* controller) -> HRESULT {
                            if (!controller) return S_OK;
                            g_controller = controller;
                            controller->get_CoreWebView2(&g_webview);
                            RECT rc; GetClientRect(hwnd, &rc);
                            controller->put_Bounds(rc);
                            EventRegistrationToken tok;
                            g_webview->add_WebMessageReceived(
                                Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                                        LPWSTR raw = nullptr;
                                        if (SUCCEEDED(args->TryGetWebMessageAsString(&raw)) && raw) {
                                            OnMessage(raw);
                                            CoTaskMemFree(raw);
                                        }
                                        return S_OK;
                                    }).Get(), &tok);
                            g_webview->NavigateToString(kHtml);
                            return S_OK;
                        }).Get());
                return S_OK;
            }).Get());
}

LRESULT CALLBACK DashProc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_SIZE:
            if (g_controller) { RECT rc; GetClientRect(h, &rc); g_controller->put_Bounds(rc); }
            return 0;
        case WM_DESTROY:
            if (g_controller) g_controller->Close();
            g_webview.Reset();
            g_controller.Reset();
            g_dashHwnd = nullptr;
            return 0;
    }
    return DefWindowProcW(h, msg, w, l);
}

}  // namespace

void OpenDashboard(HINSTANCE hInst) {
    if (g_dashHwnd) { SetForegroundWindow(g_dashHwnd); return; }

    static bool registered = false;
    if (!registered) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = DashProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = L"ngDashWnd";
        RegisterClassW(&wc);
        registered = true;
    }
    g_dashHwnd = CreateWindowW(L"ngDashWnd", L"NeuralGuard", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, 760, 640,
                               nullptr, nullptr, hInst, nullptr);
    ShowWindow(g_dashHwnd, SW_SHOW);
    InitWebView(g_dashHwnd);
}

}  // namespace ng
