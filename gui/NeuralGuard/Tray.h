// The system-tray half of the dashboard - what used to be a whole separate
// process, ngtray.exe.
//
// Why they merged: a LocalSystem service can't show UI (session-0 isolation), so
// SOMETHING in the user's session has to own the tray icon and answer ngd's
// prompts. That doesn't have to be a second executable. Two processes for one
// frontend meant two icon-state pollers, two panic paths that drifted apart, and
// a tray whose "Status" could only shell out to a cmd.exe window because it had no
// UI of its own to render into. One frontend process owns the icon and the window;
// it talks to the service over the command pipe (core/cmd.h).
//
// The message-only window is created on the CALLING thread - the WinUI UI thread,
// which already pumps messages - so menu clicks arrive there and can touch XAML
// directly with no marshalling. The prompt pipe keeps its own thread, exactly as
// it did in ngtray: it blocks on a client, and a blocked UI thread is a dead app.
#pragma once

#include <windows.h>

#include <functional>
#include <string>

namespace ngtray {

struct Callbacks {
    std::function<void()> openDashboard;   // double-click, or menu > Dashboard
    std::function<void()> showStatus;      // menu > Status (renders in-app, not a console)
    std::function<void()> panic;           // menu > Panic
    std::function<void()> quit;            // menu > Quit (really exit, not hide)
    // Ask the user about a blocked outbound connection. Returns 'A' always-allow,
    // 'O' allow-once, 'B' block. Called on the pipe thread.
    std::function<char(const std::wstring& app, const std::wstring& dest,
                       const std::wstring& port)> prompt;
};

bool Start(HINSTANCE inst, const Callbacks& cb);
void Stop();

// Swap the icon to match live mode ("learning" | "enforcing" | anything else =
// idle/offline). Cheap to call often: only touches the shell on a real change.
void SetMode(const std::string& mode);

// Freeze SetMode while a stop is in flight, so the icon can't flap back to green
// while the daemon is still legitimately unwinding.
void HoldMode(bool hold);

void Balloon(const std::wstring& title, const std::wstring& text);

}  // namespace ngtray
