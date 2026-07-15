#include "core/prompt.h"

#include <windows.h>

namespace ng {

namespace {
// Open the tray's pipe, send one message, read the 1-byte reply. 0 = unreachable.
char SendToTray(const std::string& msg) {
    const wchar_t* kPipe = L"\\\\.\\pipe\\neuralguard";
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 10; ++i) {
        pipe = CreateFileW(kPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY) return 0;  // tray not running
        WaitNamedPipeW(kPipe, 2000);
    }
    if (pipe == INVALID_HANDLE_VALUE) return 0;

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    DWORD wr = 0;
    WriteFile(pipe, msg.c_str(), (DWORD)msg.size(), &wr, nullptr);

    char reply = 0;
    DWORD rd = 0;
    ReadFile(pipe, &reply, 1, &rd, nullptr);
    CloseHandle(pipe);
    return (rd == 1) ? reply : 0;
}
}  // namespace

char PromptTray(const std::string& app, const std::string& dest, int port) {
    return SendToTray(app + "\t" + dest + "\t" + std::to_string(port));
}

bool NotifyTray(const std::string& label, int localPort) {
    // "NOTIFY\t..." marks a balloon-only message; the tray answers immediately
    // without showing a dialog (see ngtray's PromptUser).
    return SendToTray("NOTIFY\t" + label + "\t" + std::to_string(localPort)) != 0;
}

}  // namespace ng
