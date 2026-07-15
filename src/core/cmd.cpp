#include "core/cmd.h"

#include <windows.h>

namespace ng {

std::string CmdSend(const std::string& request, bool* ok) {
    if (ok) *ok = false;

    // One retry: the server closes and re-creates its pipe instance between
    // clients, so a request landing in that gap gets ERROR_PIPE_BUSY rather than
    // a real "not running".
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 2; ++attempt) {
        h = CreateFileW(kCmdPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY) return "";
        if (!WaitNamedPipeW(kCmdPipe, 2000)) return "";
    }
    if (h == INVALID_HANDLE_VALUE) return "";

    // The server is message-mode; without this the reply could arrive in pieces.
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);

    DWORD n = 0;
    if (!WriteFile(h, request.data(), (DWORD)request.size(), &n, nullptr)) {
        CloseHandle(h);
        return "";
    }

    char buf[4096] = {};
    std::string reply;
    if (ReadFile(h, buf, sizeof(buf) - 1, &n, nullptr) && n > 0) {
        reply.assign(buf, n);
        if (ok) *ok = true;
    }
    CloseHandle(h);
    return reply;
}

}  // namespace ng
