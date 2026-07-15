// The service's command channel: how a frontend tells the running engine what to
// do, instead of spawning a competing copy of it.
//
// ngd (the LocalSystem service) is the SERVER here. This is deliberately NOT the
// existing \\.\pipe\neuralguard, whose server is the TRAY - ngd connects to that
// one to ask the user about a blocked connection. The two run in opposite
// directions, and a pipe has exactly one server, so they need separate names.
//
// Why this exists: the dashboard used to launch `ngd enforce` as a whole new
// process to change modes, which knew nothing about the installed service and
// fought it for the same WFP provider. The service is already running and already
// elevated, so the right move is to ask it.
//
// Security: the pipe takes the default DACL for a LocalSystem-created pipe, which
// grants write access to SYSTEM and Administrators only. So commands require
// elevation by construction - no check of our own to get wrong. The tray runs
// elevated (requireAdministrator) and the dashboard inherits its token, so the
// frontend can command the service without a single UAC prompt of its own.
#pragma once

#include <string>

namespace ng {

inline const wchar_t* kCmdPipe = L"\\\\.\\pipe\\neuralguard-cmd";

// Requests (message-mode, one per connection):
//   "STATUS"            -> "OK mode=<m> desired=<d>"
//   "MODE <enforcing|learning|idle>"
//                       -> "OK ..."  (persists desired_mode AND switches live)
//   "PANIC"             -> "OK ..."  (drop filters, go idle, and stay idle)
// Replies start with "OK " or "ERR ".
//
// Sends one request and returns the reply. Sets *ok=false when the service can't
// be reached at all - not installed, not running, or the caller isn't elevated -
// which is different from reaching it and getting back an "ERR ...".
std::string CmdSend(const std::string& request, bool* ok = nullptr);

}  // namespace ng
