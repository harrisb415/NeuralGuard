// The NeuralGuard config dashboard - a WebView2 window hosted by the tray.
#pragma once

#include <windows.h>

namespace ng {

// Open (or focus) the dashboard window. Must be called on the UI thread.
void OpenDashboard(HINSTANCE hInst);

}  // namespace ng
