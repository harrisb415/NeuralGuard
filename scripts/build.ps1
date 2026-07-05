# Configure + build NeuralGuard on the host (Visual Studio 2026 toolchain).
# Usage:  pwsh scripts\build.ps1 [-Clean]
param([switch]$Clean)
$ErrorActionPreference = "Stop"

$root  = Split-Path $PSScriptRoot -Parent
$build = Join-Path $root "build"
$cmake = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if (-not (Test-Path $cmake)) { $cmake = "cmake" }  # fall back to PATH

if ($Clean -and (Test-Path $build)) { Remove-Item -Recurse -Force $build }

& $cmake -S $root -B $build -G "Visual Studio 18 2026" -A x64
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed ($LASTEXITCODE)" }

& $cmake --build $build --config Release
if ($LASTEXITCODE -ne 0) { throw "cmake build failed ($LASTEXITCODE)" }

$exe = Join-Path $build "Release\ngmon.exe"
Write-Host "`nBuilt: $exe" -ForegroundColor Green
