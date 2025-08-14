# Stop on first error
$ErrorActionPreference = "Stop"

Write-Host "=== LEGION2 Build Script (PowerShell) ===" -ForegroundColor Cyan

# Check Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "Node.js is not installed. Install from https://nodejs.org/" -ForegroundColor Red
    exit 1
}

# Check Rust
if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
    Write-Host "Rust is not installed. Install from https://rust-lang.org/tools/install" -ForegroundColor Red
    exit 1
}

# Check Tauri CLI
if (-not (npm list -g @tauri-apps/cli --depth=0 2>$null)) {
    Write-Host "Installing Tauri CLI globally..."
    npm install -g @tauri-apps/cli
}

# Install dependencies
Write-Host "Installing npm dependencies..." -ForegroundColor Yellow
npm install

# Build the Tauri app
Write-Host "Building LEGION2..." -ForegroundColor Yellow
npm run tauri build

Write-Host "Build complete!" -ForegroundColor Green