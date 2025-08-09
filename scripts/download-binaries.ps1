# LEGION2 Binary Downloader
# Automatically downloads and extracts nmap and masscan binaries

param(
    [string]$BinDir = (Join-Path $PSScriptRoot ".." "src-tauri" "bin")
)

Write-Host "LEGION2 Automatic Binary Download" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Ensure bin directory exists
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Write-Host "Created bin directory: $BinDir" -ForegroundColor Yellow
}

# Check if binaries already exist
$nmapPath = Join-Path $BinDir "nmap.exe"
$masscanPath = Join-Path $BinDir "masscan.exe"

$nmapExists = Test-Path $nmapPath
$masscanExists = Test-Path $masscanPath

if ($nmapExists -and $masscanExists) {
    Write-Host "✅ Both binaries already exist, skipping download" -ForegroundColor Green
    Write-Host "   nmap.exe: $nmapPath"
    Write-Host "   masscan.exe: $masscanPath"
    exit 0
}

# Create temp directory
$tempDir = Join-Path $env:TEMP "legion2-binaries"
if (Test-Path $tempDir) {
    Remove-Item $tempDir -Recurse -Force
}
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # Download Nmap if needed
    if (-not $nmapExists) {
        Write-Host "📥 Downloading nmap..." -ForegroundColor Blue
        
        # Try multiple nmap download sources
        $nmapUrls = @(
            "https://nmap.org/dist/nmap-7.97-win32.zip",
            "https://nmap.org/dist/nmap-7.95-win32.zip",
            "https://nmap.org/dist/nmap-7.94-win32.zip"
        )
        
        $nmapDownloaded = $false
        foreach ($url in $nmapUrls) {
            try {
                $nmapZip = Join-Path $tempDir "nmap.zip"
                Write-Host "   Trying: $url"
                
                # Download with progress
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($url, $nmapZip)
                
                # Extract
                Write-Host "   Extracting nmap..."
                Expand-Archive -Path $nmapZip -DestinationPath $tempDir -Force
                
                # Find nmap.exe in extracted files
                $nmapExe = Get-ChildItem -Path $tempDir -Name "nmap.exe" -Recurse | Select-Object -First 1
                if ($nmapExe) {
                    $sourcePath = Join-Path $tempDir $nmapExe.DirectoryName $nmapExe.Name
                    Copy-Item $sourcePath $nmapPath -Force
                    Write-Host "✅ nmap.exe installed successfully" -ForegroundColor Green
                    $nmapDownloaded = $true
                    break
                }
            }
            catch {
                Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }
        }
        
        if (-not $nmapDownloaded) {
            Write-Host "❌ Could not download nmap from any source" -ForegroundColor Red
        }
    }
    
    # Download/compile Masscan if needed
    if (-not $masscanExists) {
        Write-Host "📥 Downloading masscan source..." -ForegroundColor Blue
        
        $masscanUrl = "https://github.com/robertdavidgraham/masscan/archive/refs/heads/master.zip"
        $masscanZip = Join-Path $tempDir "masscan.zip"
        
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($masscanUrl, $masscanZip)
            
            # Extract
            Write-Host "   Extracting masscan source..."
            Expand-Archive -Path $masscanZip -DestinationPath $tempDir -Force
            
            # Try to find pre-built Windows binary or build instructions
            Write-Host "⚠️  Masscan requires compilation on Windows" -ForegroundColor Yellow
            Write-Host "   For now, creating placeholder and instructions..." -ForegroundColor Yellow
            
            # Create a batch file that explains how to get masscan
            $masscanBat = @"
@echo off
echo Masscan is not available - please install manually:
echo 1. Download from: https://github.com/robertdavidgraham/masscan/releases
echo 2. Or install via Chocolatey: choco install masscan
echo 3. Or compile from source using MinGW or Visual Studio
echo 4. Place masscan.exe in this directory
pause
"@
            $masscanBat | Out-File -FilePath $masscanPath.Replace('.exe', '.bat') -Encoding ASCII
            
            # Try to download from GitHub releases if available
            try {
                $releaseUrl = "https://api.github.com/repos/robertdavidgraham/masscan/releases/latest"
                $releaseInfo = Invoke-RestMethod -Uri $releaseUrl
                
                foreach ($asset in $releaseInfo.assets) {
                    if ($asset.name -like "*win*" -or $asset.name -like "*windows*" -or $asset.name -like "*.exe") {
                        Write-Host "   Found potential Windows binary: $($asset.name)"
                        try {
                            $webClient.DownloadFile($asset.browser_download_url, $masscanPath)
                            Write-Host "✅ masscan.exe downloaded from release" -ForegroundColor Green
                            break
                        }
                        catch {
                            Write-Host "   Failed to download: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            }
            catch {
                Write-Host "   No pre-built Windows binary found in releases" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "❌ Could not download masscan: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host "`n📊 Final Status:" -ForegroundColor Cyan
    if (Test-Path $nmapPath) {
        Write-Host "✅ nmap.exe: Ready" -ForegroundColor Green
    } else {
        Write-Host "❌ nmap.exe: Missing" -ForegroundColor Red
        Write-Host "   Download manually from: https://nmap.org/download.html" -ForegroundColor Yellow
    }
    
    if (Test-Path $masscanPath) {
        Write-Host "✅ masscan.exe: Ready" -ForegroundColor Green
    } else {
        Write-Host "⚠️  masscan.exe: Missing (see masscan.bat for instructions)" -ForegroundColor Yellow
    }
    
    Write-Host "`n💡 LEGION2 will use system-installed tools as fallback if local binaries are missing" -ForegroundColor Cyan

}
finally {
    # Clean up
    if (Test-Path $tempDir) {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n✅ Binary setup completed!" -ForegroundColor Green