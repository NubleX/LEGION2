# Binary Setup for LEGION2

## Required Binaries

LEGION2 requires nmap and masscan binaries to function properly. Place them in this directory:

- `nmap.exe`
- `masscan.exe`

## Download Sources

### Nmap
- Website: https://nmap.org
- Windows: Download from https://nmap.org/download.html
- Linux/macOS: Install via package manager or compile from source

### Masscan
- Repository: https://github.com/robertdavidgraham/masscan
- Windows: Download release or compile with MinGW/Visual Studio
- Linux/macOS: Install via package manager or compile from source

## Verification

After placing binaries, you can verify they work by running:
- `.\nmap.exe --version`
- `.\masscan.exe --version`

## Licensing

Both nmap (GPL-2.0) and masscan (AGPL-3.0) are open source.
See THIRD_PARTY_LICENSES.md in the project root for details.
