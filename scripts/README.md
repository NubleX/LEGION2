# LEGION2 Build Scripts

This directory contains build-time scripts used to prepare LEGION2 for distribution.

## download-binaries.js

Automatically downloads and prepares nmap and masscan binaries for bundling with LEGION2.

### Usage

```bash
# Manually run the script
node scripts/download-binaries.js

# Or use npm script
npm run download-binaries
```

### What it does

1. **Detects the current platform** (Windows, Linux, macOS)
2. **Downloads appropriate binaries**:
   - **Windows**: Downloads pre-built `.exe` files
   - **Linux/macOS**: Downloads source code and compiles locally
3. **Verifies binary integrity** and sets appropriate permissions
4. **Places binaries** in `src-tauri/bin/` directory for bundling

### Platform-specific behavior

#### Windows
- Downloads `nmap.exe` from official nmap.org releases
- Downloads `masscan.exe` from GitHub releases
- No compilation required

#### Linux/macOS
- Downloads source code for both tools
- Compiles binaries locally using system compiler
- Requires build tools (gcc, make, etc.)

### Build dependencies

#### All platforms
- Node.js (for running the script)

#### Linux/macOS (for compilation)
- GCC or compatible C compiler
- GNU Make
- Standard development tools (`build-essential` on Ubuntu/Debian)

### Error handling

The script is designed to be resilient:
- If downloads fail, the build continues (users can provide their own binaries)
- If compilation fails, falls back to system-installed versions
- Detailed error messages help diagnose issues

### Manual binary placement

If the automatic download fails, you can manually place binaries:

```
src-tauri/
└── bin/
    ├── nmap.exe (Windows) or nmap (Linux/macOS)
    └── masscan.exe (Windows) or masscan (Linux/macOS)
```

### Licensing

This script downloads open source software:
- **nmap**: GPL-2.0 License
- **masscan**: AGPL-3.0 License

See `THIRD_PARTY_LICENSES.md` for full licensing information.