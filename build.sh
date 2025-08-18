#!/bin/bash

# build.sh
# Build LEGION2 for all platforms

echo "Building LEGION2 for all platforms..."

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf src-tauri/target/release/bundle
rm -rf dist

# Install dependencies if needed
echo "Checking dependencies..."
npm install

# Build frontend
echo "Building frontend..."
npm run build

# Function to build for each platform
build_platform() {
    local platform=$1
    echo "Building for $platform..."
    
    case $platform in
        "windows")
            # For Windows (if on Windows or using cross-compilation)
            npm run tauri build -- --target x86_64-pc-windows-msvc
            ;;
        "macos")
            # For macOS (only works on macOS)
            npm run tauri build -- --target universal-apple-darwin
            ;;
        "linux")
            # For Linux
            npm run tauri build -- --target x86_64-unknown-linux-gnu
            ;;
    esac
}

# Detect current platform and build
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    build_platform "linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    build_platform "macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
    build_platform "windows"
else
    echo "Unknown platform: $OSTYPE"
    exit 1
fi

echo "Build complete! Check src-tauri/target/release/bundle/"

# --- Linux-specific: Create launcher with sudo ---
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    cat > legion2-admin.sh << 'EOF'
#!/bin/bash
# LEGION2 Admin Launcher for Linux
pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY /opt/legion2/legion2
EOF
    chmod +x legion2-admin.sh
    echo "Created legion2-admin.sh for running with elevated privileges"
fi

# --- macOS-specific: Create launcher with sudo ---
if [[ "$OSTYPE" == "darwin"* ]]; then
    cat > legion2-admin.command << 'EOF'
#!/bin/bash
# LEGION2 Admin Launcher for macOS
osascript -e 'do shell script "/Applications/LEGION2.app/Contents/MacOS/legion2" with administrator privileges'
EOF
    chmod +x legion2-admin.command
    echo "Created legion2-admin.command for running with elevated privileges"
fi

# --- Windows-specific: Create admin launcher ---
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
    cat > legion2-admin.ps1 << 'EOF'
# LEGION2 Admin Launcher for Windows
Start-Process -FilePath ".\legion2.exe" -Verb RunAs
EOF
    echo "Created legion2-admin.ps1 for running with elevated privileges"
fi