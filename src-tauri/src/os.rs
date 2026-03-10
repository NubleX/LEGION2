// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

impl OperatingSystem {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatingSystem::Windows => "windows",
            OperatingSystem::Linux => "linux",
            OperatingSystem::MacOS => "macos",
            OperatingSystem::Unknown => "unknown",
        }
    }
}

/// Detect the current operating system at compile time
pub fn get_os() -> OperatingSystem {
    if cfg!(target_os = "windows") {
        OperatingSystem::Windows
    } else if cfg!(target_os = "linux") {
        OperatingSystem::Linux
    } else if cfg!(target_os = "macos") {
        OperatingSystem::MacOS
    } else {
        OperatingSystem::Unknown
    }
}

/// Get the full path to masscan binary (checks local /bin first, then system PATH)
pub fn get_masscan_binary_path() -> PathBuf {
    let mut path = get_bin_directory();

    // Use Tauri's expected naming convention
    #[cfg(target_os = "windows")]
    {
        path.push("engines");
        path.push("windows");
        path.push("masscan-1.3.2");
        path.push("masscan-x86_64-pc-windows-msvc.exe");
    }

    #[cfg(target_os = "linux")]
    {
        path.push("engines");
        path.push("linux");
        path.push("masscan-x86_64-unknown-linux-gnu");
    }

    #[cfg(target_os = "macos")]
    {
        path.push("engines");
        path.push("macos");
        path.push("masscan-aarch64-apple-darwin");
    }

    if !path.exists() {
        log::warn!(
            "Local masscan binary not found at {:?}, trying system PATH",
            path
        );
        PathBuf::from("masscan")
    } else {
        log::info!("Using local masscan binary: {:?}", path);
        path
    }
}

/// Get the full path to nmap binary (checks local /bin first, then system PATH)
pub fn get_nmap_binary_path() -> PathBuf {
    let mut path = get_bin_directory();

    #[cfg(target_os = "windows")]
    {
        path.push("engines");
        path.push("windows");
        path.push("nmap-7.97");
        path.push("nmap-x86_64-pc-windows-msvc.exe");
    }

    #[cfg(target_os = "linux")]
    {
        path.push("engines");
        path.push("linux");
        path.push("nmap-x86_64-unknown-linux-gnu");
    }

    #[cfg(target_os = "macos")]
    {
        path.push("engines");
        path.push("macos");
        path.push("nmap-aarch64-apple-darwin");
    }

    if !path.exists() {
        log::warn!(
            "Local nmap binary not found at {:?}, trying system PATH",
            path
        );
        PathBuf::from("nmap")
    } else {
        log::info!("Using local nmap binary: {:?}", path);
        path
    }
}

/// Get the bin directory relative to the executable
pub fn get_bin_directory() -> PathBuf {
    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    log::debug!("Current executable path: {:?}", exe_path);

    let mut path = exe_path.clone();
    path.pop(); // Remove executable name

    // In development mode, the exe is at src-tauri/target/debug/legion2.exe
    // but the bin directory is at src-tauri/bin/
    // In production, the exe and bin should be in the same directory

    // Check if we're in development mode (target/debug or target/release)
    if path.to_string_lossy().contains("target") {
        // Navigate up to src-tauri directory
        while path.file_name().and_then(|name| name.to_str()) != Some("src-tauri")
            && path.parent().is_some()
        {
            path.pop();
        }
        path.push("bin");
        log::debug!("Development mode - bin directory resolved to: {:?}", path);
    } else {
        // Production mode - bin directory is relative to executable
        path.push("bin");
        log::debug!("Production mode - bin directory resolved to: {:?}", path);
    }

    path
}

/// Get the appropriate binary name for masscan based on OS (without path)
pub fn get_masscan_binary_name() -> &'static str {
    match get_os() {
        OperatingSystem::Windows => "masscan.exe",
        OperatingSystem::Linux => "masscan",
        OperatingSystem::MacOS => "masscan",
        OperatingSystem::Unknown => "masscan",
    }
}

/// Get the appropriate binary name for nmap based on OS (without path)
pub fn get_nmap_binary_name() -> &'static str {
    match get_os() {
        OperatingSystem::Windows => "nmap.exe",
        OperatingSystem::Linux => "nmap",
        OperatingSystem::MacOS => "nmap",
        OperatingSystem::Unknown => "nmap",
    }
}

/// Check if a command/binary is available on the system or locally
pub async fn is_command_available(command_path: &Path) -> bool {
    // First check if the file exists (for absolute paths)
    if command_path.is_absolute() && !command_path.exists() {
        return false;
    }
    
    // Try --version first (masscan returns non-zero but still prints version)
    let result_version = tokio::process::Command::new(command_path)
        .arg("--version")
        .output()
        .await;

    match result_version {
        Ok(output) if output.status.success() => return true,
        Ok(output) => {
            // Masscan returns non-zero exit code but still prints version info
            // Check if we got any output that looks like version info
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stdout.contains("version") || stdout.contains("Version") || 
               stderr.contains("version") || stderr.contains("Version") ||
               stdout.contains("masscan") || stderr.contains("masscan") {
                return true;
            }
            
            // Try --help as fallback
            let result_help = tokio::process::Command::new(command_path)
                .arg("--help")
                .output()
                .await;

            match result_help {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    // Check if help output contains any useful information
                    // Masscan help doesn't contain "usage:" but contains "MASSCAN" or "masscan"
                    stdout.contains("masscan")
                        || stderr.contains("masscan")
                        || stdout.contains("MASSCAN")
                        || stderr.contains("MASSCAN")
                        || stdout.contains("usage:")
                        || stderr.contains("usage:")
                        || stdout.contains("Usage:")
                        || stderr.contains("Usage:")
                }
                Err(_) => false,
            }
        }
        Err(_) => {
            // If command couldn't be spawned, try to find it in PATH
            // For relative paths like "masscan", try which/whereis
            if !command_path.is_absolute() {
                let which_result = tokio::process::Command::new("which")
                    .arg(command_path.to_string_lossy().as_ref())
                    .output()
                    .await;
                
                if let Ok(output) = which_result {
                    return output.status.success();
                }
            }
            false
        }
    }
}
/// Check if masscan is available (checks local /bin first, then system PATH)
pub async fn is_masscan_available() -> bool {
    let masscan_path = get_masscan_binary_path();
    is_command_available(&masscan_path).await
}

/// Check if nmap is available (checks local /bin first, then system PATH)
pub async fn is_nmap_available() -> bool {
    let nmap_path = get_nmap_binary_path();
    is_command_available(&nmap_path).await
}

/// Resolve a binary to its absolute path, required by setcap/getcap.
/// If the local bundled binary is not found, falls back to resolving via `which`.
#[cfg(target_os = "linux")]
async fn resolve_absolute_path(path: PathBuf) -> Option<PathBuf> {
    if path.is_absolute() && path.exists() {
        return Some(path);
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    if name.is_empty() {
        return None;
    }
    let output = tokio::process::Command::new("which")
        .arg(name)
        .output()
        .await
        .ok()?;
    let resolved = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if resolved.is_empty() { None } else { Some(PathBuf::from(resolved)) }
}

/// Check whether a binary has the required Linux capabilities for raw socket scanning.
/// Returns Ok(true) if caps are set, Ok(false) if missing, Err if getcap not available.
#[cfg(target_os = "linux")]
pub async fn binary_has_raw_caps(bin: &std::path::Path) -> Result<bool, String> {
    let output = tokio::process::Command::new("getcap")
        .arg(bin)
        .output()
        .await
        .map_err(|e| format!("getcap not found: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains("cap_net_raw") || stdout.contains("cap_net_admin"))
}

/// Set raw-socket capabilities on masscan and nmap using pkexec (prompts for password graphically).
/// Automatically resolves absolute paths — setcap requires absolute paths and fails silently on relative ones.
#[cfg(target_os = "linux")]
pub async fn set_scanner_capabilities() -> Result<String, String> {
    let masscan = resolve_absolute_path(get_masscan_binary_path())
        .await
        .ok_or_else(|| "masscan not found in PATH or local bundle".to_string())?;
    let nmap = resolve_absolute_path(get_nmap_binary_path())
        .await
        .ok_or_else(|| "nmap not found in PATH or local bundle".to_string())?;

    log::info!("Setting capabilities: masscan={:?} nmap={:?}", masscan, nmap);

    let script = format!(
        "setcap cap_net_raw,cap_net_admin=eip '{}' && setcap cap_net_raw+ep '{}'",
        masscan.display(),
        nmap.display()
    );

    let output = tokio::process::Command::new("pkexec")
        .args(["sh", "-c", &script])
        .output()
        .await
        .map_err(|e| format!("Failed to run pkexec: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(format!("Capabilities set successfully.\n{}{}", stdout, stderr))
    } else {
        Err(format!("setcap failed (exit {}): {}{}", output.status, stdout, stderr))
    }
}

/// Check the capability status of masscan and nmap, returning a human-readable status string.
#[cfg(target_os = "linux")]
pub async fn check_scanner_capabilities() -> (bool, bool, String) {
    let masscan_path = resolve_absolute_path(get_masscan_binary_path())
        .await
        .unwrap_or_else(|| PathBuf::from("masscan"));
    let nmap_path = resolve_absolute_path(get_nmap_binary_path())
        .await
        .unwrap_or_else(|| PathBuf::from("nmap"));

    let masscan_ok = binary_has_raw_caps(&masscan_path).await.unwrap_or(false);
    let nmap_ok = binary_has_raw_caps(&nmap_path).await.unwrap_or(false);

    let status = format!(
        "masscan ({}): {}\nnmap ({}): {}",
        masscan_path.display(),
        if masscan_ok { "cap_net_raw OK" } else { "MISSING caps" },
        nmap_path.display(),
        if nmap_ok { "cap_net_raw OK" } else { "MISSING caps" },
    );
    (masscan_ok, nmap_ok, status)
}
