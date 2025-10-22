// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use std::env;
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
    // Try --version first, then --help as fallback
    let result_version = tokio::process::Command::new(command_path)
        .arg("--version")
        .output()
        .await;

    match result_version {
        Ok(output) if output.status.success() => return true,
        Ok(_) => {
            // Try --help as fallback (some tools like masscan exit with non-zero on --version)
            let result_help = tokio::process::Command::new(command_path)
                .arg("--help")
                .output()
                .await;

            match result_help {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    // Check if help output contains usage information
                    stdout.contains("usage:")
                        || stderr.contains("usage:")
                        || stdout.contains("Usage:")
                        || stderr.contains("Usage:")
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
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
