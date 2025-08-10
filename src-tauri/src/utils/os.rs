// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.

// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security

//     This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
//     License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
//     version.

//     This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
//     warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//     details.

//     You should have received a copy of the GNU General Public License along with this program.
//     If not, see <http://www.gnu.org/licenses/>.

use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

impl OperatingSystem {
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
    let local_path = get_local_masscan_path();
    if local_path.exists() {
        local_path
    } else {
        PathBuf::from(get_masscan_binary_name())
    }
}

/// Get the full path to nmap binary (checks local /bin first, then system PATH)
pub fn get_nmap_binary_path() -> PathBuf {
    let local_path = get_local_nmap_path();
    if local_path.exists() {
        local_path
    } else {
        PathBuf::from(get_nmap_binary_name())
    }
}

/// Get the local path for masscan binary in /bin directory
pub fn get_local_masscan_path() -> PathBuf {
    let mut path = get_bin_directory();
    if cfg!(target_os = "windows") {
        path.push("masscan.exe");
    } else {
        path.push("masscan");
    }
    path
}

/// Get the local path for nmap binary in /bin directory
pub fn get_local_nmap_path() -> PathBuf {
    let mut path = get_bin_directory();
    if cfg!(target_os = "windows") {
        path.push("nmap.exe");
    } else {
        path.push("nmap");
    }
    path
}

/// Get the bin directory relative to the executable
pub fn get_bin_directory() -> PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    path.pop(); // Remove executable name
    path.push("bin");
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

/// Legacy function for backward compatibility
pub fn get_masscan_binary() -> &'static str {
    get_masscan_binary_name()
}

/// Legacy function for backward compatibility
pub fn get_nmap_binary() -> &'static str {
    get_nmap_binary_name()
}

/// Check if a command/binary is available on the system or locally
pub async fn is_command_available(command_path: &Path) -> bool {
    let version_arg = match get_os() {
        OperatingSystem::Windows => "--version", // Most Windows binaries support --version
        _ => "--version",
    };

    tokio::process::Command::new(command_path)
        .arg(version_arg)
        .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Check if a command/binary is available by name (legacy function)
pub async fn is_command_available_by_name(command: &str) -> bool {
    is_command_available(Path::new(command)).await
}

/// Get system information
pub fn get_system_info() -> SystemInfo {
    SystemInfo {
        os: get_os(),
        arch: get_arch(),
        masscan_binary: get_masscan_binary().to_string(),
        nmap_binary: get_nmap_binary().to_string(),
    }
}

/// Get the current architecture
pub fn get_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else {
        "unknown"
    }
}

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub os: OperatingSystem,
    pub arch: &'static str,
    pub masscan_binary: String,
    pub nmap_binary: String,
}

/// Run masscan with OS-appropriate binary (checks local /bin first)
pub async fn run_masscan(ip_range: &str, ports: &str, rate: Option<u32>) -> Result<String> {
    let masscan_path = get_masscan_binary_path();
    let rate_str = rate.unwrap_or(1000).to_string();

    let output = tokio::process::Command::new(&masscan_path)
        .args(&["-p", ports, ip_range, "--rate", &rate_str])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to execute {:?}: {}", masscan_path, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Masscan failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
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

/// Get status of local and system binaries
pub async fn get_binary_status() -> BinaryStatus {
    let local_masscan = get_local_masscan_path();
    let local_nmap = get_local_nmap_path();
    
    BinaryStatus {
        local_masscan_exists: local_masscan.exists(),
        local_masscan_path: local_masscan.to_string_lossy().to_string(),
        local_masscan_available: if local_masscan.exists() {
            is_command_available(&local_masscan).await
        } else {
            false
        },
        local_nmap_exists: local_nmap.exists(),
        local_nmap_path: local_nmap.to_string_lossy().to_string(),
        local_nmap_available: if local_nmap.exists() {
            is_command_available(&local_nmap).await
        } else {
            false
        },
        system_masscan_available: is_command_available_by_name(get_masscan_binary_name()).await,
        system_nmap_available: is_command_available_by_name(get_nmap_binary_name()).await,
        bin_directory: get_bin_directory().to_string_lossy().to_string(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BinaryStatus {
    pub local_masscan_exists: bool,
    pub local_masscan_path: String,
    pub local_masscan_available: bool,
    pub local_nmap_exists: bool,
    pub local_nmap_path: String,
    pub local_nmap_available: bool,
    pub system_masscan_available: bool,
    pub system_nmap_available: bool,
    pub bin_directory: String,
}