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
    let local_path = get_local_masscan_path();
    log::debug!("Checking local masscan path: {:?}", local_path);
    log::debug!("Local masscan path exists: {}", local_path.exists());
    
    if local_path.exists() {
        log::info!("Using local masscan binary: {:?}", local_path);
        local_path
    } else {
        let system_path = PathBuf::from(get_masscan_binary_name());
        log::info!("Local masscan not found, falling back to system PATH: {:?}", system_path);
        system_path
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
        path.push("engines");
        path.push("windows");
        path.push("masscan-1.3.2");
        path.push("masscan.exe");
    } else {
        path.push("engines");
        path.push("linux");
        path.push("masscan");
    }
    path
}

/// Get the local path for nmap binary in /bin directory
pub fn get_local_nmap_path() -> PathBuf {
    let mut path = get_bin_directory();
    if cfg!(target_os = "windows") {
        path.push("engines");
        path.push("windows");
        path.push("nmap-7.97");
        path.push("nmap.exe");
    } else {
        path.push("engines");
        path.push("linux");
        path.push("nmap");
    }
    path
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
        while path.file_name().and_then(|name| name.to_str()) != Some("src-tauri") && path.parent().is_some() {
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
                    stdout.contains("usage:") || stderr.contains("usage:") || 
                    stdout.contains("Usage:") || stderr.contains("Usage:")
                }
                Err(_) => false,
            }
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_os_detection() {
        let os = get_os();
        println!("Detected OS: {:?}", os);
        
        // On Windows, should detect Windows
        #[cfg(target_os = "windows")]
        assert_eq!(os, OperatingSystem::Windows);
        
        // On Linux, should detect Linux
        #[cfg(target_os = "linux")]
        assert_eq!(os, OperatingSystem::Linux);
        
        // On macOS, should detect macOS
        #[cfg(target_os = "macos")]
        assert_eq!(os, OperatingSystem::MacOS);
    }

    #[tokio::test]
    async fn test_binary_names() {
        let masscan_bin = get_masscan_binary_name();
        let nmap_bin = get_nmap_binary_name();
        
        println!("Masscan binary: {}", masscan_bin);
        println!("Nmap binary: {}", nmap_bin);
        
        #[cfg(target_os = "windows")]
        {
            assert_eq!(masscan_bin, "masscan.exe");
            assert_eq!(nmap_bin, "nmap.exe");
        }
        
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert_eq!(masscan_bin, "masscan");
            assert_eq!(nmap_bin, "nmap");
        }
    }

    #[tokio::test]
    async fn test_command_availability() {
        // Test with a command that should always be available
        #[cfg(target_os = "windows")]
        let available = is_command_available(std::path::Path::new("cmd")).await;
        
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let available = is_command_available(std::path::Path::new("ls")).await;
        
        println!("Command availability test result: {}", available);
        
        // Test with a command that should not be available
        let unavailable = is_command_available(std::path::Path::new("nonexistent_command_12345")).await;
        assert!(!unavailable);
    }

    #[tokio::test]
    async fn test_scanner_availability() {
        let masscan_available = is_masscan_available().await;
        let nmap_available = is_nmap_available().await;
        
        println!("Masscan available: {}", masscan_available);
        println!("Nmap available: {}", nmap_available);
        
        // These tests will depend on what's installed on the system
        // So we just print the results rather than asserting
    }

    #[tokio::test]
    async fn test_local_binary_paths() {
        let bin_dir = get_bin_directory();
        let local_masscan = get_local_masscan_path();
        let local_nmap = get_local_nmap_path();
        
        println!("Bin directory: {:?}", bin_dir);
        println!("Local masscan path: {:?}", local_masscan);
        println!("Local nmap path: {:?}", local_nmap);
        
        // Check if paths are constructed correctly
        assert!(bin_dir.to_string_lossy().ends_with("bin"));
        
        #[cfg(target_os = "windows")]
        {
            assert!(local_masscan.to_string_lossy().ends_with("masscan.exe"));
            assert!(local_nmap.to_string_lossy().ends_with("nmap.exe"));
        }
        
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert!(local_masscan.to_string_lossy().ends_with("masscan"));
            assert!(local_nmap.to_string_lossy().ends_with("nmap"));
        }
    }

    #[tokio::test]
    async fn test_binary_path_resolution() {
        let masscan_path = get_masscan_binary_path();
        let nmap_path = get_nmap_binary_path();
        
        println!("Resolved masscan path: {:?}", masscan_path);
        println!("Resolved nmap path: {:?}", nmap_path);
        
        // Should return either local path or binary name
        assert!(!masscan_path.as_os_str().is_empty());
        assert!(!nmap_path.as_os_str().is_empty());
    }
}

