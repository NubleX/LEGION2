// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use super::os::*;

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
    let masscan_bin = get_masscan_binary();
    let nmap_bin = get_nmap_binary();
    
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
    let available = is_command_available_by_name("cmd").await;
    
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let available = is_command_available_by_name("ls").await;
    
    println!("Command availability test result: {}", available);
    
    // Test with a command that should not be available
    let unavailable = is_command_available_by_name("nonexistent_command_12345").await;
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

#[tokio::test]
async fn test_binary_status() {
    let status = get_binary_status().await;
    
    println!("Binary status: {:#?}", status);
    
    // Basic validation
    assert!(!status.bin_directory.is_empty());
    assert!(!status.local_masscan_path.is_empty());
    assert!(!status.local_nmap_path.is_empty());
    
    // Paths should end with correct binary names
    #[cfg(target_os = "windows")]
    {
        assert!(status.local_masscan_path.ends_with("masscan.exe"));
        assert!(status.local_nmap_path.ends_with("nmap.exe"));
    }
    
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        assert!(status.local_masscan_path.ends_with("masscan"));
        assert!(status.local_nmap_path.ends_with("nmap"));
    }
}