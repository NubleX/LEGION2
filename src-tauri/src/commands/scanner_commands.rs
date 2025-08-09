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

use crate::utils::os::{run_masscan, run_nmap, get_binary_status, BinaryStatus, get_bin_directory};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct ScanRequest {
    pub ip_range: String,
    pub ports: String,
    pub rate: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct NmapScanRequest {
    pub target: String,
    pub args: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ScanResult {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

/// Scan with masscan (checks local /bin first, then system PATH)
#[tauri::command]
pub async fn scan_with_masscan(
    ip_range: String,
    ports: String,
    rate: Option<u32>,
) -> Result<String, String> {
    log::info!("Starting masscan scan for range: {} ports: {}", ip_range, ports);
    
    match run_masscan(&ip_range, &ports, rate).await {
        Ok(output) => {
            log::info!("Masscan scan completed successfully");
            Ok(output)
        }
        Err(e) => {
            let error_msg = format!("Masscan scan failed: {}", e);
            log::error!("{}", error_msg);
            Err(error_msg)
        }
    }
}

/// Scan with nmap (checks local /bin first, then system PATH)
#[tauri::command]
pub async fn scan_with_nmap(
    target: String,
    args: Vec<String>,
) -> Result<String, String> {
    log::info!("Starting nmap scan for target: {} with args: {:?}", target, args);
    
    // Convert Vec<String> to Vec<&str> for the function call
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    
    match run_nmap(&target, &args_ref).await {
        Ok(output) => {
            log::info!("Nmap scan completed successfully");
            Ok(output)
        }
        Err(e) => {
            let error_msg = format!("Nmap scan failed: {}", e);
            log::error!("{}", error_msg);
            Err(error_msg)
        }
    }
}

/// Get the status of masscan and nmap binaries (local and system)
#[tauri::command]
pub async fn get_scanner_status() -> Result<BinaryStatus, String> {
    match get_binary_status().await {
        status => {
            log::info!("Binary status retrieved: {:?}", status);
            Ok(status)
        }
    }
}

/// Get the bin directory path
#[tauri::command]
pub fn get_bin_directory_path() -> String {
    let bin_dir = get_bin_directory();
    bin_dir.to_string_lossy().to_string()
}

/// Check if a specific scanner is available
#[tauri::command]
pub async fn is_scanner_available(scanner: String) -> Result<bool, String> {
    match scanner.to_lowercase().as_str() {
        "masscan" => {
            let available = crate::utils::os::is_masscan_available().await;
            log::info!("Masscan availability check: {}", available);
            Ok(available)
        }
        "nmap" => {
            let available = crate::utils::os::is_nmap_available().await;
            log::info!("Nmap availability check: {}", available);
            Ok(available)
        }
        _ => Err(format!("Unknown scanner: {}", scanner))
    }
}

/// Quick network scan using the best available scanner
#[tauri::command]
pub async fn quick_network_scan(
    ip_range: String,
    common_ports_only: Option<bool>,
) -> Result<ScanResult, String> {
    let use_common_ports = common_ports_only.unwrap_or(true);
    let ports = if use_common_ports {
        "22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3389,5900"
    } else {
        "1-65535"
    };

    log::info!("Starting quick network scan for range: {} ports: {}", ip_range, ports);

    // Try masscan first (faster for large ranges)
    if crate::utils::os::is_masscan_available().await {
        match run_masscan(&ip_range, ports, Some(10000)).await {
            Ok(output) => {
                return Ok(ScanResult {
                    success: true,
                    output,
                    error: None,
                });
            }
            Err(e) => {
                log::warn!("Masscan failed, falling back to nmap: {}", e);
            }
        }
    }

    // Fall back to nmap
    if crate::utils::os::is_nmap_available().await {
        let args = vec!["-sS", "-T4", "-p", ports];
        let args_str: Vec<&str> = args.iter().cloned().collect();
        
        match run_nmap(&ip_range, &args_str).await {
            Ok(output) => {
                Ok(ScanResult {
                    success: true,
                    output,
                    error: None,
                })
            }
            Err(e) => {
                let error_msg = format!("Both masscan and nmap failed: {}", e);
                log::error!("{}", error_msg);
                Ok(ScanResult {
                    success: false,
                    output: String::new(),
                    error: Some(error_msg),
                })
            }
        }
    } else {
        let error_msg = "Neither masscan nor nmap is available".to_string();
        log::error!("{}", error_msg);
        Ok(ScanResult {
            success: false,
            output: String::new(),
            error: Some(error_msg),
        })
    }
}