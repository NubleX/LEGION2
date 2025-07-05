// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024 and Kali Linux users were left with a broken program.

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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State, Emitter};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanOptions {
    #[serde(rename = "targetIp")]
    target_ip: String,
    #[serde(rename = "scanType")]
    scan_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilityResult {
    id: String,
    severity: String,
    description: String,
    port: Option<u16>,
    service: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ScanProgressEvent {
    #[serde(rename = "scanId")]
    scan_id: String,
    progress: f32,
    message: Option<String>,
}

pub struct ScanState {
    pub active_scans: HashMap<String, tokio::task::JoinHandle<()>>,
}

pub type ScanStateStore = Mutex<ScanState>;

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    options: ScanOptions,
    state: State<'_, ScanStateStore>,
) -> Result<String, String> {
    // Validate input
    if !is_valid_target(&options.target_ip) {
        return Err("Invalid target IP or hostname".to_string());
    }

    let scan_id = Uuid::new_v4().to_string();
    let scan_id_clone = scan_id.clone();
    let app_handle = app.clone();

    // Spawn scan task
    let handle = tokio::spawn(async move {
        if let Err(e) = run_scan(app_handle, scan_id_clone, options).await {
            eprintln!("Scan error: {}", e);
        }
    });

    // Store scan handle
    state.lock().unwrap().active_scans.insert(scan_id.clone(), handle);

    Ok(scan_id)
}

#[tauri::command]
pub async fn stop_scan(
    scan_id: String,
    state: State<'_, ScanStateStore>,
) -> Result<(), String> {
    let mut scan_state = state.lock().unwrap();
    
    if let Some(handle) = scan_state.active_scans.remove(&scan_id) {
        handle.abort();
        Ok(())
    } else {
        Err("Scan not found".to_string())
    }
}

#[tauri::command]
pub async fn get_vulnerabilities(
    severity_filter: Option<String>,
) -> Result<Vec<VulnerabilityResult>, String> {
    // Mock implementation - replace with actual vulnerability retrieval
    let mut vulnerabilities = vec![
        VulnerabilityResult {
            id: "vuln-1".to_string(),
            severity: "high".to_string(),
            description: "Open SSH port detected".to_string(),
            port: Some(22),
            service: Some("ssh".to_string()),
        },
        VulnerabilityResult {
            id: "vuln-2".to_string(),
            severity: "medium".to_string(),
            description: "HTTP service without HTTPS".to_string(),
            port: Some(80),
            service: Some("http".to_string()),
        },
    ];

    // Apply filter if provided
    if let Some(filter) = severity_filter {
        vulnerabilities.retain(|v| v.severity == filter);
    }

    Ok(vulnerabilities)
}

#[tauri::command]
pub fn is_scanning(state: State<'_, ScanStateStore>) -> bool {
    !state.lock().unwrap().active_scans.is_empty()
}

// Helper functions
fn is_valid_target(target: &str) -> bool {
    use regex::Regex;
    
    let ip_regex = Regex::new(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$").unwrap();
    let domain_regex = Regex::new(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    
    ip_regex.is_match(target) || domain_regex.is_match(target)
}

async fn run_scan(
    app: AppHandle,
    scan_id: String,
    options: ScanOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    let event_name = format!("scan-progress-{}", scan_id);

    // Build nmap command
    let mut cmd = Command::new("nmap");
    cmd.arg("-v")
       .arg("--stats-every")
       .arg("5s")
       .arg(&options.target_ip)
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    // Add scan type specific args
    match options.scan_type.as_str() {
        "quick" => {
            cmd.arg("-T4").arg("-F");
        }
        "full" => {
            cmd.arg("-p-").arg("-sV");
        }
        _ => {
            cmd.arg("-sS");
        }
    }

    let mut child = cmd.spawn()?;
    
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    
    let mut stdout_reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();

    // Process output
    loop {
        tokio::select! {
            line = stdout_reader.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        let progress = parse_nmap_progress(&line);
                        let event = ScanProgressEvent {
                            scan_id: scan_id.clone(),
                            progress,
                            message: Some(line),
                        };
                        // In Tauri v2, use emit instead of emit_all
                        let _ = app.emit(&event_name, &event);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("Error reading stdout: {}", e);
                        break;
                    }
                }
            }
            err_line = stderr_reader.next_line() => {
                if let Ok(Some(line)) = err_line {
                    let event = ScanProgressEvent {
                        scan_id: scan_id.clone(),
                        progress: 0.0,
                        message: Some(format!("Error: {}", line)),
                    };
                    let _ = app.emit(&event_name, &event);
                }
            }
        }
    }

    // Wait for process to complete
    let _ = child.wait().await?;

    // Send completion event
    let event = ScanProgressEvent {
        scan_id: scan_id.clone(),
        progress: 100.0,
        message: Some("Scan completed".to_string()),
    };
    let _ = app.emit(&event_name, &event);

    Ok(())
}

fn parse_nmap_progress(line: &str) -> f32 {
    // Simple progress parsing - improve based on actual nmap output
    if line.contains("% done") {
        if let Some(pos) = line.find('%') {
            if pos > 0 {
                let start = line[..pos].rfind(' ').unwrap_or(0) + 1;
                if let Ok(percent) = line[start..pos].parse::<f32>() {
                    return percent;
                }
            }
        }
    }
    0.0
}