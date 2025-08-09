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

use super::*;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasscanOptions {
    pub rate: u32,
    pub ports: String,
    pub exclude_file: Option<String>,
    pub interface: Option<String>,
    pub source_port: Option<u16>,
    pub wait_time: u32,
    pub retries: u32,
}

impl Default for MasscanOptions {
    fn default() -> Self {
        Self {
            rate: 1000,
            ports: "1-65535",
            exclude_file: None,
            interface: None,
            source_port: None,
            wait_time: 10,
            retries: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasscanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub reason: Option<String>,
    pub banner: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct MasscanScanner {
    options: MasscanOptions,
}

impl MasscanScanner {
    pub fn new() -> Self {
        Self {
            options: MasscanOptions::default(),
        }
    }

    pub fn with_options(options: MasscanOptions) -> Self {
        Self { options }
    }

    pub async fn scan_range(
        &self,
        targets: &[IpAddr],
        ports: &[u16],
        custom_options: Option<&MasscanOptions>,
        progress_tx: &tokio::sync::mpsc::Sender<ScanProgress>,
        scan_id: &str,
    ) -> Result<Vec<MasscanResult>> {
        let options = custom_options.unwrap_or(&self.options);
        
        // Check if masscan is available
        if !self.check_masscan_available().await {
            return Err(anyhow!("masscan not found. Please install masscan first."));
        }

        // Check for required privileges on Unix systems
        #[cfg(unix)]
        {
            if !self.check_privileges().await {
                // Try to use pkexec or sudo
                return self.scan_with_privileges(targets, ports, options, progress_tx, scan_id).await;
            }
        }

        // Build masscan command
        let mut cmd = Command::new("masscan");
        
        // Add target IPs
        for ip in targets {
            cmd.arg(ip.to_string());
        }
        
        // Add ports
        if !ports.is_empty() {
            let port_spec = ports.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            cmd.arg("-p").arg(&port_spec);
        } else {
            cmd.arg("-p").arg(&options.ports);
        }
        
        // Add rate
        cmd.arg("--rate").arg(options.rate.to_string());
        
        // Output format
        cmd.arg("--output-format").arg("json");
        cmd.arg("--output-filename").arg("-"); // Output to stdout
        
        // Additional options
        if let Some(iface) = &options.interface {
            cmd.arg("--interface").arg(iface);
        }
        
        if let Some(sport) = options.source_port {
            cmd.arg("--source-port").arg(sport.to_string());
        }
        
        cmd.arg("--wait").arg(options.wait_time.to_string());
        cmd.arg("--retries").arg(options.retries.to_string());
        
        // Windows-specific adjustments
        #[cfg(windows)]
        {
            // On Windows, masscan might need WinPcap/Npcap
            cmd.arg("--adapter-ip").arg("0.0.0.0");
        }
        
        // Execute masscan
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        
        let stdout = child.stdout.take().ok_or(anyhow!("Failed to capture stdout"))?;
        let stderr = child.stderr.take().ok_or(anyhow!("Failed to capture stderr"))?;
        
        // Parse results in real-time
        let mut results = Vec::new();
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        
        let total_hosts = targets.len();
        let total_ports = if !ports.is_empty() { ports.len() } else { 65535 };
        let total_operations = total_hosts * total_ports;
        let mut operations_done = 0;
        
        // Send initial progress
        let _ = progress_tx.send(ScanProgress {
            scan_id: scan_id.to_string(),
            target_id: format!("{} hosts", total_hosts),
            progress: 0.0,
            current_phase: "Port scanning with masscan".to_string(),
            discovered_hosts: 0,
            total_ports_scanned: 0,
            open_ports_found: 0,
            estimated_time_remaining: Some((total_operations as f64 / options.rate as f64) as u64),
            message: Some(format!("Scanning at {} packets/sec", options.rate)),
            start_time: chrono::Utc::now(),
        }).await;
        
        while let Some(line) = lines.next_line().await? {
            if let Ok(parsed) = self.parse_masscan_output(&line) {
                results.push(parsed);
                
                operations_done += 1;
                let progress = (operations_done as f64 / total_operations as f64) * 100.0;
                
                // Send progress update
                let _ = progress_tx.send(ScanProgress {
                    scan_id: scan_id.to_string(),
                    target_id: format!("{} hosts", total_hosts),
                    progress,
                    current_phase: "Port scanning".to_string(),
                    discovered_hosts: results.iter()
                        .map(|r| r.ip)
                        .collect::<std::collections::HashSet<_>>()
                        .len(),
                    total_ports_scanned: operations_done,
                    open_ports_found: results.len(),
                    estimated_time_remaining: Some(
                        ((total_operations - operations_done) as f64 / options.rate as f64) as u64
                    ),
                    message: Some(format!("Found {} open ports", results.len())),
                    start_time: chrono::Utc::now(),
                }).await;
            }
        }
        
        // Wait for process to complete
        let status = child.wait().await?;
        
        if !status.success() {
            // Read stderr for error messages
            let mut error_reader = BufReader::new(stderr);
            let mut error_msg = String::new();
            use tokio::io::AsyncReadExt;
            error_reader.read_to_string(&mut error_msg).await?;
            
            if error_msg.contains("permission") || error_msg.contains("pcap") {
                return Err(anyhow!("Permission denied. Masscan requires root/admin privileges."));
            }
            
            return Err(anyhow!("Masscan failed: {}", error_msg));
        }
        
        // Send completion
        let _ = progress_tx.send(ScanProgress {
            scan_id: scan_id.to_string(),
            target_id: format!("{} hosts", total_hosts),
            progress: 100.0,
            current_phase: "Completed".to_string(),
            discovered_hosts: results.iter()
                .map(|r| r.ip)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            total_ports_scanned: total_operations,
            open_ports_found: results.len(),
            estimated_time_remaining: Some(0),
            message: Some(format!("Scan complete: {} open ports found", results.len())),
            start_time: chrono::Utc::now(),
        }).await;
        
        Ok(results)
    }
    
    async fn check_masscan_available(&self) -> bool {
        Command::new("masscan")
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
    
    #[cfg(unix)]
    async fn check_privileges(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        
        // Check if running as root
        let uid = unsafe { libc::geteuid() };
        uid == 0
    }
    
    #[cfg(unix)]
    async fn scan_with_privileges(
        &self,
        targets: &[IpAddr],
        ports: &[u16],
        options: &MasscanOptions,
        progress_tx: &tokio::sync::mpsc::Sender<ScanProgress>,
        scan_id: &str,
    ) -> Result<Vec<MasscanResult>> {
        // Try pkexec first, then sudo
        let elevate_cmd = if Command::new("pkexec").arg("--version").output().await.is_ok() {
            "pkexec"
        } else if Command::new("sudo").arg("-n").arg("true").output().await.is_ok() {
            "sudo"
        } else {
            return Err(anyhow!("Masscan requires root privileges. Please run with sudo or configure passwordless sudo."));
        };
        
        // Build elevated command
        let mut cmd = Command::new(elevate_cmd);
        cmd.arg("masscan");
        
        // Add all the same arguments
        for ip in targets {
            cmd.arg(ip.to_string());
        }
        
        if !ports.is_empty() {
            let port_spec = ports.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            cmd.arg("-p").arg(&port_spec);
        } else {
            cmd.arg("-p").arg(&options.ports);
        }
        
        cmd.arg("--rate").arg(options.rate.to_string());
        cmd.arg("--output-format").arg("json");
        cmd.arg("--output-filename").arg("-");
        
        // Continue with the same logic as before...
        // (Implementation continues as in the main scan_range method)
        
        Err(anyhow!("Privilege elevation not yet fully implemented"))
    }
    
    fn parse_masscan_output(&self, line: &str) -> Result<MasscanResult> {
        // Parse JSON output from masscan
        // Example: {"ip":"192.168.1.1","timestamp":"1234567890","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64}]}
        
        #[derive(Deserialize)]
        struct MasscanJson {
            ip: String,
            timestamp: Option<String>,
            ports: Vec<PortInfo>,
        }
        
        #[derive(Deserialize)]
        struct PortInfo {
            port: u16,
            proto: String,
            status: String,
            reason: Option<String>,
            ttl: Option<u32>,
        }
        
        let parsed: MasscanJson = serde_json::from_str(line)?;
        
        if let Some(port_info) = parsed.ports.first() {
            Ok(MasscanResult {
                ip: parsed.ip.parse()?,
                port: port_info.port,
                protocol: port_info.proto.clone(),
                state: port_info.status.clone(),
                reason: port_info.reason.clone(),
                banner: None,
                timestamp: chrono::Utc::now(),
            })
        } else {
            Err(anyhow!("No port information in masscan output"))
        }
    }
}