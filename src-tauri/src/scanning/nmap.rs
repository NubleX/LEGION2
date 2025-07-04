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

use super::*;
use anyhow::{Result, Context};
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::collections::HashMap;

pub struct NmapScanner {
    // Add configuration options if needed
}

impl NmapScanner {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn scan_target(
        &self,
        target: &ScanTarget,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> Result<ScanResult> {
        log::info!("Starting nmap scan for target: {:?}", target.ip);
        
        // Create output file path
        let timestamp = chrono::Utc::now().timestamp();
        let output_file = format!("/tmp/nmap_scan_{}_{}_{}.xml", 
            target.ip.to_string().replace(".", "_"), 
            target.id,
            timestamp
        );

        // Build nmap command based on scan type
        let mut cmd = Command::new("nmap");
        
        // Always output XML for parsing
        cmd.arg("-oX").arg(&output_file);
        
        // Configure scan based on type
        match &target.scan_type {
            ScanType::Quick => {
                cmd.args(&["-T4", "-F"]); // Fast scan, top 100 ports
            }
            ScanType::Comprehensive => {
                cmd.args(&["-sS", "-sV", "-O", "-A", "-T4"]);
                if !target.ports.is_empty() {
                    let ports: Vec<String> = target.ports.iter()
                        .map(|p| p.to_string())
                        .collect();
                    cmd.arg("-p").arg(ports.join(","));
                } else {
                    cmd.arg("-p").arg("1-65535");
                }
            }
            ScanType::Stealth => {
                cmd.args(&["-sS", "-T2", "-f", "--randomize-hosts"]);
            }
            ScanType::Custom { options } => {
                for opt in options.split_whitespace() {
                    cmd.arg(opt);
                }
            }
        }
        
        // Add target
        cmd.arg(&target.ip.to_string());
        
        // Execute with progress monitoring
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        let mut child = cmd.spawn()
            .context("Failed to spawn nmap process")?;

        // Monitor stderr for progress
        if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            let tx = progress_tx.clone();
            
            tokio::spawn(async move {
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Ok(progress) = parse_progress_line(&line) {
                        let _ = tx.send(progress).await;
                    }
                }
            });
        }

        // Wait for completion
        let status = child.wait().await
            .context("Failed to wait for nmap process")?;

        if !status.success() {
            return Err(anyhow::anyhow!("Nmap scan failed with status: {}", status));
        }

        // Parse the XML output
        let xml_content = tokio::fs::read_to_string(&output_file).await
            .context("Failed to read nmap output file")?;
        
        let result = self.parse_nmap_xml(&xml_content, target)
            .context("Failed to parse nmap XML")?;

        // Clean up temp file
        let _ = tokio::fs::remove_file(&output_file).await;

        // Send completion progress
        let _ = progress_tx.send(ScanProgress {
            scan_id: target.id.to_string(),
            target_id: target.id.to_string(),
            progress: 100.0,
            current_phase: "Scan completed".to_string(),
            discovered_hosts: 1,
            total_ports_scanned: result.open_ports.len() as i32,
            open_ports_found: result.open_ports.len() as i32,
            estimated_time_remaining: Some(0),
            message: Some("Scan completed successfully".to_string()),
            start_time: chrono::Utc::now(),
        }).await;

        Ok(result)
    }

    fn parse_nmap_xml(&self, xml_content: &str, target: &ScanTarget) -> Result<ScanResult> {
        let mut reader = Reader::from_str(xml_content);
        reader.trim_text(true);
        
        let mut result = ScanResult {
            id: uuid::Uuid::new_v4(),
            target_id: target.id,
            timestamp: chrono::Utc::now(),
            status: ScanStatus::Completed,
            open_ports: Vec::new(),
            os_detection: None,
            vulnerabilities: Vec::new(),
        };

        let mut buf = Vec::new();
        let mut in_port = false;
        let mut current_port: Option<Port> = None;
        let mut in_osmatch = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"port" => {
                            in_port = true;
                            let mut port_num = 0u16;
                            let mut protocol = "tcp".to_string();
                            
                            for attr in e.attributes() {
                                let attr = attr?;
                                match attr.key.as_ref() {
                                    b"portid" => {
                                        port_num = std::str::from_utf8(&attr.value)?
                                            .parse()
                                            .unwrap_or(0);
                                    }
                                    b"protocol" => {
                                        protocol = std::str::from_utf8(&attr.value)?
                                            .to_string();
                                    }
                                    _ => {}
                                }
                            }
                            
                            current_port = Some(Port {
                                number: port_num,
                                protocol,
                                state: "unknown".to_string(),
                                service: None,
                                version: None,
                                banner: None,
                            });
                        }
                        b"state" if in_port => {
                            if let Some(ref mut port) = current_port {
                                for attr in e.attributes() {
                                    let attr = attr?;
                                    if attr.key.as_ref() == b"state" {
                                        port.state = std::str::from_utf8(&attr.value)?
                                            .to_string();
                                    }
                                }
                            }
                        }
                        b"service" if in_port => {
                            if let Some(ref mut port) = current_port {
                                let mut service_info = HashMap::new();
                                
                                for attr in e.attributes() {
                                    let attr = attr?;
                                    let key = std::str::from_utf8(attr.key.as_ref())?;
                                    let value = std::str::from_utf8(&attr.value)?;
                                    service_info.insert(key.to_string(), value.to_string());
                                }
                                
                                port.service = service_info.get("name").cloned();
                                port.version = service_info.get("version").cloned();
                                
                                // Build version string
                                if let Some(product) = service_info.get("product") {
                                    let mut version = product.clone();
                                    if let Some(ver) = service_info.get("version") {
                                        version.push(' ');
                                        version.push_str(ver);
                                    }
                                    port.version = Some(version);
                                }
                            }
                        }
                        b"osmatch" => {
                            in_osmatch = true;
                            let mut os_name = String::new();
                            let mut accuracy = 0.0;
                            
                            for attr in e.attributes() {
                                let attr = attr?;
                                match attr.key.as_ref() {
                                    b"name" => {
                                        os_name = std::str::from_utf8(&attr.value)?
                                            .to_string();
                                    }
                                    b"accuracy" => {
                                        accuracy = std::str::from_utf8(&attr.value)?
                                            .parse()
                                            .unwrap_or(0.0);
                                    }
                                    _ => {}
                                }
                            }
                            
                            if result.os_detection.is_none() || 
                               result.os_detection.as_ref().unwrap().accuracy < accuracy {
                                result.os_detection = Some(OsDetection {
                                    name: os_name.clone(),
                                    accuracy,
                                    family: extract_os_family(&os_name),
                                    vendor: extract_os_vendor(&os_name),
                                });
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    match e.name().as_ref() {
                        b"port" => {
                            if let Some(port) = current_port.take() {
                                if port.state == "open" {
                                    result.open_ports.push(port);
                                }
                            }
                            in_port = false;
                        }
                        b"osmatch" => {
                            in_osmatch = false;
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow::anyhow!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(result)
    }
}

fn parse_progress_line(line: &str) -> Result<ScanProgress> {
    // Parse nmap progress output
    // Example: "Completed SYN Stealth Scan at 14:25, 10.00s elapsed (1000 total ports)"
    let progress = if line.contains("% done") {
        // Extract percentage
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if part.contains("%") {
                if i > 0 {
                    if let Ok(percent) = parts[i-1].parse::<f32>() {
                        return Ok(ScanProgress {
                            scan_id: String::new(),
                            target_id: String::new(),
                            progress: percent,
                            current_phase: "Scanning".to_string(),
                            discovered_hosts: 0,
                            total_ports_scanned: 0,
                            open_ports_found: 0,
                            estimated_time_remaining: None,
                            message: Some(line.to_string()),
                            start_time: chrono::Utc::now(),
                        });
                    }
                }
            }
        }
        0.0
    } else {
        0.0
    };

    Ok(ScanProgress {
        scan_id: String::new(),
        target_id: String::new(),
        progress,
        current_phase: "Scanning".to_string(),
        discovered_hosts: 0,
        total_ports_scanned: 0,
        open_ports_found: 0,
        estimated_time_remaining: None,
        message: Some(line.to_string()),
        start_time: chrono::Utc::now(),
    })
}

fn extract_os_family(os_name: &str) -> String {
    let lower = os_name.to_lowercase();
    if lower.contains("windows") {
        "Windows".to_string()
    } else if lower.contains("linux") {
        "Linux".to_string()
    } else if lower.contains("mac") || lower.contains("darwin") {
        "macOS".to_string()
    } else if lower.contains("freebsd") || lower.contains("openbsd") || lower.contains("netbsd") {
        "BSD".to_string()
    } else {
        "Unknown".to_string()
    }
}

fn extract_os_vendor(os_name: &str) -> String {
    let lower = os_name.to_lowercase();
    if lower.contains("microsoft") {
        "Microsoft".to_string()
    } else if lower.contains("apple") {
        "Apple".to_string()
    } else if lower.contains("ubuntu") {
        "Canonical".to_string()
    } else if lower.contains("redhat") || lower.contains("rhel") {
        "Red Hat".to_string()
    } else if lower.contains("debian") {
        "Debian".to_string()
    } else {
        "Unknown".to_string()
    }
}