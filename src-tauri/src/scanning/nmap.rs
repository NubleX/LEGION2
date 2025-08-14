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

use crate::commands::scanner_commands::ScanTarget;
use crate::core::traits::Source;
use crate::core::types::{ObsStream, Observation, Plan};
use crate::scanning::events::{EventType, ScanEvent};
use crate::scanning::models::{OSDetection, ScanProgress, ScanType};
use crate::shared::{PortState, Protocol, ScanPort, ScanVulnerability};
use crate::utils::os::{get_nmap_binary_path, is_nmap_available};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub target_id: String,
    pub status: ScanStatus,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub duration: Option<u64>,
    pub open_ports: Vec<ScanPort>,
    pub os_detection: Option<OSDetection>,
    pub vulnerabilities: Vec<ScanVulnerability>,
    pub scan_type: String,
    pub error_message: Option<String>,
    pub raw_output: Option<String>,
    pub command_used: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}
use anyhow::{Context, Result};
use chrono::Utc;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde_json::json;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub struct NmapScanner {
    // Add configuration options if needed
}

impl NmapScanner {
    pub fn new() -> Self {
        Self {}
    }

    /// Check if nmap is available on the system
    pub async fn is_available() -> bool {
        is_nmap_available().await
    }

    pub async fn scan_target(
        &self,
        target: &ScanTarget,
        progress_tx: mpsc::Sender<ScanProgress>,
        event_tx: Option<mpsc::Sender<ScanEvent>>,
    ) -> Result<ScanResult> {
        log::info!("Starting nmap scan for target: {:?}", target.ip);

        // Create output file path
        let timestamp = chrono::Utc::now().timestamp();
        let output_file = format!(
            "/tmp/nmap_scan_{}_{}_{}.xml",
            target.ip.to_string().replace(".", "_"),
            target.id,
            timestamp
        );

        // Check if nmap is available
        if !Self::is_available().await {
            return Err(anyhow::anyhow!("Nmap is not available on this system"));
        }

        // Build nmap command based on scan type using OS-appropriate binary (local /bin first)
        let nmap_path = get_nmap_binary_path();
        let mut cmd = Command::new(&nmap_path);

        // Always output XML for parsing and add verbose flags for real-time output
        cmd.arg("-oX").arg(&output_file);
        cmd.args(&["-vv", "--stats-every", "2s"]); // Double verbose output with frequent stats

        // Configure scan based on type
        match &target.scan_type {
            ScanType::Quick => {
                cmd.args(&["-T4", "-F"]); // Fast scan, top 100 ports
            }
            ScanType::Comprehensive => {
                cmd.args(&["-sS", "-sV", "-O", "-A", "-T4"]);
                if let Some(ports) = &target.ports {
                    if !ports.is_empty() {
                        let ports_str: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                        cmd.arg("-p").arg(ports_str.join(","));
                    }
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
            _ => { /* Handle other scan types or default */ }
        }

        // Add target
        cmd.arg(&target.ip.to_string());

        // Log the full command being executed
        log::info!("Executing nmap command: {:?}", cmd);

        // Execute with progress monitoring
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn nmap process")?;

        log::info!("Nmap process spawned with PID: {:?}", child.id());

        // Send a test output event to verify pipeline
        if let Some(ref event_tx) = event_tx {
            let test_event = ScanEvent {
                scan_id: target.id.clone(),
                event_type: EventType::ScanOutput,
                timestamp: Utc::now(),
                data: json!({
                    "source": "test",
                    "content": format!("Nmap command: nmap -vv --stats-every 2s -oX {} -T4 -F {}", output_file, target.ip),
                    "timestamp": Utc::now().to_rfc3339()
                }),
            };
            log::info!("Sending ONE test event for scan {}", target.id);
            let _ = event_tx.send(test_event).await;
        }

        // Monitor both stdout and stderr for progress and real-time output
        let stdout_handle = if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            let progress_tx_clone = progress_tx.clone();
            let event_tx_clone = event_tx.clone();
            let target_id_clone = target.id.clone();

            Some(tokio::spawn(async move {
                log::info!("Starting stdout monitor for scan {}", target_id_clone);
                let mut line_count = 0;
                while let Ok(Some(line)) = lines.next_line().await {
                    line_count += 1;
                    log::info!("STDOUT Line {}: {}", line_count, line);

                    // Send real-time output event
                    if let Some(ref event_sender) = event_tx_clone {
                        log::info!("Sending STDOUT event for line {}: {}", line_count, line);
                        let output_event = ScanEvent {
                            scan_id: target_id_clone.clone(),
                            event_type: EventType::ScanOutput,
                            timestamp: Utc::now(),
                            data: json!({
                                "source": "stdout",
                                "content": line,
                                "timestamp": Utc::now().to_rfc3339()
                            }),
                        };
                        let _ = event_sender.send(output_event).await;
                    }

                    // Try to parse progress information
                    if let Ok(progress) = parse_progress_line(&line, &target_id_clone) {
                        let _ = progress_tx_clone.send(progress).await;
                    }
                }
                log::info!(
                    "Stdout monitor ended for scan {}, total lines: {}",
                    target_id_clone,
                    line_count
                );
            }))
        } else {
            None
        };

        let stderr_handle = if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            let progress_tx_clone = progress_tx.clone();
            let event_tx_clone = event_tx.clone();
            let target_id_clone = target.id.clone();

            Some(tokio::spawn(async move {
                log::info!("Starting stderr monitor for scan {}", target_id_clone);
                let mut line_count = 0;
                while let Ok(Some(line)) = lines.next_line().await {
                    line_count += 1;
                    log::info!("STDERR Line {}: {}", line_count, line);

                    // Send real-time output event
                    if let Some(ref event_sender) = event_tx_clone {
                        let output_event = ScanEvent {
                            scan_id: target_id_clone.clone(),
                            event_type: EventType::ScanOutput,
                            timestamp: Utc::now(),
                            data: json!({
                                "source": "stderr",
                                "content": line,
                                "timestamp": Utc::now().to_rfc3339()
                            }),
                        };
                        let _ = event_sender.send(output_event).await;
                    }

                    // Try to parse progress information
                    if let Ok(progress) = parse_progress_line(&line, &target_id_clone) {
                        let _ = progress_tx_clone.send(progress).await;
                    }
                }
                log::info!(
                    "Stderr monitor ended for scan {}, total lines: {}",
                    target_id_clone,
                    line_count
                );
            }))
        } else {
            None
        };

        // Wait for completion
        let status = child
            .wait()
            .await
            .context("Failed to wait for nmap process")?;

        // Wait for output handlers to complete
        if let Some(handle) = stdout_handle {
            let _ = handle.await;
        }
        if let Some(handle) = stderr_handle {
            let _ = handle.await;
        }

        if !status.success() {
            return Err(anyhow::anyhow!("Nmap scan failed with status: {}", status));
        }

        // Parse the XML output
        let xml_content = tokio::fs::read_to_string(&output_file)
            .await
            .context("Failed to read nmap output file")?;

        let result = self
            .parse_nmap_xml(&xml_content, target)
            .context("Failed to parse nmap XML")?;

        // Clean up temp file
        let _ = tokio::fs::remove_file(&output_file).await;

        // Send completion progress
        let _ = progress_tx
            .send(ScanProgress {
                scan_id: target.id.to_string(),
                status: crate::scanning::models::ScanStatus::Completed,
                percentage: 100.0,
                stage: "Completed".to_string(),
                targets_completed: 1,
                targets_total: 1,
                hosts_found: 1,
                services_found: result.open_ports.len(),
                eta_seconds: None,
                started_at: Utc::now(),
                updated_at: Utc::now(),
                rate: None,
                details: std::collections::HashMap::new(),
                progress: 100.0,
                current_target: Some(target.ip.to_string()),
                hosts_discovered: 1,
                ports_found: result.open_ports.len() as u32,
                vulnerabilities: result.vulnerabilities.len() as u32,
                elapsed_time: 0,
                estimated_remaining: Some(0),
                message: Some("Scan completed successfully".to_string()),
                start_time: Utc::now(),
                current_phase: "Completed".to_string(),
            })
            .await;

        Ok(result)
    }

    fn parse_nmap_xml(&self, xml_content: &str, target: &ScanTarget) -> Result<ScanResult> {
        let mut reader = Reader::from_str(xml_content);

        let mut result = ScanResult {
            id: uuid::Uuid::new_v4().to_string(),
            target_id: target.ip.to_string(),
            status: ScanStatus::Completed,
            start_time: Utc::now(),
            end_time: Some(Utc::now()),
            duration: None,
            open_ports: Vec::new(),
            os_detection: None,
            vulnerabilities: Vec::new(),
            scan_type: target.scan_type.to_string(),
            error_message: None,
            raw_output: Some(xml_content.to_string()),
            command_used: None,
        };

        let mut buf = Vec::new();
        let mut in_port = false;
        let mut current_port: Option<ScanPort> = None;
        let mut _in_osmatch = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"port" => {
                            in_port = true;
                            let mut port_num = 0u16;
                            let mut protocol = Protocol::Tcp;

                            for attr in e.attributes() {
                                let attr = attr?;
                                match attr.key.as_ref() {
                                    b"portid" => {
                                        port_num =
                                            std::str::from_utf8(&attr.value)?.parse().unwrap_or(0);
                                    }
                                    b"protocol" => {
                                        protocol = match std::str::from_utf8(&attr.value)? {
                                            "tcp" => Protocol::Tcp,
                                            "udp" => Protocol::Udp,
                                            _ => Protocol::Tcp,
                                        };
                                    }
                                    _ => {}
                                }
                            }

                            current_port = Some(ScanPort {
                                number: port_num,
                                protocol,
                                state: PortState::Unknown, // Default to unknown, will be updated by <state> tag
                                service: None,
                                version: None,
                                banner: None,
                                confidence: None,
                                cpe: Vec::new(),
                                scripts: None,
                            });
                        }
                        b"state" if in_port => {
                            if let Some(ref mut port) = current_port {
                                for attr in e.attributes() {
                                    let attr = attr?;
                                    if attr.key.as_ref() == b"state" {
                                        port.state = match std::str::from_utf8(&attr.value)? {
                                            "open" => PortState::Open,
                                            "closed" => PortState::Closed,
                                            "filtered" => PortState::Filtered,
                                            _ => PortState::Unknown,
                                        };
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
                            _in_osmatch = true;
                            let mut os_name = String::new();
                            let mut accuracy = 0.0;

                            for attr in e.attributes() {
                                let attr = attr?;
                                match attr.key.as_ref() {
                                    b"name" => {
                                        os_name = std::str::from_utf8(&attr.value)?.to_string();
                                    }
                                    b"accuracy" => {
                                        accuracy = std::str::from_utf8(&attr.value)?
                                            .parse()
                                            .unwrap_or(0.0);
                                    }
                                    _ => {}
                                }
                            }

                            if result.os_detection.is_none()
                                || result.os_detection.as_ref().unwrap().accuracy < accuracy
                            {
                                result.os_detection = Some(OSDetection {
                                    name: os_name.clone(),
                                    accuracy,
                                    family: extract_os_family(&os_name),
                                    vendor: Some(extract_os_vendor(&os_name)),
                                    version: None,
                                    generation: None,
                                    fingerprint: None,
                                    cpe: Vec::new(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => match e.name().as_ref() {
                    b"port" => {
                        if let Some(port) = current_port.take() {
                            if port.state == PortState::Open {
                                result.open_ports.push(port);
                            }
                        }
                        in_port = false;
                    }
                    b"osmatch" => {
                        _in_osmatch = false;
                    }
                    _ => {}
                },
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow::anyhow!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(result)
    }
}

fn parse_progress_line(line: &str, scan_id: &str) -> Result<ScanProgress> {
    // Parse nmap progress output
    // Example: "Completed SYN Stealth Scan at 14:25, 10.00s elapsed (1000 total ports)"
    let progress = if line.contains("% done") {
        // Extract percentage
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if part.contains("%") {
                if i > 0 {
                    if let Ok(percent) = parts[i - 1].parse::<f32>() {
                        return Ok(ScanProgress {
                            scan_id: scan_id.to_string(),
                            status: crate::scanning::models::ScanStatus::Running,
                            percentage: percent,
                            stage: "Scanning".to_string(),
                            targets_completed: 0,
                            targets_total: 1,
                            hosts_found: 0,
                            services_found: 0,
                            eta_seconds: None,
                            started_at: Utc::now(),
                            updated_at: Utc::now(),
                            rate: None,
                            details: std::collections::HashMap::new(),
                            progress: percent,
                            current_target: None,
                            hosts_discovered: 0,
                            ports_found: 0,
                            vulnerabilities: 0,
                            elapsed_time: 0,
                            estimated_remaining: None,
                            message: Some(line.to_string()),
                            start_time: Utc::now(),
                            current_phase: "Scanning".to_string(),
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
        scan_id: scan_id.to_string(),
        status: crate::scanning::models::ScanStatus::Running,
        percentage: progress,
        stage: "Scanning".to_string(),
        targets_completed: 0,
        targets_total: 1,
        hosts_found: 0,
        services_found: 0,
        eta_seconds: None,
        started_at: Utc::now(),
        updated_at: Utc::now(),
        rate: None,
        details: std::collections::HashMap::new(),
        progress,
        current_target: None,
        hosts_discovered: 0,
        ports_found: 0,
        vulnerabilities: 0,
        elapsed_time: 0,
        estimated_remaining: None,
        message: Some(line.to_string()),
        start_time: Utc::now(),
        current_phase: "Scanning".to_string(),
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

#[async_trait::async_trait]
impl Source for NmapScanner {
    fn name(&self) -> &'static str {
        "nmap"
    }

    async fn start(&self, _plan: &Plan) -> anyhow::Result<ObsStream> {
        // For now, return an empty stream
        // This would need to be implemented to integrate with the streaming architecture
        use futures::stream;
        Ok(Box::pin(stream::empty()))
    }
}
