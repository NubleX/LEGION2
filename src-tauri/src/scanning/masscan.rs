// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use anyhow::{anyhow, Result};
use chrono::Utc;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::core::traits::Source;
use crate::plan::Plan;
use crate::scanning::events::{EventType, ScanEvent};
use crate::scanning::models::ScanTarget;
use crate::scanning::models::{ScanProgress, ScanStatus};
use crate::shared::{ObsStream, Observation, ObservationKind};
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::mpsc;
use crate::commands::engine_commands; // for cancellation polling

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
            ports: "1-65535".to_string(),
            exclude_file: None,
            interface: None,
            source_port: None,
            wait_time: 10,
            retries: 1,
        }
    }
}

#[derive(Debug)]
pub struct MasscanScanner {
    bin: PathBuf,
    options: MasscanOptions,
}

impl MasscanScanner {
    pub fn new() -> Result<Self> {
        let bin = crate::utils::os::get_masscan_binary_path();
        Ok(Self { 
            bin,
            options: MasscanOptions::default(),
        })
    }
    
    async fn check_masscan_available(&self) -> bool {
        std::path::Path::new(&self.bin).exists()
    }
    
    async fn build_masscan_command(&self, plan: &Plan) -> Command {
        let mut cmd = Command::new(&self.bin);

        // Port specification (required for masscan)
        let ports = if plan.ports.is_empty() {
            "1-1000"
        } else {
            &plan.ports
        };
        cmd.arg("-p").arg(ports);

        // Only show open ports
        cmd.arg("--open");

        // Set rate
        let rate = plan.rate.unwrap_or(1000);
        cmd.arg("--rate").arg(rate.to_string());

        // Output format for real-time parsing
        cmd.arg("--output-format").arg("list");

        // Add any extra arguments
        for arg in &plan.extra {
            cmd.arg(arg);
        }

        // Target specification (must be last)
        cmd.arg(&plan.targets);

        log::info!("Masscan command: {:?}", cmd);
        cmd
    }
    
    pub async fn scan_target(
        &self,
    target: &ScanTarget,
    progress_tx: mpsc::Sender<ScanProgress>,
    event_tx: mpsc::Sender<ScanEvent>,
) -> Result<Vec<u16>> {
    if !self.check_masscan_available().await {
        return Err(anyhow!("masscan binary not found. Please install masscan."));
    }

    let ports_arg = if let Some(ports) = &target.ports {
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    } else {
        "1-65535".to_string()
    };

    let mut cmd = Command::new(&self.bin);
    cmd.arg("-p")
        .arg(&ports_arg)
        .args(["--open", "--wait", "0"])
        .arg("--rate")
        .arg(self.options.rate.to_string())
        .arg(&target.ip.to_string()) // Target goes LAST
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Failed to get stdout"))?;
    let mut lines = BufReader::new(stdout).lines();

    let mut open_ports = Vec::new();
    let now = Utc::now();
    let _ = progress_tx
        .send(ScanProgress {
            scan_id: target.id.clone(),
            status: ScanStatus::Running,
            percentage: 0.0,
            stage: "Masscan".to_string(),
            targets_completed: 0,
            targets_total: 1,
            hosts_found: 0,
            services_found: 0,
            eta_seconds: None,
            started_at: now,
            updated_at: now,
            rate: None,
            details: HashMap::new(),
            progress: 0.0,
            current_target: Some(target.ip.to_string()),
            hosts_discovered: 0,
            ports_found: 0,
            vulnerabilities: 0,
            elapsed_time: 0,
            estimated_remaining: None,
            message: Some("Starting masscan".to_string()),
            start_time: now,
            current_phase: "Masscan".to_string(),
        })
        .await;

    let scan_uuid = uuid::Uuid::parse_str(&target.id)?;
    while let Some(line) = lines.next_line().await? {
        if let Some(obs) = parse_masscan_line(&line, scan_uuid) {
            if let Some(port_val) = obs.fields.get("port").and_then(|v| v.as_u64()) {
                open_ports.push(port_val as u16);
                let _ = event_tx
                    .send(ScanEvent {
                        scan_id: target.id.clone(),
                        event_type: EventType::ServiceDiscovered,
                        timestamp: Utc::now(),
                        data: json!({
                            "ip": target.ip.to_string(),
                            "port": port_val,
                            "protocol": obs
                                .fields
                                .get("protocol")
                                .and_then(|v| v.as_str())
                                .unwrap_or("tcp"),
                        }),
                    })
                    .await;
            }
        }
    }

    let _ = child.wait().await?;

    let now = Utc::now();
    let _ = progress_tx
        .send(ScanProgress {
            scan_id: target.id.clone(),
            status: ScanStatus::Running,
            percentage: 100.0,
            stage: "Masscan".to_string(),
            targets_completed: 1,
            targets_total: 1,
            hosts_found: 0,
            services_found: open_ports.len(),
            eta_seconds: None,
            started_at: now,
            updated_at: now,
            rate: None,
            details: HashMap::new(),
            progress: 100.0,
            current_target: Some(target.ip.to_string()),
            hosts_discovered: 0,
            ports_found: open_ports.len() as u32,
            vulnerabilities: 0,
            elapsed_time: 0,
            estimated_remaining: None,
            message: Some("Masscan completed".to_string()),
            start_time: now,
            current_phase: "Masscan".to_string(),
        })
        .await;

    Ok(open_ports)
    }
}

// Use the proper OS utilities to find masscan (checks local /bin first)
fn get_masscan_binary_path() -> Result<PathBuf> {
    Ok(crate::utils::os::get_masscan_binary_path())
}

#[async_trait::async_trait]
impl Source for MasscanScanner {
    fn name(&self) -> &'static str {
        "masscan"
    }

    async fn start(&self, plan: &Plan) -> Result<ObsStream> {
        if !self.check_masscan_available().await {
            return Err(anyhow!("masscan binary not found. Please install masscan."));
        }

        let mut cmd = Command::new(&self.bin);
        // Masscan syntax: masscan -p[ports] [options] [targets]
        cmd.arg("-p")
            .arg(&plan.ports)
            .arg("--open")
            .arg("--rate")
            .arg(&plan.rate.unwrap_or(1000).to_string())
            .arg("--output-format")
            .arg("list")
            .arg(&plan.targets) // Target goes LAST
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        log::info!("Executing masscan command: {:?}", cmd);

        let mut child = cmd.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to get stdout"))?;
        let reader = BufReader::new(stdout);
        let lines = reader.lines();

        let scan_id = plan.scan_id;
        let discovered_count = 0u64;

        log::info!("Starting masscan stream processing");

        let stream = stream::unfold(
            (lines, discovered_count, child),
            move |(mut lines, mut count, mut child)| async move {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        if engine_commands::is_scan_cancelled() {
                            log::warn!("Masscan scan cancelled by user");
                            let _ = child.kill().await;
                            let mut fields = serde_json::Map::new();
                            fields.insert("status".to_string(), "cancelled".into());
                            let cancel_obs = Observation {
                                scan_id,
                                kind: ObservationKind::Metric,
                                fields,
                                ts: Utc::now(),
                                key: "scan-status".to_string(),
                                raw: None,
                            };
                            return Some((cancel_obs, (lines, count, child)));
                        }
                        log::info!("Masscan output line: {}", line);
                        if let Some(obs) = parse_masscan_line(&line, scan_id) {
                            count += 1;
                            log::info!("Parsed masscan observation: {:?}", obs);
                            // Create a progress observation every 10 discoveries
                            if count % 10 == 0 {
                                let progress_obs =
                                    create_progress_observation(&line, scan_id, count);
                                Some((progress_obs, (lines, count, child)))
                            } else {
                                Some((obs, (lines, count, child)))
                            }
                        } else {
                            log::debug!("Non-service masscan line: {}", line);
                            // Skip this line and continue
                            Some((
                                Observation {
                                    scan_id,
                                    kind: ObservationKind::Metric,
                                    fields: {
                                        let mut fields = serde_json::Map::new();
                                        fields.insert(
                                            "masscan_output".to_string(),
                                            line.clone().into(),
                                        );
                                        fields
                                    },
                                    ts: Utc::now(),
                                    key: "masscan-output".to_string(),
                                    raw: Some(line),
                                },
                                (lines, count, child),
                            ))
                        }
                    }
                    Ok(None) => {
                        log::info!("Masscan stream ended - waiting for process to complete");
                        // Wait for the child process to finish
                        match child.wait().await {
                            Ok(status) => {
                                log::info!("Masscan process completed with status: {}", status);
                            }
                            Err(e) => {
                                log::error!("Error waiting for masscan process: {}", e);
                            }
                        }
                        None
                    }
                    Err(e) => {
                        log::error!("Error reading masscan output: {}", e);
                        // Kill the child process if there was an error
                        let _ = child.kill().await;
                        None
                    }
                }
            },
        );

        Ok(stream.boxed())
    }
}

/// Parse a line from masscan output in list format
/// Expected format: "open tcp 80 192.168.1.1" or "open udp 53 192.168.1.2"
fn parse_masscan_line(line: &str, scan_id: uuid::Uuid) -> Option<Observation> {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();

    // Expected format: ["open", "tcp"/"udp", "port", "ip"]
    if parts.len() >= 4 && parts[0] == "open" {
        let protocol = parts[1];
        if let (Ok(port), Ok(ip)) = (parts[2].parse::<u16>(), parts[3].parse::<IpAddr>()) {
            let mut fields = serde_json::Map::new();
            fields.insert("ip".to_string(), ip.to_string().into());
            fields.insert("port".to_string(), port.into());
            fields.insert("protocol".to_string(), protocol.into());
            fields.insert("state".to_string(), "open".into());
            fields.insert("reason".to_string(), "syn-ack".into()); // masscan default reason

            return Some(Observation {
                scan_id,
                kind: ObservationKind::Service,
                fields,
                ts: Utc::now(),
                key: format!("{}:{}/{}", ip, port, protocol),
                raw: Some(line.to_string()),
            });
        }
    }

    None
}

/// Create a progress observation for masscan using ScanProgress  
fn create_progress_observation(
    line: &str,
    scan_id: uuid::Uuid,
    discovered_count: u64,
) -> Observation {
    let mut fields = serde_json::Map::new();
    fields.insert("scan_phase".to_string(), "port_scan".into());
    fields.insert("services_found".to_string(), discovered_count.into());
    fields.insert(
        "progress_message".to_string(),
        format!("Masscan found {} open ports", discovered_count).into(),
    );

    Observation {
        scan_id,
        kind: ObservationKind::Metric,
        fields,
        ts: Utc::now(),
        key: format!("masscan-progress-{}", discovered_count),
        raw: Some(line.to_string()),
    }
}
