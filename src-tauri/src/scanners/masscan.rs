// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::commands::engine_commands;
use crate::os::is_command_available;
use crate::plan::Plan;
use crate::scanners::events::{EventType, ScanEvent};
use crate::shared::shared::{ObsStream, Observation, ObservationKind};
use crate::shared::ScanTypes::{ScanProgress, ScanStatus, ScanTarget};
use crate::shared::traits::Source;
use crate::utils::xml_parser::XmlParser;
use anyhow::{anyhow, Result};
use chrono::Utc;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

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
        let bin = crate::os::get_masscan_binary_path();
        Ok(Self {
            bin,
            options: MasscanOptions::default(),
        })
    }

    async fn check_masscan_available(&self) -> bool {
        is_command_available(&self.bin).await
    }

    async fn build_masscan_command(&self, plan: &Plan) -> (Command, String) {
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

        // Output format for real-time parsing (list format for CLI streaming)
        cmd.arg("--output-format").arg("list");

        // Ensure .scans directory exists
        std::fs::create_dir_all(".scans").unwrap_or_else(|e| {
            log::warn!("Failed to create .scans directory: {}", e);
        });

        // Generate XML output file in .scans directory for comprehensive parsing
        let xml_file = format!(
            ".scans/masscan_{}_{}.xml",
            plan.scan_id.to_string().replace("-", "_"),
            chrono::Utc::now().timestamp()
        );
        cmd.arg("-oX").arg(&xml_file);

        // Add any extra arguments
        for arg in &plan.extra {
            cmd.arg(arg);
        }

        // Detect private 10.* targets and append interface if provided
        let targets_private = plan
            .targets
            .split(|c| c == ' ' || c == ',' || c == '\n')
            .any(|t| t.trim_start().starts_with("10."));
        if targets_private {
            if let Some(iface) = &plan.interface {
                cmd.arg("-e").arg(iface);
            }
        }

        // Target specification (must be last)
        cmd.arg(&plan.targets);

        log::info!("Masscan command: {:?}", cmd);
        (cmd, xml_file)
    }

    pub async fn scan_target(
        &self,
        target: &ScanTarget,
        progress_tx: mpsc::Sender<ScanProgress>,
        event_tx: mpsc::Sender<ScanEvent>,
    ) -> Result<Vec<u16>> {
        if !self.check_masscan_available().await {
            let _ = event_tx
                .send(ScanEvent {
                    scan_id: target.id.clone(),
                    event_type: EventType::Error,
                    timestamp: Utc::now(),
                    data: json!({
                        "message": "masscan binary not found. Please install masscan."
                    }),
                })
                .await;
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
            .arg("--output-format")
            .arg("list")
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
                message: Some("Starting Masscan scan".to_string()),
                start_time: now,
                current_phase: "Initialization".to_string(),
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

                    let _ = event_tx
                        .send(ScanEvent {
                            scan_id: target.id.clone(),
                            event_type: EventType::ScanProgress,
                            timestamp: Utc::now(),
                            data: json!({
                                "message": format!(
                                    "Masscan found open port {} on {}",
                                    port_val, target.ip
                                ),
                                "ports_found": open_ports.len()
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
                estimated_remaining: Some(0),
                message: Some(format!("Masscan completed - found {} ports", open_ports.len())),
                start_time: now,
                current_phase: "Completed".to_string(),
            })
            .await;

        Ok(open_ports)
    }
}

#[async_trait::async_trait]
impl Source for MasscanScanner {
    fn name(&self) -> &'static str {
        "masscan"
    }

    async fn start(&self, plan: &Plan) -> Result<ObsStream> {
        if !self.check_masscan_available().await {
            let obs = Observation {
                scan_id: plan.scan_id,
                kind: ObservationKind::Error,
                fields: {
                    let mut fields = serde_json::Map::new();
                    fields.insert(
                        "message".to_string(),
                        "masscan binary not found. Please install masscan.".into(),
                    );
                    fields
                },
                ts: Utc::now(),
                key: "masscan-error".to_string(),
                raw: None,
            };
            return Ok(stream::once(async move { obs }).boxed());
        }

        let (mut cmd, xml_file) = self.build_masscan_command(plan).await;
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
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
            (lines, discovered_count, child, xml_file.clone(), false, Vec::new()),
            move |(mut lines, mut count, mut child, xml_file, xml_parsed, mut xml_obs_queue)| async move {
                // First, emit any queued XML observations
                if let Some(queued_obs) = xml_obs_queue.pop() {
                    return Some((queued_obs, (lines, count, child, xml_file, xml_parsed, xml_obs_queue)));
                }

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
                            return Some((cancel_obs, (lines, count, child, xml_file, xml_parsed, xml_obs_queue)));
                        }
                        log::info!("Masscan output line: {}", line);
                        if let Some(obs) = parse_masscan_line(&line, scan_id) {
                            count += 1;
                            log::info!("Parsed masscan observation: {:?}", obs);

                            // Create a progress observation every 10 discoveries
                            if count % 10 == 0 {
                                let progress_obs =
                                    create_progress_observation(&line, scan_id, count);
                                Some((progress_obs, (lines, count, child, xml_file, xml_parsed, xml_obs_queue)))
                            } else {
                                Some((obs, (lines, count, child, xml_file, xml_parsed, xml_obs_queue)))
                            }
                        } else {
                            log::debug!("Non-service masscan line: {}", line);
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
                                (lines, count, child, xml_file, xml_parsed, xml_obs_queue),
                            ))
                        }
                    }
                    Ok(None) => {
                        log::info!("Masscan stream ended - waiting for process to complete");
                        match child.wait().await {
                            Ok(status) => {
                                log::info!("Masscan process completed with status: {}", status);

                                // Delegate XML parsing to xml_parser module
                                if !xml_parsed {
                                    log::info!(
                                        "Delegating XML parsing to xml_parser module: {}",
                                        xml_file
                                    );
                                    let xml_path = Path::new(&xml_file);

                                    if xml_path.exists() {
                                        let xml_parser = XmlParser::new(scan_id);
                                        match xml_parser.parse_masscan_xml(xml_path) {
                                            Ok(mut xml_observations) => {
                                                log::info!("XML parser generated {} comprehensive observations from masscan", xml_observations.len());

                                                // Queue all XML observations (in reverse order so they emit in correct order with pop())
                                                xml_observations.reverse();
                                                xml_obs_queue.extend(xml_observations);

                                                // Create a completion observation indicating XML parsing is done
                                                let completion_obs = Observation {
                                                    scan_id,
                                                    kind: ObservationKind::Metric,
                                                    fields: {
                                                        let mut fields = serde_json::Map::new();
                                                        fields.insert(
                                                            "scan_status".to_string(),
                                                            "masscan_xml_parsing_complete".into(),
                                                        );
                                                        fields.insert(
                                                            "xml_file".to_string(),
                                                            xml_file.clone().into(),
                                                        );
                                                        fields.insert(
                                                            "xml_observations_count".to_string(),
                                                            (xml_obs_queue.len() as i64).into(),
                                                        );
                                                        fields
                                                    },
                                                    ts: chrono::Utc::now(),
                                                    key: "masscan-xml-complete".to_string(),
                                                    raw: None,
                                                };

                                                // Emit completion observation, then queued XML observations will follow
                                                log::info!("Queued {} XML observations for emission", xml_obs_queue.len());
                                                return Some((
                                                    completion_obs,
                                                    (lines, count, child, xml_file, true, xml_obs_queue),
                                                ));
                                            }
                                            Err(e) => {
                                                log::error!("Failed to parse masscan XML with xml_parser: {}", e);
                                            }
                                        }
                                    } else {
                                        log::warn!("Masscan XML file not found: {}", xml_file);
                                    }

                                    // Keep XML file for queue processing (don't delete it)
                                    log::info!("Masscan XML file {} retained in .scans/ directory for queue processing", xml_file);
                                }
                            }
                            Err(e) => {
                                log::error!("Error waiting for masscan process: {}", e);
                            }
                        }
                        None
                    }
                    Err(e) => {
                        log::error!("Error reading masscan output: {}", e);
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
/// Supports both "open tcp 80 192.168.1.1" and "open tcp 192.168.1.1 80" as well as
/// the default output "Discovered open port 22/tcp on 10.0.0.5"
fn parse_masscan_line(line: &str, scan_id: uuid::Uuid) -> Option<Observation> {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();

    if parts.len() >= 4 && parts[0] == "open" {
        let protocol = parts[1];
        let (port_str, ip_str) =
            if parts[2].parse::<u16>().is_ok() && parts[3].parse::<IpAddr>().is_ok() {
                (parts[2], parts[3])
            } else if parts[2].parse::<IpAddr>().is_ok() && parts[3].parse::<u16>().is_ok() {
                (parts[3], parts[2])
            } else {
                return None;
            };
        let port = port_str.parse::<u16>().ok()?;
        let ip: IpAddr = ip_str.parse().ok()?;

        let mut fields = serde_json::Map::new();
        fields.insert("ip".to_string(), ip.to_string().into());
        fields.insert("port".to_string(), port.into());
        fields.insert("protocol".to_string(), protocol.into());
        fields.insert("state".to_string(), "open".into());
        fields.insert("reason".to_string(), "syn-ack".into());

        return Some(Observation {
            scan_id,
            kind: ObservationKind::Service,
            fields,
            ts: Utc::now(),
            key: format!("{}:{}/{}", ip, port, protocol),
            raw: Some(line.to_string()),
        });
    }

    if line.starts_with("Discovered open port ") {
        let rest = line.trim_start_matches("Discovered open port ");
        let mut parts = rest.split_whitespace();
        let port_proto = parts.next()?; // e.g., 22/tcp
        let _on = parts.next()?; // "on"
        let ip_str = parts.next()?; // e.g., 10.0.0.5

        let mut it = port_proto.split('/');
        let port = it.next()?.parse::<u16>().ok()?;
        let protocol = it.next().unwrap_or("tcp");
        let ip: IpAddr = ip_str.parse().ok()?;

        let mut fields = serde_json::Map::new();
        fields.insert("ip".to_string(), ip.to_string().into());
        fields.insert("port".to_string(), port.into());
        fields.insert("protocol".to_string(), protocol.into());
        fields.insert("state".to_string(), "open".into());
        fields.insert("reason".to_string(), "syn-ack".into());

        return Some(Observation {
            scan_id,
            kind: ObservationKind::Service,
            fields,
            ts: Utc::now(),
            key: format!("{}:{}/{}", ip, port, protocol),
            raw: Some(line.to_string()),
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_port_then_ip() {
        let scan_id = uuid::Uuid::nil();
        let line = "open tcp 80 192.168.1.1";
        let obs = parse_masscan_line(line, scan_id).expect("should parse");
        assert_eq!(
            obs.fields.get("ip").and_then(|v| v.as_str()),
            Some("192.168.1.1")
        );
        assert_eq!(obs.fields.get("port").and_then(|v| v.as_u64()), Some(80));
    }

    #[test]
    fn parses_ip_then_port() {
        let scan_id = uuid::Uuid::nil();
        let line = "open tcp 192.168.1.1 443";
        let obs = parse_masscan_line(line, scan_id).expect("should parse");
        assert_eq!(
            obs.fields.get("ip").and_then(|v| v.as_str()),
            Some("192.168.1.1")
        );
        assert_eq!(obs.fields.get("port").and_then(|v| v.as_u64()), Some(443));
    }

    #[test]
    fn parses_default_discovered_format() {
        let scan_id = uuid::Uuid::nil();
        let line = "Discovered open port 22/tcp on 10.0.0.5";
        let obs = parse_masscan_line(line, scan_id).expect("should parse");
        assert_eq!(
            obs.fields.get("ip").and_then(|v| v.as_str()),
            Some("10.0.0.5")
        );
        assert_eq!(obs.fields.get("port").and_then(|v| v.as_u64()), Some(22));
    }
}
