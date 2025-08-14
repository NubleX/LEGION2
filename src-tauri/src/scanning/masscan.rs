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
use crate::shared::{ObsStream, Observation, ObservationKind};

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
        let bin = get_masscan_binary_path()?;
        Ok(Self {
            bin,
            options: MasscanOptions::default(),
        })
    }

    pub fn with_options(options: MasscanOptions) -> Result<Self> {
        let bin = get_masscan_binary_path()?;
        Ok(Self { bin, options })
    }

    async fn check_masscan_available(&self) -> bool {
        Command::new(&self.bin)
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false)
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
        cmd.arg("-p")
            .arg(&plan.ports)
            .arg(&plan.targets)
            .args(["--open", "--wait", "0"])
            .args(["--rate", &plan.rate.unwrap_or(1000).to_string()])
            .arg("--output-format")
            .arg("list")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = cmd.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to get stdout"))?;
        let reader = BufReader::new(stdout);
        let lines = reader.lines();

        let scan_id = plan.scan_id;
        let mut discovered_count = 0u64;

        let stream = stream::unfold(
            (lines, discovered_count),
            move |(mut lines, mut count)| async move {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        if let Some(obs) = parse_masscan_line(&line, scan_id) {
                            count += 1;
                            // Create a progress observation every 10 discoveries
                            if count % 10 == 0 {
                                let progress_obs =
                                    create_progress_observation(&line, scan_id, count);
                                Some((progress_obs, (lines, count)))
                            } else {
                                Some((obs, (lines, count)))
                            }
                        } else {
                            // Skip this line and continue
                            Some((
                                Observation {
                                    scan_id,
                                    kind: ObservationKind::Metric,
                                    fields: {
                                        let mut fields = serde_json::Map::new();
                                        fields.insert(
                                            "message".to_string(),
                                            format!("Masscan output: {}", line).into(),
                                        );
                                        fields
                                    },
                                    ts: Utc::now(),
                                    key: "masscan-output".to_string(),
                                    raw: Some(line),
                                },
                                (lines, count),
                            ))
                        }
                    }
                    _ => None,
                }
            },
        );

        Ok(stream.boxed())
    }
}

/// Create a progress observation for masscan using ScanProgress
fn create_progress_observation(
    line: &str,
    scan_id: uuid::Uuid,
    discovered_count: u64,
) -> Observation {
    use chrono::Utc;
    use std::collections::HashMap;

    let now = Utc::now();
    let progress_percentage = (discovered_count as f32 * 0.1).min(90.0); // Estimate progress, cap at 90%

    let progress = ScanProgress {
        scan_id: scan_id.to_string(),
        status: crate::scanning::models::ScanStatus::Running,
        percentage: progress_percentage,
        stage: "Port Discovery".to_string(),
        targets_completed: 0, // Masscan doesn't track individual targets this way
        targets_total: 1,     // Usually scanning one network range
        hosts_found: 0,       // This would need to be tracked separately for hosts
        services_found: discovered_count as usize,
        eta_seconds: None,
        started_at: now, // Would ideally be tracked from scan start
        updated_at: now,
        rate: None, // Could calculate based on time elapsed
        details: HashMap::new(),

        // Additional fields for compatibility
        progress: progress_percentage,
        current_target: None,
        hosts_discovered: 0, // Masscan finds services, not just hosts
        ports_found: discovered_count as u32,
        vulnerabilities: 0,
        elapsed_time: 0, // Would need to track actual elapsed time
        estimated_remaining: None,
        message: Some(format!("Discovered {} services", discovered_count)),
        start_time: now,
        current_phase: "Port Discovery".to_string(),
    };

    Observation {
        scan_id,
        kind: ObservationKind::Metric,
        fields: {
            let mut fields = serde_json::Map::new();
            fields.insert(
                "progress".to_string(),
                serde_json::to_value(&progress).unwrap_or_default(),
            );
            fields.insert("discovered_count".to_string(), discovered_count.into());
            fields
        },
        ts: Utc::now(),
        key: "masscan-progress".to_string(),
        raw: Some(line.to_string()),
    }
}

fn parse_masscan_line(line: &str, scan_id: uuid::Uuid) -> Option<Observation> {
    // Parse masscan output format: "Discovered open port 22/tcp on 192.168.1.1"
    if !line.starts_with("Discovered open port ") {
        return None;
    }

    let rest = line.trim_start_matches("Discovered open port ");
    let mut parts = rest.split_whitespace();

    let port_proto = parts.next()?; // e.g., "22/tcp"
    let _on = parts.next()?; // "on"
    let ip = parts.next()?; // e.g., "192.168.1.1"

    // Parse port/protocol
    let mut port_parts = port_proto.split('/');
    let port: u16 = port_parts.next()?.parse().ok()?;
    let protocol = port_parts.next().unwrap_or("tcp").to_string();

    let ip_addr: IpAddr = ip.parse().ok()?;

    let mut fields = serde_json::Map::new();
    fields.insert(
        "ip".to_string(),
        serde_json::Value::String(ip_addr.to_string()),
    );
    fields.insert(
        "port".to_string(),
        serde_json::Value::Number(serde_json::Number::from(port)),
    );
    fields.insert("protocol".to_string(), serde_json::Value::String(protocol));
    fields.insert(
        "reason".to_string(),
        serde_json::Value::String("open".to_string()),
    );

    Some(Observation {
        scan_id,
        kind: ObservationKind::Service,
        fields,
        ts: Utc::now(),
        key: format!("service-{}:{}", ip_addr, port),
        raw: Some(line.to_string()),
    })
}
