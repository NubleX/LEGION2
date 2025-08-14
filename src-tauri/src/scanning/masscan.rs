// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use futures::{stream, StreamExt};
use chrono::Utc;
use std::path::PathBuf;

use crate::core::types::{Observation, ObservationKind, ObsStream, Plan};
use crate::core::traits::Source;
use crate::scanning::models::ScanProgress;

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
        cmd.arg("-p").arg(&plan.ports)
           .arg(&plan.targets)
           .args(["--open", "--wait", "0"])
           .args(["--rate", &plan.rate.unwrap_or(1000).to_string()])
           .arg("--output-format").arg("list")
           .stdout(Stdio::piped())
           .stderr(Stdio::null());

        let mut child = cmd.spawn()?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("Failed to get stdout"))?;
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        let scan_id = plan.scan_id;
        let stream = stream::unfold(lines, move |mut lines| async move {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(obs) = parse_masscan_line(&line, scan_id) {
                        Some((obs, lines))
                    } else {
                        // Skip this line and continue
                        Some((
                            Observation {
                                scan_id,
                                kind: ObservationKind::Metric,
                                fields: {
                                    let mut fields = serde_json::Map::new();
                                    fields.insert("message".to_string(), format!("Masscan output: {}", line).into());
                                    fields
                                },
                                ts: Utc::now(),
                                key: "masscan-output".to_string(),
                                raw: Some(line),
                            },
                            lines
                        ))
                    }
                }
                _ => None,
            }
        });

        Ok(stream.boxed())
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
    fields.insert("ip".to_string(), serde_json::Value::String(ip_addr.to_string()));
    fields.insert("port".to_string(), serde_json::Value::Number(serde_json::Number::from(port)));
    fields.insert("protocol".to_string(), serde_json::Value::String(protocol));
    fields.insert("reason".to_string(), serde_json::Value::String("open".to_string()));
    
    Some(Observation {
        scan_id,
        kind: ObservationKind::Service,
        fields,
        ts: Utc::now(),
        key: format!("service-{}:{}", ip_addr, port),
        raw: Some(line.to_string()),
    })
}