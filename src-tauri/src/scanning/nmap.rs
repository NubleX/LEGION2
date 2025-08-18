// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::core::traits::Source;
use crate::plan::Plan;
use crate::scanning::events::{EventType, ScanEvent};
use crate::scanning::models::ScanTarget;
use crate::scanning::models::{OSDetection, ScanProgress, ScanType};
use crate::shared::{ObsStream, Observation};
use crate::shared::{PortState, Protocol, ScanPort, ScanVulnerability};
use crate::utils::os::{get_nmap_binary_path, is_nmap_available};
use crate::utils::parsing::NmapParser;
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
use anyhow::{anyhow, Context, Result};
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

    async fn build_nmap_command(&self, plan: &Plan) -> (Command, String) {
        let nmap_path = get_nmap_binary_path();
        let mut cmd = Command::new(&nmap_path);

        // CRITICAL: Add scan type flags based on plan
        let scan_type_args = self.get_scan_type_args(plan);
        for arg in scan_type_args {
            cmd.arg(arg);
        }

        // Add port specification if provided
        if !plan.ports.is_empty() && plan.ports != "default" {
            cmd.arg("-p").arg(&plan.ports);
        }

        // Add extra arguments from plan
        for arg in &plan.extra {
            cmd.arg(arg);
        }

        // Detect private 10.* targets and adjust privileges/interfaces
        let targets_private = plan
            .targets
            .split(|c| c == ' ' || c == ',' || c == '\n')
            .any(|t| t.trim_start().starts_with("10."));

        if let Some(iface) = &plan.interface {
            cmd.arg("-e").arg(iface);
        }

        if targets_private {
            cmd.arg("--privileged");
        }

        // Enable verbose output for parsing
        cmd.arg("-v");

        // Generate XML output file for comprehensive parsing
        let xml_file = format!("nmap_output_{}.xml", plan.scan_id);
        cmd.arg("-oX").arg(&xml_file);

        // Add target last
        cmd.arg(&plan.targets);

        log::info!("Nmap command: {:?}", cmd);
        (cmd, xml_file)
    }

    fn get_scan_type_args(&self, plan: &Plan) -> Vec<String> {
        // Parse scan type from plan.extra or use defaults
        let mut args = Vec::new();

        // Check for scan type indicators in plan.extra
        let extra_str = plan.extra.join(" ");

        if extra_str.contains("-T4") && extra_str.contains("-F") {
            // Quick scan
            args.push("-T5".to_string());
            args.push("-A".to_string());
            args.push("-oX ../.scans/results.xml".to_string());
            args.push("-vv".to_string());
            args.push("-p-".to_string());
        } else if extra_str.contains("-A") || extra_str.contains("-sV") {
            // Comprehensive scan
            args.push("-sS".to_string());
            args.push("-sV".to_string());
            args.push("-O".to_string());
            args.push("-T4".to_string());
            args.push("-vvv".to_string());
            args.push("-oX ../.scans/results.xml".to_string());
            args.push("-p-".to_string());
            args.push("-sC".to_string());
        } else if extra_str.contains("-T2") {
            // Stealth scan
            args.push("-sS".to_string());
            args.push("-T2".to_string());
            args.push("-f".to_string());
            args.push("--randomize-hosts".to_string());
        } else {
            // Default: TCP SYN scan with normal timing
            args.push("-sS".to_string());
            args.push("-T3".to_string());
        }

        args
    }
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

fn extract_os_version(os_name: &str) -> Option<String> {
    // Try to extract version numbers from common OS patterns
    if let Some(caps) = regex::Regex::new(r"(\d+(?:\.\d+)*)").unwrap().find(os_name) {
        Some(caps.as_str().to_string())
    } else {
        None
    }
}

fn extract_os_generation(os_name: &str) -> Option<String> {
    let lower = os_name.to_lowercase();

    // Windows generations
    if lower.contains("windows 11") {
        Some("11".to_string())
    } else if lower.contains("windows 10") {
        Some("10".to_string())
    } else if lower.contains("windows 8") {
        Some("8".to_string())
    } else if lower.contains("windows 7") {
        Some("7".to_string())
    } else if lower.contains("windows vista") {
        Some("Vista".to_string())
    } else if lower.contains("windows xp") {
        Some("XP".to_string())
    } else if lower.contains("lts") {
        Some("LTS".to_string())
    } else {
        extract_os_version(os_name)
    }
}

#[async_trait::async_trait]
impl Source for NmapScanner {
    fn name(&self) -> &'static str {
        "nmap"
    }

    async fn start(&self, plan: &Plan) -> anyhow::Result<ObsStream> {
        let (mut cmd, xml_file) = self.build_nmap_command(plan).await;
        let mut child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        use futures::stream;
        use tokio::io::{AsyncBufReadExt, BufReader};

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to get stdout"))?;
        let reader = BufReader::new(stdout);
        let lines = reader.lines();

        let scan_id = plan.scan_id;

        // Use stateful parser with Arc<Mutex<>> to allow sharing across async closure
        use std::sync::{Arc, Mutex};
        let parser = Arc::new(Mutex::new(NmapParser::new(scan_id)));

        let stream = stream::unfold(
            (lines, parser, child, xml_file.clone(), false),
            move |(mut lines, parser, mut child, xml_file, xml_parsed)| async move {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        log::info!("Nmap output line: {}", line);
                        let obs = {
                            let mut parser_guard = parser.lock().unwrap();
                            parser_guard.parse_line(&line)
                        };

                        if let Some(observation) = obs {
                            log::info!("Parsed nmap observation: {:?}", observation);
                            Some((observation, (lines, parser, child, xml_file, xml_parsed)))
                        } else {
                            // Even if no observation was created, continue parsing
                            // This happens for lines that set context but don't create observations
                            Some((
                                Observation {
                                    scan_id,
                                    kind: crate::shared::ObservationKind::Metric,
                                    fields: {
                                        let mut fields = serde_json::Map::new();
                                        fields
                                            .insert("nmap_output".to_string(), line.clone().into());
                                        fields
                                    },
                                    ts: chrono::Utc::now(),
                                    key: "nmap-output".to_string(),
                                    raw: Some(line),
                                },
                                (lines, parser, child, xml_file, xml_parsed),
                            ))
                        }
                    }
                    Ok(None) => {
                        log::info!("Nmap stream ended - waiting for process to complete");
                        // Wait for the child process to finish
                        match child.wait().await {
                            Ok(status) => {
                                log::info!("Nmap process completed with status: {}", status);

                                // Parse XML output for comprehensive host information
                                if !xml_parsed {
                                    log::info!("Reading XML output from: {}", xml_file);
                                    match tokio::fs::read_to_string(&xml_file).await {
                                        Ok(xml_content) => {
                                            log::info!("Successfully read XML file, parsing comprehensive host data");
                                            let observations = {
                                                let parser_guard = parser.lock().unwrap();
                                                parser_guard.parse_host_xml(&xml_content)
                                            };
                                            match observations {
                                                Ok(observations) => {
                                                    log::info!("Parsed {} comprehensive observations from XML", observations.len());
                                                    // Return the first observation and continue with the rest
                                                    if let Some(first_obs) =
                                                        observations.into_iter().next()
                                                    {
                                                        // Note: This is simplified - in a full implementation you'd want to emit all observations
                                                        return Some((
                                                            first_obs,
                                                            (lines, parser, child, xml_file, true),
                                                        ));
                                                    }
                                                }
                                                Err(e) => {
                                                    log::error!("Failed to parse nmap XML: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log::error!(
                                                "Failed to read XML output file {}: {}",
                                                xml_file,
                                                e
                                            );
                                        }
                                    }

                                    // Clean up XML file
                                    let _ = tokio::fs::remove_file(&xml_file).await;
                                }
                            }
                            Err(e) => {
                                log::error!("Error waiting for nmap process: {}", e);
                            }
                        }
                        None
                    }
                    Err(e) => {
                        log::error!("Error reading nmap output: {}", e);
                        // Kill the child process if there was an error
                        let _ = child.kill().await;
                        None
                    }
                }
            },
        );

        Ok(Box::pin(stream))
    }
}
