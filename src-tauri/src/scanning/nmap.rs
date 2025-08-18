// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::core::traits::Source;
use crate::plan::Plan;
use crate::scanning::events::{EventType, ScanEvent};
use crate::scanning::models::{OSDetection, ScanProgress, ScanTarget, ScanType};
use crate::shared::{ObsStream, Observation, ObservationKind};
use crate::shared::{PortState, Protocol, ScanPort, ScanVulnerability};
use crate::utils::os::{get_nmap_binary_path, is_nmap_available};
use crate::utils::parsing::NmapParser;
use crate::utils::xml_parser::XmlParser;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

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
        if !plan.ports.is_empty() && plan.ports != "-1000" {
            cmd.arg("-p").arg(&plan.ports);
        }

        // Add extra arguments from plan
        for arg in &plan.extra {
            cmd.arg(arg);
        }

        // Enable verbose output for parsing
        cmd.arg("-v");

        // Ensure .scans directory exists
        std::fs::create_dir_all(".scans").unwrap_or_else(|e| {
            log::warn!("Failed to create .scans directory: {}", e);
        });

        // Generate XML output file in .scans directory for comprehensive parsing
        let xml_file = format!(
            ".scans/nmap_{}_{}.xml",
            plan.scan_id.to_string().replace("-", "_"),
            chrono::Utc::now().timestamp()
        );
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
            args.push("-oX .scans/results.xml".to_string());
            args.push("-vv".to_string());
            args.push("-p-".to_string());
        } else if extra_str.contains("-A") || extra_str.contains("-sV") {
            // Comprehensive scan
            args.push("-sS".to_string());
            args.push("-sV".to_string());
            args.push("-O".to_string());
            args.push("-T4".to_string());
            args.push("-vvv".to_string());
            args.push("-oX .scans/results.xml".to_string());
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

// OS detection logic moved to xml_parser.rs for proper separation of concerns

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

                                // Delegate XML parsing to xml_parser module
                                if !xml_parsed {
                                    log::info!(
                                        "Delegating XML parsing to xml_parser module: {}",
                                        xml_file
                                    );
                                    let xml_path = Path::new(&xml_file);

                                    if xml_path.exists() {
                                        let xml_parser = XmlParser::new(scan_id);
                                        match xml_parser.parse_nmap_xml(xml_path) {
                                            Ok(xml_observations) => {
                                                log::info!("XML parser generated {} comprehensive observations", xml_observations.len());

                                                // Create a completion observation indicating XML parsing is done
                                                let completion_obs = Observation {
                                                    scan_id,
                                                    kind: ObservationKind::Metric,
                                                    fields: {
                                                        let mut fields = serde_json::Map::new();
                                                        fields.insert(
                                                            "scan_status".to_string(),
                                                            "xml_parsing_complete".into(),
                                                        );
                                                        fields.insert(
                                                            "xml_file".to_string(),
                                                            xml_file.clone().into(),
                                                        );
                                                        fields.insert(
                                                            "xml_observations_count".to_string(),
                                                            (xml_observations.len() as i64).into(),
                                                        );
                                                        fields
                                                    },
                                                    ts: chrono::Utc::now(),
                                                    key: "nmap-xml-complete".to_string(),
                                                    raw: None,
                                                };

                                                // Note: In a full implementation, we'd need to emit all XML observations
                                                // For now, we just signal that XML file is ready for processing
                                                return Some((
                                                    completion_obs,
                                                    (lines, parser, child, xml_file, true),
                                                ));
                                            }
                                            Err(e) => {
                                                log::error!(
                                                    "Failed to parse nmap XML with xml_parser: {}",
                                                    e
                                                );
                                            }
                                        }
                                    } else {
                                        log::warn!("XML file not found: {}", xml_file);
                                    }

                                    // Keep XML file for queue processing (don't delete it)
                                    log::info!("XML file {} retained in .scans/ directory for queue processing", xml_file);
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
