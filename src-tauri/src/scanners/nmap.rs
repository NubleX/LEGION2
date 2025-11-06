// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::commands::engine_commands;
use crate::plan::Plan;
use crate::scanners::events::{EventType, ScanEvent};
use crate::shared::shared::{ObsStream, Observation, ObservationKind};
use crate::shared::shared::{PortState, Protocol, ScanPort, ScanVulnerability};
use crate::shared::ScanTypes::{ScanProgress, ScanTarget};
use crate::shared::traits::Source;
use crate::shared::ScanTypes::ScanType;
use crate::utils::parsing::NmapParser;
use crate::utils::xml_parser::XmlParser;
use crate::shared::ScanTypes::OSDetection;
use crate::os::{get_nmap_binary_path, is_nmap_available};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio_stream::StreamExt;

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

    /// Check if the current process is running as root
    fn is_running_as_root() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false // Windows doesn't need root for network scanning (uses raw sockets differently)
        }
    }

    /// Determine if the scan requires root privileges
    fn needs_root_privileges(plan: &Plan) -> bool {
        // Network scanning (especially local networks) requires root for:
        // - ARP ping scans
        // - Raw socket access
        // - OS detection (-O flag)
        // - Most scan types except basic TCP connect scans

        // Check if scanning local networks (10.x, 192.168.x, 172.16-31.x)
        let is_local_network = plan.targets.contains("10.")
            || plan.targets.contains("192.168.")
            || plan.targets.contains("172.16.")
            || plan.targets.contains("172.17.")
            || plan.targets.contains("172.18.")
            || plan.targets.contains("172.19.")
            || plan.targets.contains("172.2")
            || plan.targets.contains("172.30.")
            || plan.targets.contains("172.31.");

        // Check if using privileged scan types
        let has_privileged_flags = plan.extra.iter().any(|arg| {
            arg == "-O" || arg == "-sS" || arg == "-sU" || arg == "-sN"
            || arg == "-sF" || arg == "-sX" || arg == "-A"
        });

        // Assume we need root if scanning local networks or using privileged flags
        is_local_network || has_privileged_flags || plan.interface.is_some()
    }

    /// Auto-detect the network interface for local 10.x networks
    fn detect_local_interface() -> Result<String, String> {
        // Try to find interface with 10.x IP address
        let output = std::process::Command::new("ip")
            .args(&["-o", "addr", "show"])
            .output()
            .map_err(|e| format!("Failed to run ip command: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Look for lines with "inet 10." to find the interface
        for line in stdout.lines() {
            if line.contains("inet 10.") {
                // Extract interface name (first field after index)
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    return Ok(parts[1].to_string());
                }
            }
        }

        Err("No interface with 10.x IP address found".to_string())
    }

    async fn build_nmap_command(&self, plan: &Plan) -> (Command, String) {
        let nmap_path = get_nmap_binary_path();

        // Check if we need elevated privileges (network scanning typically does)
        let needs_elevation = Self::needs_root_privileges(plan);

        let mut cmd = if needs_elevation && !Self::is_running_as_root() {
            // Use pkexec to elevate only nmap, not the entire app
            log::info!("Elevating nmap privileges using pkexec");
            let mut elevated_cmd = Command::new("pkexec");
            elevated_cmd.arg("--disable-internal-agent"); // Don't show GUI prompt in some environments
            elevated_cmd.arg(&nmap_path);
            elevated_cmd
        } else {
            Command::new(&nmap_path)
        };

        // Add extra arguments from plan first (these contain scan type flags like -T4, -F, etc.)
        for arg in &plan.extra {
            cmd.arg(arg);
        }

        // Check if extra_args already specifies ports with -p (not -F, since -p takes precedence)
        let extra_has_explicit_port_spec = plan.extra.iter().any(|arg| {
            arg == "-p" || arg.starts_with("-p")
        });

        // Port handling:
        // - Empty = use nmap's default (top 1000 most common ports) - fast for host discovery
        // - "-" = use -p- (all 65535 ports) - comprehensive scanning
        // - Other = use user-specified port range
        if !extra_has_explicit_port_spec {
            let ports = plan.ports.trim();
            if ports == "-" {
                // Comprehensive: scan all 65535 ports
                cmd.arg("-p-");
            } else if !ports.is_empty() {
                // Use the specific port range provided by user
                cmd.arg("-p").arg(ports);
            }
            // If empty, don't add -p flag - nmap will use its default top 1000 ports (fast)
        }
        // If extra_has_explicit_port_spec is true, -p is already in extra_args, don't add another

        // Detect private 10.* targets and adjust privileges/interfaces
        let targets_private = plan
            .targets
            .split(|c| c == ' ' || c == ',' || c == '\n')
            .any(|t| t.trim_start().starts_with("10."));

        // Auto-detect network interface if not specified
        if let Some(iface) = &plan.interface {
            // User specified interface explicitly
            cmd.arg("-e").arg(iface);
        } else if targets_private {
            // For 10.x networks, try to auto-detect the interface
            if let Ok(detected_iface) = Self::detect_local_interface() {
                log::info!("Auto-detected network interface: {}", detected_iface);
                cmd.arg("-e").arg(detected_iface);
            } else {
                log::warn!("Could not auto-detect interface for 10.x network - scan may fail");
            }
        }

        // Don't need --privileged flag when using pkexec for elevation
        // pkexec already runs nmap as root

        // Enable verbose output for parsing
        cmd.arg("-v");

        // Use /tmp for XML output when running with pkexec (root can write there)
        let scan_dir = if needs_elevation && !Self::is_running_as_root() {
            // Running with pkexec - use /tmp which is writable by root
            std::path::PathBuf::from("/tmp/legion2_scans")
        } else {
            // Running normally - use local .scans directory
            std::path::PathBuf::from(".scans")
        };

        // Ensure scan directory exists and is writable
        std::fs::create_dir_all(&scan_dir).unwrap_or_else(|e| {
            log::warn!("Failed to create scan directory {:?}: {}", scan_dir, e);
        });

        // Set directory permissions to 0777 so both root and user can write
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&scan_dir) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o777);
                let _ = std::fs::set_permissions(&scan_dir, perms);
            }
        }

        // Generate XML output file in scan directory
        let xml_file = scan_dir.join(format!(
            "nmap_{}_{}.xml",
            plan.scan_id.to_string().replace("-", "_"),
            chrono::Utc::now().timestamp()
        ));
        cmd.arg("-oX").arg(&xml_file);

        let xml_file_str = xml_file.to_string_lossy().to_string();

        // Add target last
        cmd.arg(&plan.targets);

        // Log the full command for debugging
        log::info!("Nmap command: {:?}", cmd);
        log::info!("Nmap will scan targets: {} on ports: {}", plan.targets, plan.ports);
        log::info!("XML output will be saved to: {}", xml_file_str);
        (cmd, xml_file_str)
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

        // Capture stderr for error logging
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("Failed to get stderr"))?;
        let stderr_reader = BufReader::new(stderr);

        // Spawn task to log stderr
        tokio::spawn(async move {
            let mut stderr_lines = stderr_reader.lines();
            while let Ok(Some(line)) = stderr_lines.next_line().await {
                log::error!("[nmap stderr] {}", line);
            }
        });

        let scan_id = plan.scan_id;

        // Use stateful parser with Arc<Mutex<>> to allow sharing across async closure
        use std::sync::{Arc, Mutex};
        let parser = Arc::new(Mutex::new(NmapParser::new(scan_id)));

        let stream = stream::unfold(
            (lines, parser, child, xml_file.clone(), false, Vec::new()),
            move |(mut lines, parser, mut child, xml_file, xml_parsed, mut xml_obs_queue)| async move {
                // First, emit any queued XML observations
                if let Some(queued_obs) = xml_obs_queue.pop() {
                    return Some((queued_obs, (lines, parser, child, xml_file, xml_parsed, xml_obs_queue)));
                }

                match lines.next_line().await {
                    Ok(Some(line)) => {
                        if engine_commands::is_scan_cancelled() {
                            log::warn!("Nmap scan cancelled by user");
                            let _ = child.kill().await;
                            let mut fields = serde_json::Map::new();
                            fields.insert("status".to_string(), "cancelled".into());
                            let cancel_obs = Observation {
                                scan_id,
                                kind: ObservationKind::Metric,
                                fields,
                                ts: chrono::Utc::now(),
                                key: "scan-status".to_string(),
                                raw: None,
                            };
                            return Some((
                                cancel_obs,
                                (lines, parser, child, xml_file, xml_parsed, xml_obs_queue),
                            ));
                        }
                        log::info!("Nmap output line: {}", line);
                        let obs = {
                            let mut parser_guard = parser.lock().unwrap();
                            parser_guard.parse_line(&line)
                        };

                        if let Some(observation) = obs {
                            log::info!("Parsed nmap observation: {:?}", observation);
                            Some((observation, (lines, parser, child, xml_file, xml_parsed, xml_obs_queue)))
                        } else {
                            // Even if no observation was created, continue parsing
                            // This happens for lines that set context but don't create observations
                            Some((
                                Observation {
                                    scan_id,
                                    kind: ObservationKind::Metric,
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
                                (lines, parser, child, xml_file, xml_parsed, xml_obs_queue),
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
                                            Ok(mut xml_observations) => {
                                                log::info!("XML parser generated {} comprehensive observations", xml_observations.len());

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
                                                            "xml_parsing_complete".into(),
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
                                                    key: "nmap-xml-complete".to_string(),
                                                    raw: None,
                                                };

                                                // Emit completion observation, then queued XML observations will follow
                                                log::info!("Queued {} XML observations for emission", xml_obs_queue.len());
                                                return Some((
                                                    completion_obs,
                                                    (lines, parser, child, xml_file, true, xml_obs_queue),
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
