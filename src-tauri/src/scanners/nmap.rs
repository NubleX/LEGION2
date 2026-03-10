// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::commands::engine_commands;
use crate::plan::Plan;
use crate::shared::shared::{ObsStream, Observation, ObservationKind, ScanProgress, ScanStatus};
use crate::shared::shared::{ScanPort, ScanVulnerability};
use crate::shared::traits::Source;
use crate::utils::parsing::NmapParser;
use crate::utils::xml_parser::XmlParser;
use crate::shared::ScanTypes::OSDetection;
use crate::os::{get_nmap_binary_path};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
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

// ScanStatus is now imported from shared::shared

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

    /// Auto-detect the network interface for local networks, skipping VPN/virtual interfaces.
    fn detect_local_interface() -> Result<String, String> {
        let output = std::process::Command::new("ip")
            .args(&["-o", "addr", "show"])
            .output()
            .map_err(|e| format!("Failed to run ip command: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            if line.contains("inet 10.") || line.contains("inet 192.168.") || line.contains("inet 172.") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    let iface = parts[1];
                    // Skip VPN, tunnel, and virtual interfaces
                    if iface != "lo"
                        && !iface.contains("wg")
                        && !iface.contains("tun")
                        && !iface.contains("docker")
                        && !iface.contains("virbr")
                        && !iface.contains("veth")
                    {
                        return Ok(iface.to_string());
                    }
                }
            }
        }

        Err("No suitable local network interface found".to_string())
    }

    async fn build_nmap_command(&self, plan: &Plan) -> (Command, String) {
        let nmap_path = get_nmap_binary_path();

        // Run nmap directly — privileged access is handled via cap_net_raw (set by Fix Permissions).
        // If caps are not set and not running as root, nmap gracefully falls back to TCP connect scan.
        if Self::needs_root_privileges(plan) && !Self::is_running_as_root() {
            log::info!("nmap: running without root — cap_net_raw required for SYN/ARP scans. Use Fix Permissions if scanning fails.");
        }

        let mut cmd = Command::new(&nmap_path);

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

        // Skip reverse DNS resolution — prevents hangs on networks without reverse DNS
        cmd.arg("-n");

        // Enable verbose output for parsing
        cmd.arg("-v");

        // Add NSE scripts if specified
        if let Some(ref scripts) = plan.nse_scripts {
            if !scripts.is_empty() {
                // Join scripts with comma: --script "script1,script2,script3"
                let script_list = scripts.join(",");
                cmd.arg("--script").arg(&script_list);
            }
        }

        // Add NSE script arguments if specified
        if let Some(ref script_args) = plan.nse_script_args {
            if !script_args.is_empty() {
                // Format: --script-args 'script1.arg1=value1,script2.arg2=value2'
                let args_list: Vec<String> = script_args
                    .iter()
                    .map(|(key, value)| format!("{}={}", key, value))
                    .collect();
                let args_string = args_list.join(",");
                cmd.arg("--script-args").arg(&args_string);
            }
        }

        // Use /tmp for XML output — always writable regardless of user/root
        let scan_dir = std::env::temp_dir().join("legion2_scans");

        std::fs::create_dir_all(&scan_dir).unwrap_or_else(|e| {
            log::warn!("Failed to create scan directory {:?}: {}", scan_dir, e);
        });

        // Generate XML output file in scan directory
        let xml_file = scan_dir.join(format!(
            "nmap_{}_{}.xml",
            plan.scan_id.to_string().replace("-", "_"),
            chrono::Utc::now().timestamp()
        ));
        cmd.arg("-oX").arg(&xml_file);

        let xml_file_str = xml_file.to_string_lossy().to_string();

        // Add targets as separate arguments — passing the whole string as one arg causes
        // nmap to treat it as a single unresolvable hostname and attempt DNS resolution.
        for target in plan.targets.split(|c: char| c == ' ' || c == ',' || c == '\n') {
            let t = target.trim();
            if !t.is_empty() {
                cmd.arg(t);
            }
        }

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

        // Register PID so cancel kills this process immediately
        if let Some(pid) = child.id() {
            engine_commands::register_child_pid(pid).await;
        }

        use futures::stream;
        use tokio::io::{AsyncBufReadExt, BufReader};

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to get stdout"))?;
        let reader = BufReader::new(stdout);
        let lines = reader.lines();

        // Pipe stderr through a channel so nmap progress lines appear in the UI terminal.
        // nmap writes status lines like "Initiating SYN Stealth Scan at 06:49" to stderr.
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("Failed to get stderr"))?;

        let (stderr_tx, stderr_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            let mut stderr_lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = stderr_lines.next_line().await {
                log::debug!("[nmap stderr] {}", line);
                let _ = stderr_tx.send(line);
            }
        });

        let scan_id = plan.scan_id;
        let targets = plan.targets.clone();
        let start_time = chrono::Utc::now();
        let mut unique_hosts = std::collections::HashSet::new();
        let mut ports_found = 0u64;
        let nmap_pid = child.id();

        // Use stateful parser with Arc<Mutex<>> to allow sharing across async closure
        use std::sync::{Arc, Mutex};
        let parser = Arc::new(Mutex::new(NmapParser::new(scan_id)));

        let stream = stream::unfold(
            (lines, parser, child, xml_file.clone(), false, Vec::new(), start_time, unique_hosts, ports_found, targets.clone(), stderr_rx),
            move |(mut lines, parser, mut child, xml_file, xml_parsed, mut xml_obs_queue, start_time, mut unique_hosts, mut ports_found, targets, mut stderr_rx)| async move {
                // First, emit any queued XML observations
                if let Some(queued_obs) = xml_obs_queue.pop() {
                    return Some((queued_obs, (lines, parser, child, xml_file, xml_parsed, xml_obs_queue, start_time, unique_hosts, ports_found, targets.clone(), stderr_rx)));
                }

                tokio::select! {
                    biased;
                    // Emit nmap stderr progress lines (status updates) to the UI terminal
                    Some(stderr_line) = stderr_rx.recv() => {
                        let mut fields = serde_json::Map::new();
                        fields.insert("nmap_output".to_string(), stderr_line.clone().into());
                        let obs = Observation {
                            scan_id,
                            kind: ObservationKind::Metric,
                            fields,
                            ts: chrono::Utc::now(),
                            key: "nmap-progress".to_string(),
                            raw: Some(stderr_line),
                        };
                        return Some((obs, (lines, parser, child, xml_file, xml_parsed, xml_obs_queue, start_time, unique_hosts, ports_found, targets.clone(), stderr_rx)));
                    }
                    result = lines.next_line() => match result {
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
                                (lines, parser, child, xml_file, xml_parsed, xml_obs_queue, start_time, unique_hosts, ports_found, targets.clone(), stderr_rx),
                            ));
                        }
                        log::info!("Nmap output line: {}", line);
                        let obs = {
                            let mut parser_guard = parser.lock().unwrap();
                            parser_guard.parse_line(&line)
                        };

                        if let Some(observation) = obs {
                            log::info!("Parsed nmap observation: {:?}", observation);
                            
                            // Track hosts and ports for progress
                            if observation.kind == ObservationKind::Host {
                                if let Some(ip_str) = observation.fields.get("ip").and_then(|v| v.as_str()) {
                                    unique_hosts.insert(ip_str.to_string());
                                }
                            } else if observation.kind == ObservationKind::Service {
                                ports_found += 1;
                                if let Some(ip_str) = observation.fields.get("ip").and_then(|v| v.as_str()) {
                                    unique_hosts.insert(ip_str.to_string());
                                }
                            }
                            
                            // Emit progress observation every 10 services or on first service
                            if observation.kind == ObservationKind::Service && (ports_found % 10 == 0 || ports_found == 1) {
                                let elapsed = (chrono::Utc::now() - start_time).num_seconds() as u64;
                                let progress_obs = create_nmap_progress_observation(
                                    scan_id,
                                    ports_found,
                                    unique_hosts.len() as u32,
                                    elapsed,
                                    &targets,
                                );
                                // Emit both the service observation and progress
                                xml_obs_queue.push(observation);
                                Some((progress_obs, (lines, parser, child, xml_file, xml_parsed, xml_obs_queue, start_time, unique_hosts, ports_found, targets.clone(), stderr_rx)))
                            } else {
                                Some((observation, (lines, parser, child, xml_file, xml_parsed, xml_obs_queue, start_time, unique_hosts, ports_found, targets.clone(), stderr_rx)))
                            }
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
                                (lines, parser, child, xml_file, xml_parsed, xml_obs_queue, start_time, unique_hosts, ports_found, targets.clone(), stderr_rx),
                            ))
                        }
                    }
                    Ok(None) => {
                        log::info!("Nmap stream ended - waiting for process to complete");
                        // Wait for the child process to finish
                        match child.wait().await {
                            Ok(status) => {
                                log::info!("Nmap process completed with status: {}", status);
                                if let Some(pid) = nmap_pid {
                                    engine_commands::unregister_child_pid(pid).await;
                                }

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
                                                    (lines, parser, child, xml_file, true, xml_obs_queue, start_time, unique_hosts, ports_found, targets.clone(), stderr_rx),
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
                        let _ = child.kill().await;
                        None
                    }
                    } // end select! result arm match
                } // end select!
            },
        );

        Ok(Box::pin(stream))
    }
}

/// Create a progress observation for nmap using ScanProgress struct
fn create_nmap_progress_observation(
    scan_id: uuid::Uuid,
    ports_found: u64,
    hosts_discovered: u32,
    elapsed_time: u64,
    targets: &str,
) -> Observation {
    let now = chrono::Utc::now();
    let progress = ScanProgress {
        scan_id: scan_id.to_string(),
        status: ScanStatus::Running,
        percentage: 0.0, // Nmap doesn't provide percentage in real-time
        stage: "service_detection".to_string(),
        targets_completed: 0,
        targets_total: 1,
        hosts_found: hosts_discovered as usize,
        services_found: ports_found as usize,
        eta_seconds: None,
        started_at: now - chrono::Duration::seconds(elapsed_time as i64),
        updated_at: now,
        rate: None,
        details: {
            let mut details = std::collections::HashMap::new();
            details.insert("ports_found".to_string(), ports_found.into());
            details.insert("hosts_discovered".to_string(), hosts_discovered.into());
            details.insert("targets".to_string(), targets.into());
            details.insert("scanner".to_string(), "nmap".into());
            details
        },
        progress: 0.0,
        current_target: Some(targets.to_string()),
        hosts_discovered,
        ports_found: ports_found as u32,
        vulnerabilities: 0,
        elapsed_time,
        estimated_remaining: None,
        message: Some(format!("Nmap found {} services on {} hosts", ports_found, hosts_discovered)),
        start_time: now - chrono::Duration::seconds(elapsed_time as i64),
        current_phase: "service_detection".to_string(),
    };

    // Serialize ScanProgress to JSON and include in observation fields
    let mut fields = serde_json::Map::new();
    fields.insert("scan_progress".to_string(), serde_json::to_value(&progress).unwrap_or(serde_json::Value::Null));
    fields.insert("scan_status".to_string(), "running".into());
    fields.insert("ports_found".to_string(), ports_found.into());
    fields.insert("hosts_discovered".to_string(), hosts_discovered.into());

    Observation {
        scan_id,
        kind: ObservationKind::Metric,
        fields,
        ts: now,
        key: format!("nmap-progress-{}", ports_found),
        raw: None,
    }
}
