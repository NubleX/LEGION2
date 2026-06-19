// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::plan::Plan;
use crate::shared::scan_types::PortRange;
use crate::shared::shared::{PortState, Protocol};
use crate::network::network::parse_target_specification;
use crate::database::Db;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

/// Parse scan ID from optional string, generating a new UUID if None
fn parse_scan_id(scan_id: Option<String>) -> Result<Uuid, String> {
    Ok(scan_id
        .map(|s| Uuid::parse_str(&s))
        .transpose()
        .map_err(|e| format!("Invalid UUID: {}", e))?
        .unwrap_or_else(Uuid::new_v4))
}

/// Create a masscan plan using the builder pattern
#[tauri::command]
pub fn create_masscan_plan(
    scan_id: Option<String>,
    targets: String,
    ports: String,
    rate: Option<u64>,
    interface: Option<String>,
) -> Result<Plan, String> {
    let scan_id = parse_scan_id(scan_id)?;

    let mut plan = Plan::masscan(scan_id, targets, ports, rate);
    if let Some(iface) = interface {
        plan = plan.with_interface(iface);
    }
    Ok(plan)
}

/// Create an nmap plan using the builder pattern
#[tauri::command]
pub fn create_nmap_plan(
    scan_id: Option<String>,
    targets: String,
    ports: String,
    extra_args: Vec<String>,
    interface: Option<String>,
) -> Result<Plan, String> {
    let scan_id = parse_scan_id(scan_id)?;

    let mut plan = Plan::nmap(scan_id, targets, ports, extra_args);
    if let Some(iface) = interface {
        plan = plan.with_interface(iface);
    }
    Ok(plan)
}

/// Create a comprehensive scan plan using the builder pattern
#[tauri::command]
pub fn create_comprehensive_plan(
    scan_id: Option<String>,
    targets: String,
    ports: String,
    interface: Option<String>,
) -> Result<Plan, String> {
    let scan_id = parse_scan_id(scan_id)?;

    let mut plan = Plan::comprehensive(scan_id, targets, ports);
    if let Some(iface) = interface {
        plan = plan.with_interface(iface);
    }
    Ok(plan)
}

/// Create an OS detection plan using the builder pattern
#[tauri::command]
pub fn create_os_detection_plan(
    scan_id: Option<String>,
    targets: String,
    interface: Option<String>,
) -> Result<Plan, String> {
    let scan_id = parse_scan_id(scan_id)?;

    let mut plan = Plan::os_detection(scan_id, targets);
    if let Some(iface) = interface {
        plan = plan.with_interface(iface);
    }
    Ok(plan)
}

/// Add OS detection to an existing plan
#[tauri::command]
pub fn plan_with_os_detection(plan: Plan) -> Result<Plan, String> {
    let enhanced_plan = plan.with_os_detection();
    Ok(enhanced_plan)
}

/// Add extra arguments to a plan
#[tauri::command]
pub fn plan_with_extra_args(plan: Plan, args: Vec<String>) -> Result<Plan, String> {
    let enhanced_plan = plan.with_extra_args(args);
    Ok(enhanced_plan)
}

/// Add modules to a plan
#[tauri::command]
pub fn plan_with_modules(plan: Plan, modules: Vec<String>) -> Result<Plan, String> {
    let enhanced_plan = plan.with_modules(modules);
    Ok(enhanced_plan)
}

/// Set scan rate for a plan
#[tauri::command]
pub fn plan_with_rate(plan: Plan, rate: u64) -> Result<Plan, String> {
    let enhanced_plan = plan.with_rate(rate);
    Ok(enhanced_plan)
}

/// Add a sink to a plan
#[tauri::command]
pub fn plan_with_sink(plan: Plan, sink_type: String) -> Result<Plan, String> {
    let enhanced_plan = plan.with_sink(sink_type);
    Ok(enhanced_plan)
}

/// Get available scan types
#[tauri::command]
pub fn get_scan_types() -> Vec<String> {
    vec![
        "Discovery".to_string(),
        "PortScan".to_string(),
        "ServiceDetection".to_string(),
        "Vulnerability".to_string(),
        "Comprehensive".to_string(),
        "Quick".to_string(),
        "Stealth".to_string(),
    ]
}

/// Get available scan timing options
#[tauri::command]
pub fn get_scan_timings() -> Vec<String> {
    vec![
        "Paranoid".to_string(),
        "Sneaky".to_string(),
        "Polite".to_string(),
        "Normal".to_string(),
        "Aggressive".to_string(),
        "Insane".to_string(),
    ]
}

/// Create a port range configuration
#[tauri::command]
pub fn create_port_range(
    start: u16,
    end: u16,
    _top_ports: Option<u16>,
) -> Result<PortRange, String> {
    if start > end {
        return Err("Start port must be less than or equal to end port".to_string());
    }
    Ok(PortRange {
        start,
        end,
    })
}

/// Parse a protocol string
#[tauri::command]
pub fn parse_protocol(protocol_str: String) -> Result<String, String> {
    let protocol: Protocol = protocol_str
        .parse()
        .map_err(|e| format!("Invalid protocol: {}", e))?;
    Ok(protocol.as_str().to_string())
}

/// Parse a port state string
#[tauri::command]
pub fn parse_port_state(state_str: String) -> Result<String, String> {
    let state: PortState = state_str
        .parse()
        .map_err(|e| format!("Invalid port state: {}", e))?;
    Ok(state.as_str().to_string())
}

/// Get available transform modules from the module registry
#[tauri::command]
pub fn get_available_modules() -> Vec<String> {
    let registry = crate::modules::get_registry();
    registry.list_available_transforms()
}

/// Create a plan with specific modules for transform pipeline
#[tauri::command]
pub fn create_plan_with_modules(
    scan_id: Option<String>,
    targets: String,
    ports: String,
    source_type: String,
    modules: Vec<String>,
    sink_types: Vec<String>,
    interface: Option<String>,
) -> Result<Plan, String> {
    let scan_id = parse_scan_id(scan_id)?;

    let mut plan = Plan {
        scan_id,
        targets,
        ports,
        rate: None,
        extra: Vec::new(),
        modules,
        source_type,
        sink_types,
        interface: None,
        nse_scripts: None,
        nse_script_args: None,
    };
    
    if let Some(iface) = interface {
        plan = plan.with_interface(iface);
    }

    Ok(plan)
}

/// Create a netsniffer plan for passive network monitoring
#[tauri::command]
pub fn create_netsniffer_plan(
    scan_id: Option<String>,
    interface: String,
) -> Result<Plan, String> {
    let scan_id = parse_scan_id(scan_id)?;

    let plan = Plan::netsniffer(scan_id, interface);
    Ok(plan)
}

/// Massmap result indicating which plans to execute in order:
///   Phase 1: discovery_plan  — nmap -sn, finds alive hosts fast (~5s for /24)
///   Phase 2: masscan_plan    — masscan all 65535 ports on alive hosts only (fast, few hosts)
///   Phase 3: nmap_plan       — nmap -sV service detection on alive hosts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MassmapResult {
    pub use_masscan: bool,
    pub discovery_plan: Option<Plan>,
    pub masscan_plan: Option<Plan>,
    pub nmap_plan: Plan,
}

/// Create a massmap plan - unified scanner that uses masscan for discovery on large networks
/// (>100 IPs) if no hosts are already discovered, then nmap for detailed scanning
#[tauri::command]
pub async fn create_massmap_plan(
    scan_id: Option<String>,
    targets: String,
    ports: String,
    scan_type: String,
    extra_args: Vec<String>,
    detect_os: bool,
    detect_versions: bool,
    skip_ping: bool,
    rate: Option<u64>,
    interface: Option<String>,
    db: State<'_, Arc<Db>>,
) -> Result<MassmapResult, String> {
    let scan_id = parse_scan_id(scan_id)?;
    
    // Parse target specification to get IP count and IP list
    let (ip_count, target_ips) = match parse_target_specification(&targets) {
        Ok(ips) => {
            let count = ips.len();
            let ip_set: HashSet<IpAddr> = ips.into_iter().collect();
            (count, ip_set)
        }
        Err(e) => {
            log::warn!("Failed to parse target specification for counting: {}, assuming single target", e);
            (1, HashSet::new()) // Assume single target if parsing fails
        }
    };
    
    log::info!("Massmap: Target range contains {} IPs", ip_count);
    
    // Check if hosts already exist in database
    let all_existing_hosts = db.inner().get_all_hosts().await
        .unwrap_or_else(|e| {
            log::warn!("Failed to check existing hosts: {}", e);
            Vec::new()
        });
    
    // Filter existing hosts to only those in the target range
    let existing_hosts_in_range: Vec<_> = if !target_ips.is_empty() {
        all_existing_hosts
            .iter()
            .filter(|h| {
                // Try to parse host IP and check if it's in target range
                h.ip.parse::<IpAddr>()
                    .map(|ip| target_ips.contains(&ip))
                    .unwrap_or(false)
            })
            .collect()
    } else {
        // If target parsing failed, check all hosts (conservative approach)
        all_existing_hosts.iter().collect()
    };
    
    let has_existing_hosts = !existing_hosts_in_range.is_empty();
    log::info!("Massmap: Found {} existing hosts in database ({} in target range)", 
               all_existing_hosts.len(), existing_hosts_in_range.len());
    
    // Determine if we need masscan:
    // - For quick scan: always use masscan for discovery on large networks (>100 IPs) for fast discovery
    // - For other scans: use masscan if >100 IPs AND no existing hosts in target range
    let use_masscan = if scan_type == "quick" {
        ip_count > 100 // Always use masscan for quick scans on large networks
    } else {
        ip_count > 100 && !has_existing_hosts // For other scans, check existing hosts
    };
    
    // Phase 1: Fast host discovery (nmap -sn with ARP on local nets) — finds alive IPs in seconds.
    // The frontend narrows masscan's targets to only these IPs after Phase 1 completes.
    let mut discovery_plan: Option<Plan> = None;
    let mut masscan_plan: Option<Plan> = None;

    if use_masscan {
        log::info!("Massmap: {} IPs — using 3-phase discovery → masscan → nmap", ip_count);

        // Each phase gets its own UUID so the frontend can distinguish which phase just finished.
        let discovery_scan_id = Uuid::new_v4();
        let masscan_scan_id = Uuid::new_v4();

        // Phase 1 plan: nmap -sn discovers alive hosts, targets overridden by frontend after it runs
        let mut disc = Plan::discovery(discovery_scan_id, targets.clone());
        if let Some(iface) = &interface {
            disc = disc.with_interface(iface.clone());
        }
        discovery_plan = Some(disc);

        // Phase 2 plan: masscan on alive hosts (targets narrowed by frontend after Phase 1).
        // Quick scan uses a targeted top-28 port list for speed; comprehensive scans all 65535.
        // Rate default 100 000 pps — safe for a LAN /24, completes in ~10s.
        let masscan_rate = rate.or(Some(100_000));
        let port_range = if scan_type == "quick" {
            "21,22,23,25,53,80,110,111,135,139,143,161,443,445,993,995,\
             1883,3306,3389,5353,5432,5900,6443,8080,8443,8883,9100,27017".to_string()
        } else if ports.is_empty() {
            "1-65535".to_string()
        } else {
            ports.clone()
        };
        let mut plan = Plan::masscan(masscan_scan_id, targets.clone(), port_range, masscan_rate);
        if let Some(iface) = &interface {
            plan = plan.with_interface(iface.clone());
        }
        masscan_plan = Some(plan);
    } else {
        log::info!("Massmap: {} IPs / has existing hosts — using nmap only", ip_count);
    }

    // Phase 3 (or sole phase): nmap service detection.
    // When masscan ran, the frontend replaces nmap_ports with only the ports masscan found open
    // (so nmap only scans confirmed-open ports — very fast).
    // Until that override arrives, use a port spec consistent with the scan type.
    let nmap_ports = if scan_type == "quick" {
        // Same targeted list as masscan phase — frontend will narrow further to masscan-open ports
        "21,22,23,25,53,80,110,111,135,139,143,161,443,445,993,995,\
         1883,3306,3389,5353,5432,5900,6443,8080,8443,8883,9100,27017".to_string()
    } else if ports.is_empty() && scan_type == "comprehensive" {
        "-".to_string()
    } else if use_masscan {
        ports.clone() // frontend will narrow to masscan-open ports
    } else {
        ports
    };

    let mut nmap_plan = match scan_type.as_str() {
        "quick" => {
            // Network topology + device classification scan — fast, informative, <90s for /24.
            // -sT: TCP connect scan — does NOT require cap_net_raw/root; always produces
            //      open/closed/filtered per host rather than "all filtered" from SYN EPERM.
            // -sV: service version detection for device type hints
            // --version-intensity 2: fast probing (default is 7)
            // --host-timeout 30s: cap per-host time so one slow host can't stall the scan
            // -Pn: skip host discovery (masscan already confirmed alive hosts)
            // No -O: OS detection is slow; MAC vendor from ARP covers topology needs
            let args = vec![
                "-sT".to_string(),
                "-sV".to_string(),
                "--version-intensity".to_string(), "2".to_string(),
                "-T4".to_string(),
                "--host-timeout".to_string(), "30s".to_string(),
                "-Pn".to_string(),
            ];
            Plan::nmap(scan_id, targets, nmap_ports, args)
                .with_nse_scripts(vec![
                    "banner".to_string(),
                    "http-title".to_string(),
                    "ssh-hostkey".to_string(),
                ])
        }
        "comprehensive" => {
            let mut plan = Plan::comprehensive(scan_id, targets, nmap_ports);
            if use_masscan {
                plan = plan.with_extra_args(vec!["-Pn".to_string()]);
            }
            plan
        }
        "stealth" => {
            Plan::nmap(scan_id, targets, nmap_ports, vec![
                "-sS".to_string(), "-T2".to_string(), "-f".to_string(),
                "--randomize-hosts".to_string(),
            ])
        }
        _ => {
            let mut args = Vec::new();
            if detect_os { args.push("-O".to_string()); }
            if detect_versions { args.push("-sV".to_string()); }
            if skip_ping || use_masscan { args.push("-Pn".to_string()); }
            args.extend(extra_args);
            Plan::nmap(scan_id, targets, nmap_ports, args)
        }
    };
    
    if let Some(iface) = interface {
        nmap_plan = nmap_plan.with_interface(iface);
    }
    
    Ok(MassmapResult {
        use_masscan,
        discovery_plan,
        masscan_plan,
        nmap_plan,
    })
}
