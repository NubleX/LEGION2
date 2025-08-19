// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::plan::Plan;
use crate::shared::{ScanTypes::{PortRange, ScanType}, shared::{PortState, Protocol}};
use uuid::Uuid;

/// Create a masscan plan using the builder pattern
#[tauri::command]
pub fn create_masscan_plan(
    scan_id: Option<String>,
    targets: String,
    ports: String,
    rate: Option<u64>,
    interface: Option<String>,
) -> Result<Plan, String> {
    let scan_id = scan_id
        .map(|s| Uuid::parse_str(&s))
        .transpose()
        .map_err(|e| format!("Invalid UUID: {}", e))?
        .unwrap_or_else(Uuid::new_v4);

    let mut plan = Plan::masscan(scan_id, targets, ports, rate);
    if let Some(iface) = interface {
        plan = plan.with_interface(iface);
    }
    Ok(plan)
}

/// Create an nmap plan using the builder pattern
#[tauri::command]
pub async fn create_nmap_plan(
    scan_id: Option<String>,
    targets: String,
    ports: String,
    extra_args: Vec<String>,
    interface: Option<String>,
) -> Result<Plan, String> {
    let scan_id = scan_id
        .map(|s| Uuid::parse_str(&s))
        .transpose()
        .map_err(|e| format!("Invalid UUID: {}", e))?
        .unwrap_or_else(Uuid::new_v4);

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
    let scan_id = scan_id
        .map(|s| Uuid::parse_str(&s))
        .transpose()
        .map_err(|e| format!("Invalid UUID: {}", e))?
        .unwrap_or_else(Uuid::new_v4);

    let mut plan = Plan::comprehensive(scan_id, targets, ports);
    if let Some(iface) = interface {
        plan = plan.with_interface(iface);
    }
    Ok(plan)
}

/// Create an OS detection plan using the builder pattern
#[tauri::command]
pub fn create_os_detection_plan(scan_id: Option<String>, targets: String) -> Result<Plan, String> {
    let scan_id = scan_id
        .map(|s| Uuid::parse_str(&s))
        .transpose()
        .map_err(|e| format!("Invalid UUID: {}", e))?
        .unwrap_or_else(Uuid::new_v4);

    let plan = Plan::os_detection(scan_id, targets);
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
    top_ports: Option<u16>,
) -> Result<PortRange, String> {
    if start > end {
        return Err("Start port must be less than or equal to end port".to_string());
    }
    Ok(PortRange {
        start,
        end,
        top_ports,
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
) -> Result<Plan, String> {
    let scan_id = scan_id
        .map(|s| Uuid::parse_str(&s))
        .transpose()
        .map_err(|e| format!("Invalid UUID: {}", e))?
        .unwrap_or_else(Uuid::new_v4);

    let plan = Plan {
        scan_id,
        targets,
        ports,
        rate: None,
        extra: Vec::new(),
        modules,
        source_type,
        sink_types,
        interface: None,
    };

    Ok(plan)
}
