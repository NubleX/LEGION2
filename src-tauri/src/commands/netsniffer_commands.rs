// LEGION2 - Network Sniffer Commands
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::network::netsniffer::{log_artifact, oui_lookup_vendor};
use anyhow::Result;
use serde_json::{json, Value};
use tauri::command;

/// Command to lookup vendor by MAC address
#[command]
pub async fn lookup_mac_vendor(mac_address: String) -> Result<Option<String>, String> {
    // Parse MAC address from string format (e.g., "aa:bb:cc:dd:ee:ff")
    let mac_parts: Vec<&str> = mac_address.split(':').collect();

    if mac_parts.len() != 6 {
        return Err("Invalid MAC address format. Expected: aa:bb:cc:dd:ee:ff".to_string());
    }

    let mut mac_bytes = [0u8; 6];
    for (i, part) in mac_parts.iter().enumerate() {
        match u8::from_str_radix(part, 16) {
            Ok(byte) => mac_bytes[i] = byte,
            Err(_) => return Err("Invalid MAC address format. Use hexadecimal values.".to_string()),
        }
    }

    Ok(oui_lookup_vendor(mac_bytes))
}

/// Command to log network artifacts to netsniffer.ndjson
#[command]
pub async fn log_network_artifact(
    ip: String,
    mac: Option<String>,
    vendor: Option<String>,
    hostname: Option<String>,
    os: Option<String>,
    source: String,
) -> Result<(), String> {
    let artifact = json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "os": os,
        "source": source
    });

    log_artifact(artifact);
    Ok(())
}

/// Command to start network monitoring/sniffing
#[command]
pub async fn start_network_monitoring(
    interface: Option<String>,
    filter: Option<String>,
) -> Result<String, String> {
    // For now, return a message indicating the capability is available
    // In a full implementation, this would start the packet capture from netsniffer.rs
    let iface = interface.unwrap_or_else(|| "default".to_string());
    let bpf_filter = filter.unwrap_or_else(|| "tcp".to_string());

    log::info!(
        "Network monitoring request for interface: {}, filter: {}",
        iface,
        bpf_filter
    );

    Ok(format!(
        "Network monitoring configured for interface '{}' with filter '{}'",
        iface, bpf_filter
    ))
}

/// Command to stop network monitoring
#[command]
pub async fn stop_network_monitoring() -> Result<String, String> {
    log::info!("Network monitoring stop requested");
    Ok("Network monitoring stopped".to_string())
}

/// Command to get OUI vendor statistics
#[command]
pub async fn get_vendor_statistics() -> Result<Value, String> {
    // This would analyze the netsniffer artifacts and return vendor statistics
    // For now, return a placeholder response
    Ok(json!({
        "total_devices": 0,
        "vendors": {},
        "unknown_vendors": 0,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Command to parse XML and enrich MAC addresses
#[command]
pub async fn parse_xml_for_mac_enrichment(xml_content: String) -> Result<Vec<Value>, String> {
    // This would use the parse_host_xml function from transformer.rs
    // For now, return placeholder to indicate the capability
    let artifacts = vec![json!({
        "ip": "192.168.1.100",
        "mac": "aa:bb:cc:dd:ee:ff",
        "vendor": "Example Vendor",
        "source": "xml_parser"
    })];

    Ok(artifacts)
}
