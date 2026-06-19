// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Plan defines what the engine should execute - moved from core/types.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub scan_id: Uuid,
    pub targets: String,
    pub ports: String,
    pub rate: Option<u64>,
    pub extra: Vec<String>,
    pub modules: Vec<String>,
    pub source_type: String,
    pub sink_types: Vec<String>,
    pub interface: Option<String>,
    pub nse_scripts: Option<Vec<String>>,
    pub nse_script_args: Option<HashMap<String, String>>,
}

impl Plan {
    /// Create a masscan plan
    pub fn masscan(scan_id: Uuid, targets: String, ports: String, rate: Option<u64>) -> Self {
        Self {
            scan_id,
            targets,
            ports,
            rate,
            extra: vec![],
            modules: vec![],
            source_type: "masscan".to_string(),
            sink_types: vec![
                "ui".to_string(),
                "db".to_string(),
                "vulnerability".to_string(),
            ],
            interface: None,
            nse_scripts: None,
            nse_script_args: None,
        }
    }

    /// Create an nmap plan  
    pub fn nmap(scan_id: Uuid, targets: String, ports: String, extra_args: Vec<String>) -> Self {
        Self {
            scan_id,
            targets,
            ports,
            rate: None,
            extra: extra_args,
            modules: vec![],
            source_type: "nmap".to_string(),
            sink_types: vec![
                "ui".to_string(),
                "db".to_string(),
                "vulnerability".to_string(),
            ],
            interface: None,
            nse_scripts: None,
            nse_script_args: None,
        }
    }

    /// Create a fast host-discovery plan using nmap -sn (ARP on local networks, ICMP elsewhere).
    /// This is Phase 1 of Massmap: find which IPs are alive before masscan port-scans them.
    pub fn discovery(scan_id: Uuid, targets: String) -> Self {
        Self {
            scan_id,
            targets,
            ports: String::new(),
            rate: None,
            extra: vec![
                "-sn".to_string(),           // Host discovery only (no port scan)
                "-n".to_string(),            // Skip reverse DNS
                "-T5".to_string(),           // Fastest timing template
                "--min-parallelism".to_string(), "256".to_string(),
            ],
            modules: vec![],
            source_type: "nmap".to_string(), // NmapScanner handles this
            sink_types: vec!["ui".to_string(), "db".to_string()],
            interface: None,
            nse_scripts: None,
            nse_script_args: None,
        }
    }

    /// Add extra arguments
    pub fn with_extra_args(mut self, args: Vec<String>) -> Self {
        self.extra.extend(args);
        self
    }

    /// Add modules to the processing pipeline
    pub fn with_modules(mut self, modules: Vec<String>) -> Self {
        self.modules.extend(modules);
        self
    }

    /// Set scan rate (for masscan)
    pub fn with_rate(mut self, rate: u64) -> Self {
        self.rate = Some(rate);
        self
    }

    /// Add a sink type
    pub fn with_sink(mut self, sink_type: String) -> Self {
        if !self.sink_types.contains(&sink_type) {
            self.sink_types.push(sink_type);
        }
        self
    }

    /// Enable OS detection (adds -O flag for nmap)
    pub fn with_os_detection(mut self) -> Self {
        if self.source_type == "nmap" {
            if !self.extra.contains(&"-O".to_string()) {
                self.extra.push("-O".to_string());
            }
        }
        self
    }

    /// Enable comprehensive scan with OS detection, service detection, and aggressive options
    pub fn comprehensive(scan_id: Uuid, targets: String, ports: String) -> Self {
        Self {
            scan_id,
            targets,
            ports,
            rate: None,
            extra: vec![
                "-sS".to_string(),
                "-sV".to_string(),
                "-O".to_string(),
                "-A".to_string(),
                "-T4".to_string(),
            ],
            modules: vec![],
            source_type: "nmap".to_string(),
            sink_types: vec![
                "ui".to_string(),
                "db".to_string(),
                "vulnerability".to_string(),
            ],
            interface: None,
            nse_scripts: None,
            nse_script_args: None,
        }
    }

    /// Create OS detection specific scan
    pub fn os_detection(scan_id: Uuid, targets: String) -> Self {
        Self {
            scan_id,
            targets,
            ports: "1-1000".to_string(), // Common ports for OS detection
            rate: None,
            extra: vec![
                "-O".to_string(),
                "-sS".to_string(),
                "-T4".to_string(),
                "-PS80,443,22".to_string(), // TCP SYN ping to common ports
                "-PA80,443,22".to_string(), // TCP ACK ping to common ports
                "--max-rtt-timeout".to_string(),
                "2s".to_string(), // Reasonable timeout
                "--initial-rtt-timeout".to_string(),
                "500ms".to_string(),
            ],
            modules: vec![],
            source_type: "nmap".to_string(),
            sink_types: vec![
                "ui".to_string(),
                "db".to_string(),
                "vulnerability".to_string(),
            ],
            interface: None,
            nse_scripts: None,
            nse_script_args: None,
        }
    }

    /// Set network interface for scanners
    pub fn with_interface(mut self, interface: String) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Create a netsniffer plan for passive network monitoring
    /// Captures packets on the specified interface for OS fingerprinting and MAC enrichment
    pub fn netsniffer(scan_id: Uuid, interface: String) -> Self {
        Self {
            scan_id,
            targets: String::new(), // No active targets for passive monitoring
            ports: String::new(),   // Captures all ports
            rate: None,
            extra: vec![],
            modules: vec![
                "mac_enrichment".to_string(),
                "passive_os".to_string(),
                "service_parsing".to_string(),
                "cve_enrichment".to_string(),
                "port_service_cve".to_string(),
            ],
            source_type: "netsniffer".to_string(),
            sink_types: vec![
                "ui".to_string(),
                "db".to_string(),
            ],
            interface: Some(interface),
            nse_scripts: None,
            nse_script_args: None,
        }
    }

    /// Create a hybrid scan plan: masscan for fast port discovery + nmap for detailed analysis
    /// This is the "unity" pattern - combining speed with depth
    pub fn hybrid(
        scan_id: Uuid,
        targets: String,
        ports: String,
        masscan_rate: u64,
    ) -> Vec<Self> {
        vec![
            // Phase 1: Fast port discovery with masscan
            Self::masscan(scan_id, targets.clone(), ports.clone(), Some(masscan_rate))
                .with_modules(vec!["ip_enrichment".to_string()]),
            // Phase 2: Detailed service/OS detection with nmap
            // Note: In practice, this would use discovered hosts/ports from phase 1
            Self::nmap(
                scan_id,
                targets,
                ports,
                vec!["-sV".to_string(), "-O".to_string(), "-sC".to_string()],
            )
            .with_modules(vec![
                "service_parsing".to_string(),
                "vulnerability".to_string(),
            ]),
        ]
    }

    /// Create an IoT spider scan plan
    /// Sends lightweight discovery probes (SSDP, mDNS, WSDD, SNMP, CoAP, MQTT) 
    /// to discover IoT devices on the network
    pub fn iot_spider(scan_id: Uuid, targets: String, protocols: Vec<String>) -> Self {
        Self {
            scan_id,
            targets,
            ports: String::new(), // IoT protocols use specific ports
            rate: None,
            extra: protocols, // Store protocol list in extra for now
            modules: vec![
                "ip_enrichment".to_string(),
                "service_parsing".to_string(),
            ],
            source_type: "iot_probe".to_string(),
            sink_types: vec![
                "ui".to_string(),
                "db".to_string(),
                "vulnerability".to_string(),
            ],
            interface: None,
            nse_scripts: None,
            nse_script_args: None,
        }
    }

    /// Filter which IoT protocols to use
    pub fn with_iot_protocols(mut self, protocols: Vec<String>) -> Self {
        self.extra = protocols;
        self
    }

    /// Add NSE scripts to execute during nmap scan
    pub fn with_nse_scripts(mut self, scripts: Vec<String>) -> Self {
        self.nse_scripts = Some(scripts);
        self
    }

    /// Add NSE script arguments
    /// Format: HashMap with keys like "script1.arg1" -> "value1"
    pub fn with_nse_script_args(mut self, args: HashMap<String, String>) -> Self {
        self.nse_script_args = Some(args);
        self
    }

    /// Create a continuous monitoring plan: netsniffer + periodic nmap
    /// Passive monitoring combined with periodic active scanning
    pub fn continuous_monitor(scan_id: Uuid, targets: String, interface: String) -> Vec<Self> {
        vec![
            // Continuous passive monitoring
            Self::netsniffer(scan_id, interface),
            // Periodic active OS detection
            Self::os_detection(scan_id, targets)
                .with_modules(vec!["passive_os".to_string(), "mac_enrichment".to_string()]),
        ]
    }
}
