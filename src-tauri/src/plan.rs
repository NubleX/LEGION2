// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use serde::{Deserialize, Serialize};
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
        }
    }

    /// Set network interface for scanners
    pub fn with_interface(mut self, interface: String) -> Self {
        self.interface = Some(interface);
        self
    }
}
