// LEGION2 - IoT Probe Source
// Coordinates sending IoT discovery probes with netsniffer capture
// Implements Source trait to integrate with the unified pipeline

use crate::commands::engine_commands;
use crate::plan::Plan;
use crate::scanners::netsniffer::NetSnifferSource;
use crate::scanners::probes::iot_probes::{
    IoTProtocol, IoTProbeResponse, IoTProbeSender,
    SSDPProbe, MDNSProbe, WSDDProbe, SNMPProbe, CoAPProbe,
};
use crate::shared::shared::{ObsStream, Observation, ObservationKind};
use crate::shared::traits::Source;
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use futures::stream::{self, StreamExt};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// IoT Probe Source - sends discovery probes and captures responses
pub struct IoTProbeSource {
    protocols: Vec<IoTProtocol>,
    interface: String,
    output_dir: PathBuf,
    probe_timeout: Duration,
}

impl IoTProbeSource {
    pub fn new(protocols: Vec<IoTProtocol>, interface: String, output_dir: PathBuf) -> Self {
        Self {
            protocols,
            interface,
            output_dir,
            probe_timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    /// Send multicast probes for discovery protocols
    async fn send_multicast_probes(&self) -> Result<Vec<(IoTProtocol, Instant)>> {
        let mut probe_times = Vec::new();
        
        for protocol in &self.protocols {
            if protocol.multicast_address().is_some() {
                let probe_time = Instant::now();
                if let Err(e) = IoTProbeSender::send_multicast_probe(protocol, Some(&self.interface)) {
                    log::warn!("Failed to send {} probe: {}", protocol.as_str(), e);
                } else {
                    log::debug!("Sent {} multicast probe", protocol.as_str());
                    probe_times.push((protocol.clone(), probe_time));
                }
                // Small delay between probes
                sleep(Duration::from_millis(100)).await;
            }
        }
        
        Ok(probe_times)
    }

    /// Send unicast probes to specific targets
    async fn send_unicast_probes(&self, targets: &[String]) -> Result<Vec<(IoTProtocol, String, Instant)>> {
        let mut probe_times = Vec::new();
        
        for target in targets {
            for protocol in &self.protocols {
                let probe_time = Instant::now();
                if let Err(e) = IoTProbeSender::send_unicast_probe(protocol, target, None) {
                    log::debug!("Failed to send {} probe to {}: {}", protocol.as_str(), target, e);
                } else {
                    log::debug!("Sent {} probe to {}", protocol.as_str(), target);
                    probe_times.push((protocol.clone(), target.clone(), probe_time));
                }
                // Small delay between probes
                sleep(Duration::from_millis(50)).await;
            }
        }
        
        Ok(probe_times)
    }

    /// Parse captured packet to check if it's a response to our probes
    fn parse_probe_response(
        &self,
        packet_data: &[u8],
        src_ip: &str,
        src_port: u16,
        dst_port: u16,
        probe_times: &[(IoTProtocol, Instant)],
    ) -> Option<IoTProbeResponse> {
        // Match port to protocol
        let protocol = match dst_port {
            1900 => Some(IoTProtocol::SSDP),
            5353 => Some(IoTProtocol::MDNS),
            3702 => Some(IoTProtocol::WSDD),
            161 => Some(IoTProtocol::SNMP),
            5683 | 5684 => Some(IoTProtocol::CoAP),
            _ => None,
        }?;

        // Check if this response is within timeout window of a probe
        let now = Instant::now();
        let is_recent_probe = probe_times.iter().any(|(p, t)| {
            p == &protocol && now.duration_since(*t) < self.probe_timeout
        });

        if !is_recent_probe {
            return None;
        }

        // Parse response based on protocol
        let mut response = match protocol {
            IoTProtocol::SSDP => SSDPProbe::parse_response(packet_data).ok()?,
            IoTProtocol::MDNS => MDNSProbe::parse_response(packet_data).ok()?,
            IoTProtocol::WSDD => WSDDProbe::parse_response(packet_data).ok()?,
            IoTProtocol::SNMP => SNMPProbe::parse_response(packet_data).ok()?,
            IoTProtocol::CoAP => CoAPProbe::parse_response(packet_data).ok()?,
            IoTProtocol::MQTT => return None, // MQTT is TCP, handled separately
        };

        response.source_ip = src_ip.to_string();
        response.source_port = src_port;
        
        Some(response)
    }

    /// Convert IoT probe response to Observation
    fn response_to_observations(&self, response: IoTProbeResponse, scan_id: uuid::Uuid) -> Vec<Observation> {
        let mut observations = Vec::new();
        let ts = Utc::now();

        // Host observation
        let mut host_fields = serde_json::Map::new();
        host_fields.insert("ip".to_string(), response.source_ip.clone().into());
        host_fields.insert("iot_protocol".to_string(), response.protocol.as_str().into());
        host_fields.insert("source".to_string(), "iot_probe".into());
        host_fields.insert("status".to_string(), "up".into());

        // Add device info from response
        for (key, value) in &response.device_info {
            host_fields.insert(format!("device_{}", key), value.clone());
        }

        // Determine device type from protocol and info
        let device_type = self.infer_device_type(&response);
        if let Some(dt) = device_type {
            host_fields.insert("device_type".to_string(), dt.into());
        }

        // Check if this is a pivot candidate
        let pivot_candidate = self.is_pivot_candidate(&response);
        host_fields.insert("pivot_candidate".to_string(), pivot_candidate.into());

        observations.push(Observation {
            scan_id,
            kind: ObservationKind::Host,
            fields: host_fields,
            ts,
            key: format!("host-{}", response.source_ip),
            raw: Some(String::from_utf8_lossy(&response.raw_response).to_string()),
        });

        // Service observation
        let mut service_fields = serde_json::Map::new();
        service_fields.insert("ip".to_string(), response.source_ip.clone().into());
        service_fields.insert("port".to_string(), response.source_port.into());
        service_fields.insert("protocol".to_string(), "udp".into());
        service_fields.insert("state".to_string(), "open".into());
        service_fields.insert("service".to_string(), response.protocol.as_str().into());
        service_fields.insert("source".to_string(), "iot_probe".into());

        // Add protocol-specific service info
        for (key, value) in &response.device_info {
            service_fields.insert(key.clone(), value.clone());
        }

        observations.push(Observation {
            scan_id,
            kind: ObservationKind::Service,
            fields: service_fields,
            ts,
            key: format!("service-{}-{}-udp", response.source_ip, response.source_port),
            raw: None,
        });

        observations
    }

    /// Infer device type from probe response
    fn infer_device_type(&self, response: &IoTProbeResponse) -> Option<String> {
        // Check device info for hints
        if let Some(server) = response.device_info.get("server") {
            if let Some(server_str) = server.as_str() {
                let server_lower = server_str.to_lowercase();
                if server_lower.contains("router") || server_lower.contains("gateway") {
                    return Some("router".to_string());
                }
                if server_lower.contains("camera") || server_lower.contains("ipcam") {
                    return Some("camera".to_string());
                }
                if server_lower.contains("printer") {
                    return Some("printer".to_string());
                }
                if server_lower.contains("tv") || server_lower.contains("smart") {
                    return Some("smart_tv".to_string());
                }
            }
        }

        // Infer from protocol
        match response.protocol {
            IoTProtocol::SSDP => Some("upnp_device".to_string()),
            IoTProtocol::MDNS => Some("bonjour_device".to_string()),
            IoTProtocol::WSDD => Some("windows_device".to_string()),
            IoTProtocol::SNMP => Some("network_device".to_string()),
            IoTProtocol::CoAP => Some("iot_device".to_string()),
            IoTProtocol::MQTT => Some("mqtt_broker".to_string()),
        }
    }

    /// Determine if device is a good pivot candidate
    fn is_pivot_candidate(&self, response: &IoTProbeResponse) -> bool {
        // Devices with multiple services are better pivot points
        // For now, mark devices with exposed management interfaces
        match response.protocol {
            IoTProtocol::SSDP | IoTProtocol::WSDD => {
                // UPnP/WSDD devices often have web interfaces
                true
            }
            IoTProtocol::SNMP => {
                // SNMP devices are network infrastructure
                true
            }
            IoTProtocol::CoAP => {
                // CoAP devices are IoT endpoints
                response.device_info.contains_key("resources")
            }
            _ => false,
        }
    }
}

#[async_trait]
impl Source for IoTProbeSource {
    fn name(&self) -> &'static str {
        "iot_probe"
    }

    async fn start(&self, plan: &Plan) -> Result<ObsStream> {
        let scan_id = plan.scan_id;
        let interface = self.interface.clone();
        let output_dir = self.output_dir.clone();
        let protocols = self.protocols.clone();

        log::info!("Starting IoT Probe Source with protocols: {:?}", 
            protocols.iter().map(|p| p.as_str()).collect::<Vec<_>>());

        // Start netsniffer to capture responses
        let netsniffer = NetSnifferSource::new(interface.clone(), output_dir);
        let mut sniffer_stream = netsniffer.start(plan).await?;

        // Send multicast probes first
        let probe_times = self.send_multicast_probes().await?;
        log::info!("Sent {} multicast probes", probe_times.len());

        // Parse targets from plan
        let targets: Vec<String> = plan.targets
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Send unicast probes to targets if specified
        let unicast_probe_times = if !targets.is_empty() {
            self.send_unicast_probes(&targets).await?
        } else {
            Vec::new()
        };

        // Combine probe times
        let mut all_probe_times: Vec<(IoTProtocol, Instant)> = probe_times;
        for (proto, _, time) in unicast_probe_times {
            all_probe_times.push((proto, time));
        }

        // Wait for responses (probe_timeout duration)
        sleep(self.probe_timeout).await;

        // Process captured packets
        let mut obs_queue = VecDeque::new();
        let mut response_count = 0;
        let probe_times_ref = all_probe_times.clone();
        let probe_timeout = self.probe_timeout;
        let protocols_clone = self.protocols.clone();

        // Create stream that processes sniffer output and matches with probes
        let stream = stream::unfold(
            (sniffer_stream, obs_queue, response_count, probe_times_ref, protocols_clone),
            move |(mut sniffer_stream, mut obs_queue, mut response_count, probe_times_ref, protocols_clone)| async move {
                // First, emit from queue if available
                if let Some(obs) = obs_queue.pop_front() {
                    return Some((obs, (sniffer_stream, obs_queue, response_count, probe_times_ref, protocols_clone)));
                }

                // Check cancellation
                if engine_commands::is_scan_cancelled() {
                    log::info!("IoT Probe Source cancelled");
                    return None;
                }

                // Get next observation from sniffer
                match sniffer_stream.next().await {
                    Some(obs) => {
                        // Check if this is a UDP packet observation we can parse
                        // Look for UDP packets on IoT protocol ports
                        if let (Some(src_ip), Some(src_port), Some(dst_port), Some(proto)) = (
                            obs.fields.get("src_ip").and_then(|v| v.as_str()),
                            obs.fields.get("sport").and_then(|v| v.as_u64().map(|p| p as u16)),
                            obs.fields.get("dport").and_then(|v| v.as_u64().map(|p| p as u16)),
                            obs.fields.get("protocol").and_then(|v| v.as_str()),
                        ) {
                            if proto == "udp" {
                                // Match port to protocol
                                let protocol = match dst_port {
                                    1900 => Some(IoTProtocol::SSDP),
                                    5353 => Some(IoTProtocol::MDNS),
                                    3702 => Some(IoTProtocol::WSDD),
                                    161 => Some(IoTProtocol::SNMP),
                                    5683 | 5684 => Some(IoTProtocol::CoAP),
                                    _ => None,
                                };

                                if let Some(proto_enum) = protocol {
                                    // Check if this response is within timeout window of a probe
                                    let now = Instant::now();
                                    let is_recent_probe = probe_times_ref.iter().any(|(p, t)| {
                                        p == &proto_enum && now.duration_since(*t) < probe_timeout
                                    });

                                    if is_recent_probe {
                                        // Try to parse response from raw data if available
                                        if let Some(raw_data) = &obs.raw {
                                            if let Ok(packet_bytes) = hex::decode(raw_data) {
                                                let response = match proto_enum {
                                                    IoTProtocol::SSDP => SSDPProbe::parse_response(&packet_bytes).ok(),
                                                    IoTProtocol::MDNS => MDNSProbe::parse_response(&packet_bytes).ok(),
                                                    IoTProtocol::WSDD => WSDDProbe::parse_response(&packet_bytes).ok(),
                                                    IoTProtocol::SNMP => SNMPProbe::parse_response(&packet_bytes).ok(),
                                                    IoTProtocol::CoAP => CoAPProbe::parse_response(&packet_bytes).ok(),
                                                    IoTProtocol::MQTT => None,
                                                };

                                                if let Some(mut resp) = response {
                                                    resp.source_ip = src_ip.to_string();
                                                    resp.source_port = src_port;
                                                    
                                                    response_count += 1;
                                                    
                                                    // Create IoT observations
                                                    let ts = Utc::now();
                                                    
                                                    // Host observation
                                                    let mut host_fields = serde_json::Map::new();
                                                    host_fields.insert("ip".to_string(), resp.source_ip.clone().into());
                                                    host_fields.insert("iot_protocol".to_string(), resp.protocol.as_str().into());
                                                    host_fields.insert("source".to_string(), "iot_probe".into());
                                                    host_fields.insert("status".to_string(), "up".into());
                                                    
                                                    for (key, value) in &resp.device_info {
                                                        host_fields.insert(format!("device_{}", key), value.clone());
                                                    }
                                                    
                                                    let device_type = match resp.protocol {
                                                        IoTProtocol::SSDP => Some("upnp_device"),
                                                        IoTProtocol::MDNS => Some("bonjour_device"),
                                                        IoTProtocol::WSDD => Some("windows_device"),
                                                        IoTProtocol::SNMP => Some("network_device"),
                                                        IoTProtocol::CoAP => Some("iot_device"),
                                                        IoTProtocol::MQTT => Some("mqtt_broker"),
                                                    };
                                                    
                                                    if let Some(dt) = device_type {
                                                        host_fields.insert("device_type".to_string(), dt.into());
                                                    }
                                                    
                                                    let pivot_candidate = matches!(resp.protocol, 
                                                        IoTProtocol::SSDP | IoTProtocol::WSDD | IoTProtocol::SNMP);
                                                    host_fields.insert("pivot_candidate".to_string(), pivot_candidate.into());
                                                    
                                                    let host_obs = Observation {
                                                        scan_id,
                                                        kind: ObservationKind::Host,
                                                        fields: host_fields,
                                                        ts,
                                                        key: format!("host-{}", resp.source_ip),
                                                        raw: Some(String::from_utf8_lossy(&resp.raw_response).to_string()),
                                                    };
                                                    
                                                    // Service observation
                                                    let mut service_fields = serde_json::Map::new();
                                                    service_fields.insert("ip".to_string(), resp.source_ip.clone().into());
                                                    service_fields.insert("port".to_string(), resp.source_port.into());
                                                    service_fields.insert("protocol".to_string(), "udp".into());
                                                    service_fields.insert("state".to_string(), "open".into());
                                                    service_fields.insert("service".to_string(), resp.protocol.as_str().into());
                                                    service_fields.insert("source".to_string(), "iot_probe".into());
                                                    
                                                    for (key, value) in &resp.device_info {
                                                        service_fields.insert(key.clone(), value.clone());
                                                    }
                                                    
                                                    let service_obs = Observation {
                                                        scan_id,
                                                        kind: ObservationKind::Service,
                                                        fields: service_fields,
                                                        ts,
                                                        key: format!("service-{}-{}-udp", resp.source_ip, resp.source_port),
                                                        raw: None,
                                                    };
                                                    
                                                    obs_queue.push_back(host_obs);
                                                    obs_queue.push_back(service_obs);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Emit the original observation or first queued IoT observation
                        if let Some(queued) = obs_queue.pop_front() {
                            Some((queued, (sniffer_stream, obs_queue, response_count, probe_times_ref, protocols_clone)))
                        } else {
                            Some((obs, (sniffer_stream, obs_queue, response_count, probe_times_ref, protocols_clone)))
                        }
                    }
                    None => {
                        // Sniffer stream ended, emit completion metric
                        if response_count > 0 {
                            let completion_obs = Observation {
                                scan_id,
                                kind: ObservationKind::Metric,
                                fields: {
                                    let mut fields = serde_json::Map::new();
                                    fields.insert("status".to_string(), "completed".into());
                                    fields.insert("response_count".to_string(), response_count.into());
                                    fields
                                },
                                ts: Utc::now(),
                                key: "iot-probe-complete".to_string(),
                                raw: None,
                            };
                            Some((completion_obs, (sniffer_stream, obs_queue, response_count, probe_times_ref, protocols_clone)))
                        } else {
                            None
                        }
                    }
                }
            },
        );

        Ok(Box::pin(stream))
    }
}

