// LEGION2 - IoT Network Discovery Probes
// Implements lightweight discovery protocols for IoT device enumeration
// Based on NSE library implementations (upnp.lua, dnssd.lua, wsdd.lua, snmp.lua, coap.lua, mqtt.lua)

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use uuid::Uuid;
use serde_json::Number;

/// Supported IoT discovery protocols
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IoTProtocol {
    SSDP,   // UPnP/SSDP discovery
    MDNS,   // mDNS/DNS-SD (Bonjour)
    WSDD,   // Web Services Dynamic Discovery
    SNMP,   // Simple Network Management Protocol
    CoAP,   // Constrained Application Protocol
    MQTT,   // MQTT broker discovery
}

impl IoTProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            IoTProtocol::SSDP => "ssdp",
            IoTProtocol::MDNS => "mdns",
            IoTProtocol::WSDD => "wsdd",
            IoTProtocol::SNMP => "snmp",
            IoTProtocol::CoAP => "coap",
            IoTProtocol::MQTT => "mqtt",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ssdp" => Some(IoTProtocol::SSDP),
            "mdns" => Some(IoTProtocol::MDNS),
            "wsdd" => Some(IoTProtocol::WSDD),
            "snmp" => Some(IoTProtocol::SNMP),
            "coap" => Some(IoTProtocol::CoAP),
            "mqtt" => Some(IoTProtocol::MQTT),
            _ => None,
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            IoTProtocol::SSDP => 1900,
            IoTProtocol::MDNS => 5353,
            IoTProtocol::WSDD => 3702,
            IoTProtocol::SNMP => 161,
            IoTProtocol::CoAP => 5683,
            IoTProtocol::MQTT => 1883,
        }
    }

    pub fn multicast_address(&self) -> Option<Ipv4Addr> {
        match self {
            IoTProtocol::SSDP => Some(Ipv4Addr::new(239, 255, 255, 250)),
            IoTProtocol::MDNS => Some(Ipv4Addr::new(224, 0, 0, 251)),
            IoTProtocol::WSDD => Some(Ipv4Addr::new(239, 255, 255, 250)),
            IoTProtocol::SNMP => None, // SNMP is unicast
            IoTProtocol::CoAP => Some(Ipv4Addr::new(224, 0, 1, 187)), // CoAP multicast
            IoTProtocol::MQTT => None, // MQTT is unicast
        }
    }
}

/// Parsed response from an IoT probe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoTProbeResponse {
    pub protocol: IoTProtocol,
    pub source_ip: String,
    pub source_port: u16,
    pub device_info: HashMap<String, serde_json::Value>,
    pub raw_response: Vec<u8>,
}

/// SSDP/UPnP Probe Implementation
pub struct SSDPProbe;

impl SSDPProbe {
    /// Build SSDP M-SEARCH request packet
    pub fn build_probe() -> Vec<u8> {
        format!(
            "M-SEARCH * HTTP/1.1\r\n\
             Host: 239.255.255.250:1900\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 3\r\n\
             ST: ssdp:all\r\n\
             \r\n"
        )
        .into_bytes()
    }

    /// Parse SSDP response headers
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        let response_str = String::from_utf8_lossy(data);
        let mut device_info = HashMap::new();
        
        // Extract headers
        let location = Self::extract_header(&response_str, "LOCATION");
        let usn = Self::extract_header(&response_str, "USN");
        let server = Self::extract_header(&response_str, "SERVER");
        let st = Self::extract_header(&response_str, "ST");
        
        if let Some(loc) = location {
            device_info.insert("location".to_string(), serde_json::Value::String(loc));
        }
        if let Some(usn_val) = usn {
            device_info.insert("usn".to_string(), serde_json::Value::String(usn_val));
        }
        if let Some(srv) = server {
            device_info.insert("server".to_string(), serde_json::Value::String(srv));
        }
        if let Some(st_val) = st {
            device_info.insert("st".to_string(), serde_json::Value::String(st_val));
        }

        // Extract source IP/port from response (will be filled by caller)
        Ok(IoTProbeResponse {
            protocol: IoTProtocol::SSDP,
            source_ip: String::new(),
            source_port: 1900,
            device_info,
            raw_response: data.to_vec(),
        })
    }

    fn extract_header(response: &str, header: &str) -> Option<String> {
        let pattern = format!("(?i)\r\n{}:\\s*(.+?)\r\n", header);
        let re = regex::Regex::new(&pattern).ok()?;
        re.captures(response)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().trim().to_string())
    }
}

/// mDNS/DNS-SD Probe Implementation
pub struct MDNSProbe;

impl MDNSProbe {
    /// Build mDNS query for _services._dns-sd._udp.local
    pub fn build_probe() -> Vec<u8> {
        // Simple mDNS query packet
        // Transaction ID: random 16-bit
        // Flags: Standard query (0x0000)
        // Questions: 1
        // Query: _services._dns-sd._udp.local, type PTR, class IN
        let mut packet = Vec::new();
        
        // Transaction ID (random)
        let tx_id = rand::random::<u16>();
        packet.extend_from_slice(&tx_id.to_be_bytes());
        
        // Flags: Standard query, recursion desired
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        
        // Questions: 1
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        // Answer/Authority/Additional RRs: 0
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        
        // Query name: _services._dns-sd._udp.local
        let query_name = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00";
        packet.extend_from_slice(query_name);
        
        // Type: PTR (12)
        packet.extend_from_slice(&12u16.to_be_bytes());
        
        // Class: IN (1)
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        packet
    }

    /// Parse mDNS response
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        // Basic mDNS parsing - extract service names from DNS packet
        // Full DNS parsing would use dns-parser crate, but for now we do basic extraction
        let mut device_info = HashMap::new();
        
        // Check if this looks like a DNS packet (starts with transaction ID)
        if data.len() >= 12 {
            // DNS header is 12 bytes
            // Answers section starts after questions
            // For now, just mark that we received a response
            device_info.insert(
                "response_received".to_string(),
                serde_json::Value::Bool(true),
            );
            device_info.insert(
                "packet_length".to_string(),
                serde_json::Value::Number(Number::from(data.len())),
            );
        }

        Ok(IoTProbeResponse {
            protocol: IoTProtocol::MDNS,
            source_ip: String::new(),
            source_port: 5353,
            device_info,
            raw_response: data.to_vec(),
        })
    }
}

/// WSDD Probe Implementation
pub struct WSDDProbe;

impl WSDDProbe {
    /// Build WSDD general probe (SOAP envelope)
    pub fn build_probe() -> Vec<u8> {
        let uuid = Uuid::new_v4().to_string();
        format!(
            "<env:Envelope xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\" \
             xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
             xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">\
             <env:Header>\
             <wsd:AppSequence InstanceId=\"1285624958737\" MessageNumber=\"1\" \
             SequenceId=\"urn:uuid:{}\"/>\
             <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>\
             <wsa:Action>\
             http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe\
             </wsa:Action>\
             <wsa:MessageID>urn:uuid:{}</wsa:MessageID>\
             </env:Header>\
             <env:Body><wsd:Probe/></env:Body>\
             </env:Envelope>",
            uuid, uuid
        )
        .into_bytes()
    }

    /// Parse WSDD ProbeMatch response
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        let response_str = String::from_utf8_lossy(data);
        let mut device_info = HashMap::new();
        
        // Parse SOAP XML response
        let doc = roxmltree::Document::parse(&response_str)?;
        
        // Extract MessageID
        if let Some(msg_id) = doc
            .descendants()
            .find(|n| n.tag_name().name() == "MessageID")
        {
            if let Some(text) = msg_id.text() {
                device_info.insert("message_id".to_string(), serde_json::Value::String(text.to_string()));
            }
        }
        
        // Extract XAddrs
        if let Some(xaddrs) = doc
            .descendants()
            .find(|n| n.tag_name().name() == "XAddrs")
        {
            if let Some(text) = xaddrs.text() {
                device_info.insert("xaddrs".to_string(), serde_json::Value::String(text.to_string()));
            }
        }
        
        // Extract Types
        if let Some(types) = doc
            .descendants()
            .find(|n| n.tag_name().name() == "Types")
        {
            if let Some(text) = types.text() {
                device_info.insert("types".to_string(), serde_json::Value::String(text.to_string()));
            }
        }

        Ok(IoTProbeResponse {
            protocol: IoTProtocol::WSDD,
            source_ip: String::new(),
            source_port: 3702,
            device_info,
            raw_response: data.to_vec(),
        })
    }
}

/// SNMP Probe Implementation
pub struct SNMPProbe;

impl SNMPProbe {
    /// Build SNMP GetRequest for system description (OID 1.3.6.1.2.1.1.1.0)
    pub fn build_probe(community: &str) -> Vec<u8> {
        // Simplified SNMP v2c GetRequest
        // This is a minimal implementation - full ASN.1 encoding would be more complex
        // For now, return a basic structure that can be enhanced later
        let mut packet = Vec::new();
        
        // SNMP version: 1 (v2c)
        // Community: public
        // PDU: GetRequest
        // OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        
        // This is a placeholder - full SNMP encoding requires ASN.1 DER encoding
        // For production, use snmp-parser crate or implement full ASN.1 encoder
        packet.extend_from_slice(community.as_bytes());
        
        packet
    }

    /// Parse SNMP response
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        // Basic SNMP response detection
        // Full SNMP parsing requires ASN.1 DER decoding (complex)
        // For now, just detect if we got a response
        let mut device_info = HashMap::new();
        
        // SNMP v2c response starts with version (0x02), length, value (0x01 for v2c)
        // Then community string, then PDU type (0xA2 for Response-PDU)
        if data.len() > 4 && data[0] == 0x30 {
            // Looks like ASN.1 SEQUENCE (SNMP message)
            device_info.insert(
                "response_received".to_string(),
                serde_json::Value::Bool(true),
            );
            device_info.insert(
                "packet_length".to_string(),
                serde_json::Value::Number(Number::from(data.len())),
            );
            
            // Try to find Response-PDU marker (0xA2)
            if data.windows(1).any(|w| w[0] == 0xA2) {
                device_info.insert(
                    "pdu_type".to_string(),
                    serde_json::Value::String("response".to_string()),
                );
            }
        }

        Ok(IoTProbeResponse {
            protocol: IoTProtocol::SNMP,
            source_ip: String::new(),
            source_port: 161,
            device_info,
            raw_response: data.to_vec(),
        })
    }
}

/// CoAP Probe Implementation
pub struct CoAPProbe;

impl CoAPProbe {
    /// Build CoAP GET request for /.well-known/core
    pub fn build_probe() -> Vec<u8> {
        // CoAP packet structure:
        // Byte 0: Version (2 bits) + Type (2 bits) + Token Length (4 bits)
        // Byte 1: Code (GET = 0x01)
        // Bytes 2-3: Message ID
        // Option: Uri-Path: .well-known
        // Option: Uri-Path: core
        
        let mut packet = Vec::new();
        
        // Header: Version=1, Type=Non-Confirmable, Token Length=0
        packet.push(0x40);
        
        // Code: GET (0x01)
        packet.push(0x01);
        
        // Message ID (random)
        let msg_id = rand::random::<u16>();
        packet.extend_from_slice(&msg_id.to_be_bytes());
        
        // Uri-Path option: .well-known (length 11)
        packet.push(0xB0 | 11u8); // Option delta=11 (Uri-Path), length=11
        packet.extend_from_slice(b".well-known");
        
        // Uri-Path option: core (length 4)
        packet.push(0xB0 | 4u8); // Option delta=11 (Uri-Path), length=4
        packet.extend_from_slice(b"core");
        
        packet
    }

    /// Parse CoAP response (Link-Format)
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        // Basic CoAP response parsing
        let mut device_info = HashMap::new();
        
        if data.len() >= 4 {
            // Check CoAP version (should be 1)
            let version = (data[0] >> 6) & 0x03;
            if version == 1 {
                device_info.insert(
                    "response_received".to_string(),
                    serde_json::Value::Bool(true),
                );
                
                // Extract code (success = 2.05 = 0x45)
                let code = data[1];
                device_info.insert(
                    "code".to_string(),
                    serde_json::Value::Number(code.into()),
                );
                
                // Try to extract payload (Link-Format)
                if data.len() > 4 {
                    // Look for payload marker (0xFF)
                    if let Some(payload_start) = data.iter().position(|&b| b == 0xFF) {
                        if payload_start + 1 < data.len() {
                            let payload = &data[payload_start + 1..];
                            if let Ok(link_format) = String::from_utf8(payload.to_vec()) {
                                device_info.insert(
                                    "resources".to_string(),
                                    serde_json::Value::String(link_format),
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(IoTProbeResponse {
            protocol: IoTProtocol::CoAP,
            source_ip: String::new(),
            source_port: 5683,
            device_info,
            raw_response: data.to_vec(),
        })
    }
}

/// MQTT Probe Implementation
pub struct MQTTProbe;

impl MQTTProbe {
    /// Build MQTT CONNECT packet
    pub fn build_probe() -> Vec<u8> {
        // MQTT CONNECT packet structure:
        // Fixed header: [0x10 (CONNECT), remaining length]
        // Variable header: Protocol name + level, Connect flags, Keep alive
        // Payload: Client ID
        
        let mut packet = Vec::new();
        
        // Fixed header: CONNECT (0x10)
        packet.push(0x10);
        
        // Remaining length (will be calculated)
        let protocol_name = b"MQTT";
        let protocol_level = 4u8; // MQTT 3.1.1
        let connect_flags = 0x02u8; // Clean session
        let keep_alive = 60u16;
        let client_id = b"legion2-probe";
        
        let remaining_len = 2 + protocol_name.len() as u8 + 1 + 1 + 2 + client_id.len() as u8 + 2;
        packet.push(remaining_len);
        
        // Variable header
        // Protocol name length + name
        packet.extend_from_slice(&(protocol_name.len() as u16).to_be_bytes());
        packet.extend_from_slice(protocol_name);
        
        // Protocol level
        packet.push(protocol_level);
        
        // Connect flags
        packet.push(connect_flags);
        
        // Keep alive
        packet.extend_from_slice(&keep_alive.to_be_bytes());
        
        // Payload: Client ID
        packet.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        packet.extend_from_slice(client_id);
        
        packet
    }

    /// Parse MQTT CONNACK response
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        if data.len() < 4 {
            return Err(anyhow!("MQTT response too short"));
        }
        
        let mut device_info = HashMap::new();
        
        // CONNACK: [0x20, remaining_len, reserved, return_code]
        if data[0] == 0x20 && data.len() >= 4 {
            let return_code = data[3];
                device_info.insert(
                    "return_code".to_string(),
                    serde_json::Value::Number(Number::from(return_code)),
                );
            
            match return_code {
                0 => device_info.insert("status".to_string(), serde_json::Value::String("accepted".to_string())),
                1 => device_info.insert("status".to_string(), serde_json::Value::String("unacceptable_protocol".to_string())),
                2 => device_info.insert("status".to_string(), serde_json::Value::String("identifier_rejected".to_string())),
                3 => device_info.insert("status".to_string(), serde_json::Value::String("server_unavailable".to_string())),
                4 => device_info.insert("status".to_string(), serde_json::Value::String("bad_credentials".to_string())),
                5 => device_info.insert("status".to_string(), serde_json::Value::String("not_authorized".to_string())),
                _ => device_info.insert("status".to_string(), serde_json::Value::String("unknown".to_string())),
            };
        }

        Ok(IoTProbeResponse {
            protocol: IoTProtocol::MQTT,
            source_ip: String::new(),
            source_port: 1883,
            device_info,
            raw_response: data.to_vec(),
        })
    }
}

/// Unified probe sender
pub struct IoTProbeSender;

impl IoTProbeSender {
    /// Send a multicast probe
    pub fn send_multicast_probe(
        protocol: &IoTProtocol,
        interface: Option<&str>,
    ) -> Result<()> {
        let multicast_addr = protocol
            .multicast_address()
            .ok_or_else(|| anyhow!("Protocol {} does not support multicast", protocol.as_str()))?;
        
        let port = protocol.default_port();
        let probe_data = match protocol {
            IoTProtocol::SSDP => SSDPProbe::build_probe(),
            IoTProtocol::MDNS => MDNSProbe::build_probe(),
            IoTProtocol::WSDD => WSDDProbe::build_probe(),
            IoTProtocol::CoAP => CoAPProbe::build_probe(),
            _ => return Err(anyhow!("Protocol {} does not support multicast", protocol.as_str())),
        };
        
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_multicast_ttl_v4(2)?; // Limit to local network
        
        // Join multicast group if interface specified
        if let Some(iface) = interface {
            // Interface binding would go here (platform-specific)
            log::debug!("Sending {} probe on interface {}", protocol.as_str(), iface);
        }
        
        let target = SocketAddr::new(multicast_addr.into(), port);
        socket.send_to(&probe_data, target)?;
        
        Ok(())
    }

    /// Send a unicast probe to a specific target
    pub fn send_unicast_probe(
        protocol: &IoTProtocol,
        target_ip: &str,
        port: Option<u16>,
    ) -> Result<()> {
        let target_port = port.unwrap_or_else(|| protocol.default_port());
        let target_addr: SocketAddr = format!("{}:{}", target_ip, target_port).parse()?;
        
        let probe_data = match protocol {
            IoTProtocol::SSDP => SSDPProbe::build_probe(),
            IoTProtocol::MDNS => MDNSProbe::build_probe(),
            IoTProtocol::WSDD => WSDDProbe::build_probe(),
            IoTProtocol::SNMP => SNMPProbe::build_probe("public"),
            IoTProtocol::CoAP => CoAPProbe::build_probe(),
            IoTProtocol::MQTT => MQTTProbe::build_probe(),
        };
        
        let socket = match target_addr {
            SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0")?,
            SocketAddr::V6(_) => UdpSocket::bind("[::]:0")?,
        };
        
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.send_to(&probe_data, target_addr)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssdp_probe_build() {
        let probe = SSDPProbe::build_probe();
        assert!(probe.len() > 0);
        assert!(probe.windows(4).any(|w| w == b"M-SE"));
    }

    #[test]
    fn test_protocol_from_str() {
        assert_eq!(IoTProtocol::from_str("ssdp"), Some(IoTProtocol::SSDP));
        assert_eq!(IoTProtocol::from_str("MDNS"), Some(IoTProtocol::MDNS));
        assert_eq!(IoTProtocol::from_str("invalid"), None);
    }
}

