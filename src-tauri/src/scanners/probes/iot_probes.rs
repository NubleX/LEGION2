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
/// Based on NSE library dnssd.lua - implements mDNS service discovery with proper DNS parsing
pub struct MDNSProbe;

impl MDNSProbe {
    /// Build mDNS query for _services._dns-sd._udp.local
    /// Based on NSE library dnssd.lua Helper.queryAllServices
    pub fn build_probe() -> Vec<u8> {
        // Manual DNS packet construction (dns-parser 0.9 doesn't have a Builder API)
        let mut packet = Vec::new();
        
        // Transaction ID (random)
        let tx_id = rand::random::<u16>();
        packet.extend_from_slice(&tx_id.to_be_bytes());
        
        // Flags: Standard query (for mDNS, typically 0x0000 - no recursion desired)
        packet.extend_from_slice(&0x0000u16.to_be_bytes());
        
        // Questions: 1
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        // Answer/Authority/Additional RRs: 0
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        
        // Query name: _services._dns-sd._udp.local
        // DNS name encoding: length byte + label, terminated by 0x00
        let query_name = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00";
        packet.extend_from_slice(query_name);
        
        // Type: PTR (12)
        packet.extend_from_slice(&12u16.to_be_bytes());
        
        // Class: IN (1)
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        packet
    }

    /// Parse mDNS response
    /// Based on NSE library dnssd.lua Comm.decodeRecords and Helper.queryServices
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        use dns_parser::{Packet, RData};
        
        let mut device_info = HashMap::new();
        
        // Parse DNS packet using dns-parser crate
        match Packet::parse(data) {
            Ok(packet) => {
                device_info.insert(
                    "response_received".to_string(),
                    serde_json::Value::Bool(true),
                );
                
                // Extract service names from PTR records (answers)
                let mut services = Vec::new();
                for answer in packet.answers {
                    if let RData::PTR(name) = answer.data {
                        let service_name = name.to_string();
                        services.push(serde_json::Value::String(service_name));
                    }
                }
                
                // Extract additional records (SRV, TXT, A, AAAA)
                let mut additional_info = serde_json::Map::new();
                let mut ipv4_addrs = Vec::new();
                let mut ipv6_addrs = Vec::new();
                let mut txt_records = Vec::new();
                let mut srv_records = Vec::new();
                
                for additional in packet.additional {
                    match additional.data {
                        RData::A(addr) => {
                            ipv4_addrs.push(serde_json::Value::String(addr.0.to_string()));
                        }
                        RData::AAAA(addr) => {
                            ipv6_addrs.push(serde_json::Value::String(addr.0.to_string()));
                        }
                        RData::TXT(txt) => {
                            // TXT records are key-value pairs
                            let txt_str = txt.iter()
                                .filter_map(|bytes| String::from_utf8(bytes.to_vec()).ok())
                                .collect::<Vec<_>>()
                                .join(" ");
                            if !txt_str.is_empty() {
                                txt_records.push(serde_json::Value::String(txt_str));
                            }
                        }
                        RData::SRV(srv_data) => {
                            // SRV record structure in dns-parser 0.8
                            let mut srv = serde_json::Map::new();
                            srv.insert("priority".to_string(), (srv_data.priority as i64).into());
                            srv.insert("weight".to_string(), (srv_data.weight as i64).into());
                            srv.insert("port".to_string(), (srv_data.port as i64).into());
                            srv.insert("target".to_string(), srv_data.target.to_string().into());
                            srv_records.push(srv.into());
                        }
                        RData::PTR(name) => {
                            // Additional PTR records
                            services.push(serde_json::Value::String(name.to_string()));
                        }
                        _ => {}
                    }
                }
                
                if !services.is_empty() {
                    device_info.insert(
                        "services".to_string(),
                        serde_json::Value::Array(services),
                    );
                }
                
                if !ipv4_addrs.is_empty() {
                    additional_info.insert("ipv4".to_string(), serde_json::Value::Array(ipv4_addrs));
                }
                
                if !ipv6_addrs.is_empty() {
                    additional_info.insert("ipv6".to_string(), serde_json::Value::Array(ipv6_addrs));
                }
                
                if !txt_records.is_empty() {
                    additional_info.insert("txt_records".to_string(), serde_json::Value::Array(txt_records));
                }
                
                if !srv_records.is_empty() {
                    additional_info.insert("srv_records".to_string(), serde_json::Value::Array(srv_records));
                }
                
                if !additional_info.is_empty() {
                    device_info.insert(
                        "additional_info".to_string(),
                        additional_info.into(),
                    );
                }
                
                // Extract hostname from questions or answers
                if let Some(question) = packet.questions.first() {
                    device_info.insert(
                        "query_name".to_string(),
                        serde_json::Value::String(question.qname.to_string()),
                    );
                }
            }
            Err(_) => {
                // Not a valid DNS packet, but mark as received
                device_info.insert(
                    "response_received".to_string(),
                    serde_json::Value::Bool(true),
                );
                device_info.insert(
                    "packet_length".to_string(),
                    serde_json::Value::Number(Number::from(data.len())),
                );
            }
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
/// Based on NSE library snmp.lua - implements SNMP v2c GetRequest with proper ASN.1 DER encoding
pub struct SNMPProbe;

impl SNMPProbe {
    /// Encode ASN.1 length field
    fn encode_length(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else {
            let mut bytes = Vec::new();
            let mut n = len;
            while n > 0 {
                bytes.push((n & 0xFF) as u8);
                n >>= 8;
            }
            bytes.reverse();
            vec![0x80 | bytes.len() as u8]
                .into_iter()
                .chain(bytes.into_iter())
                .collect()
        }
    }

    /// Encode OID component (base 128 encoding)
    fn encode_oid_component(value: u32) -> Vec<u8> {
        let mut result = Vec::new();
        let mut val = value;
        
        while val >= 128 {
            result.push((0x80 | (val & 0x7F)) as u8);
            val >>= 7;
        }
        result.push((val & 0x7F) as u8);
        result
    }

    /// Encode OID string to ASN.1 format
    /// OID format: 1.3.6.1.2.1.1.1.0 -> encoded bytes
    fn encode_oid(oid_str: &str) -> Vec<u8> {
        let parts: Vec<u32> = oid_str
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        
        if parts.len() < 2 {
            return Vec::new();
        }
        
        // First two components encoded as: first * 40 + second
        let mut encoded = vec![(parts[0] * 40 + parts[1]) as u8];
        
        // Encode remaining components
        for &part in parts.iter().skip(2) {
            encoded.extend_from_slice(&Self::encode_oid_component(part));
        }
        
        encoded
    }

    /// Encode ASN.1 INTEGER
    fn encode_integer(value: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut val = value as u64;
        
        // Handle negative numbers
        if value < 0 {
            val = (!value as u64) + 1;
        }
        
        // Encode in big-endian
        while val > 0 || bytes.is_empty() {
            bytes.push((val & 0xFF) as u8);
            val >>= 8;
        }
        bytes.reverse();
        
        // Remove leading zeros (except for value 0)
        while bytes.len() > 1 && bytes[0] == 0 && (bytes[1] & 0x80 == 0) {
            bytes.remove(0);
        }
        while bytes.len() > 1 && bytes[0] == 0xFF && (bytes[1] & 0x80 != 0) {
            bytes.remove(0);
        }
        
        bytes
    }

    /// Encode ASN.1 OCTET STRING
    fn encode_octet_string(data: &[u8]) -> Vec<u8> {
        let mut result = vec![0x04]; // OCTET STRING tag
        result.extend_from_slice(&Self::encode_length(data.len()));
        result.extend_from_slice(data);
        result
    }

    /// Encode ASN.1 SEQUENCE
    fn encode_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
        let mut content = Vec::new();
        for elem in elements {
            content.extend_from_slice(elem);
        }
        let mut result = vec![0x30]; // SEQUENCE tag
        result.extend_from_slice(&Self::encode_length(content.len()));
        result.extend_from_slice(&content);
        result
    }

    /// Build SNMP v2c GetRequest for system description (OID 1.3.6.1.2.1.1.1.0)
    /// Based on NSE library snmp.lua buildGetRequest function
    pub fn build_probe(community: &str) -> Vec<u8> {
        // Generate random request ID (0-65000)
        let req_id = (rand::random::<u32>() % 65000) as i32;
        
        // Encode OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        let oid_encoded = Self::encode_oid("1.3.6.1.2.1.1.1.0");
        let oid_tag = vec![0x06]; // OID tag
        let mut oid_element = oid_tag;
        oid_element.extend_from_slice(&Self::encode_length(oid_encoded.len()));
        oid_element.extend_from_slice(&oid_encoded);
        
        // NULL value for GetRequest
        let null_value = vec![0x05, 0x00]; // NULL tag + length 0
        
        // VarBind: SEQUENCE of {OID, NULL}
        let varbind = Self::encode_sequence(&[oid_element, null_value]);
        
        // VarBindList: SEQUENCE of VarBind
        let varbind_list = Self::encode_sequence(&[varbind]);
        
        // GetRequest-PDU: SEQUENCE {requestID, error-status, error-index, variable-bindings}
        // Tag 0xA0 = GetRequest-PDU (context-specific, constructed)
        let req_id_encoded = {
            let mut result = vec![0x02]; // INTEGER tag
            let id_bytes = Self::encode_integer(req_id);
            result.extend_from_slice(&Self::encode_length(id_bytes.len()));
            result.extend_from_slice(&id_bytes);
            result
        };
        
        let error_status = {
            let mut result = vec![0x02]; // INTEGER tag
            let err_bytes = Self::encode_integer(0); // noError
            result.extend_from_slice(&Self::encode_length(err_bytes.len()));
            result.extend_from_slice(&err_bytes);
            result
        };
        
        let error_index = {
            let mut result = vec![0x02]; // INTEGER tag
            let idx_bytes = Self::encode_integer(0);
            result.extend_from_slice(&Self::encode_length(idx_bytes.len()));
            result.extend_from_slice(&idx_bytes);
            result
        };
        
        let pdu_content = vec![req_id_encoded, error_status, error_index, varbind_list];
        let mut pdu = vec![0xA0]; // GetRequest-PDU tag
        let pdu_elements: Vec<Vec<u8>> = pdu_content.iter().cloned().collect();
        let pdu_encoded = Self::encode_sequence(&pdu_elements);
        pdu.extend_from_slice(&pdu_encoded[1..]); // Skip SEQUENCE tag, use our PDU tag
        
        // SNMP Message: SEQUENCE {version, community, PDU}
        let version = {
            let mut result = vec![0x02]; // INTEGER tag
            let ver_bytes = Self::encode_integer(1); // SNMPv2c
            result.extend_from_slice(&Self::encode_length(ver_bytes.len()));
            result.extend_from_slice(&ver_bytes);
            result
        };
        
        let community_encoded = Self::encode_octet_string(community.as_bytes());
        
        let message_elements = vec![version, community_encoded, pdu];
        Self::encode_sequence(&message_elements)
    }

    /// Parse SNMP response - extracts system description and other OID values
    /// Based on NSE library snmp.lua decode function
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        let mut device_info = HashMap::new();
        
        if data.len() < 4 || data[0] != 0x30 {
            // Not a valid SNMP message (should start with SEQUENCE 0x30)
            return Ok(IoTProbeResponse {
                protocol: IoTProtocol::SNMP,
                source_ip: String::new(),
                source_port: 161,
                device_info,
                raw_response: data.to_vec(),
            });
        }
        
        device_info.insert(
            "response_received".to_string(),
            serde_json::Value::Bool(true),
        );
        
        // Try to find Response-PDU marker (0xA2)
        if data.iter().any(|&b| b == 0xA2) {
            device_info.insert(
                "pdu_type".to_string(),
                serde_json::Value::String("response".to_string()),
            );
            
            // Try to extract system description from response
            // Look for OID 1.3.6.1.2.1.1.1.0 followed by OCTET STRING (0x04)
            if let Some(oid_pos) = Self::find_oid_in_response(data, &[1, 3, 6, 1, 2, 1, 1, 1, 0]) {
                if let Some(sys_descr) = Self::extract_string_after_oid(data, oid_pos) {
                    device_info.insert(
                        "system_description".to_string(),
                        serde_json::Value::String(sys_descr),
                    );
                }
            }
        }
        
        device_info.insert(
            "packet_length".to_string(),
            serde_json::Value::Number(Number::from(data.len())),
        );

        Ok(IoTProbeResponse {
            protocol: IoTProtocol::SNMP,
            source_ip: String::new(),
            source_port: 161,
            device_info,
            raw_response: data.to_vec(),
        })
    }

    /// Find OID in SNMP response (simplified search)
    fn find_oid_in_response(data: &[u8], _oid: &[u32]) -> Option<usize> {
        // Simplified OID search - look for pattern
        // In practice, would need full ASN.1 parsing
        // For now, just check if response contains expected structure
        if data.len() > 20 {
            // OID 1.3.6.1.2.1.1.1.0 encoded as: 0x2b 0x06 0x01 0x02 0x01 0x01 0x01 0x00
            // 0x2b = 1*40 + 3 = 43
            let oid_pattern = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
            for i in 0..data.len().saturating_sub(oid_pattern.len()) {
                if data[i..].starts_with(oid_pattern) {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Extract string value after OID in SNMP response
    fn extract_string_after_oid(data: &[u8], oid_pos: usize) -> Option<String> {
        // Look for OCTET STRING tag (0x04) after OID
        let search_start = oid_pos + 8; // Skip OID
        for i in search_start..data.len().saturating_sub(2) {
            if data[i] == 0x04 {
                // Found OCTET STRING tag
                if i + 1 < data.len() {
                    let len = data[i + 1] as usize;
                    if i + 2 + len <= data.len() {
                        let string_data = &data[i + 2..i + 2 + len];
                        if let Ok(s) = String::from_utf8(string_data.to_vec()) {
                            return Some(s);
                        }
                    }
                }
            }
        }
        None
    }
}

/// CoAP Probe Implementation
/// Based on NSE library coap.lua - implements CoAP GET request with proper option encoding
pub struct CoAPProbe;

impl CoAPProbe {
    /// Build CoAP GET request for /.well-known/core
    /// Based on NSE library coap.lua COAP.header.build and COAP.header.options.build
    pub fn build_probe() -> Vec<u8> {
        // CoAP packet structure (RFC 7252):
        // Byte 0: Version (2 bits) + Type (2 bits) + Token Length (4 bits)
        // Byte 1: Code (GET = 0.01 = 0x01)
        // Bytes 2-3: Message ID
        // Options: Uri-Path: .well-known, Uri-Path: core
        
        let mut packet = Vec::new();
        
        // Header: Version=1, Type=Non-Confirmable (1), Token Length=0
        // ver << 6 | type << 4 | tkl
        // 1 << 6 = 0x40, 1 << 4 = 0x10, 0 = 0x00
        // 0x40 | 0x10 | 0x00 = 0x50
        packet.push(0x50);
        
        // Code: GET (0.01) = 0x01
        packet.push(0x01);
        
        // Message ID (random)
        let msg_id = rand::random::<u16>();
        packet.extend_from_slice(&msg_id.to_be_bytes());
        
        // Token (empty, tkl=0)
        // No token bytes
        
        // Options: Uri-Path options
        // Option format: Option Delta (4 bits) | Option Length (4 bits) | Option Value
        // Uri-Path option number = 11
        // First option: delta=11, length=11, value=".well-known"
        let opt1_delta = 11u8; // Uri-Path
        let opt1_value = b".well-known";
        let opt1_len = opt1_value.len() as u8;
        packet.push((opt1_delta << 4) | opt1_len);
        packet.extend_from_slice(opt1_value);
        
        // Second option: delta=0 (same option number), length=4, value="core"
        let opt2_delta = 0u8; // Same option (Uri-Path)
        let opt2_value = b"core";
        let opt2_len = opt2_value.len() as u8;
        packet.push((opt2_delta << 4) | opt2_len);
        packet.extend_from_slice(opt2_value);
        
        // No payload marker (0xFF) needed for GET request
        
        packet
    }

    /// Parse CoAP response (Link-Format)
    /// Based on NSE library coap.lua COAP.parse and COAP.payload.application_link_format.parse
    pub fn parse_response(data: &[u8]) -> Result<IoTProbeResponse> {
        let mut device_info = HashMap::new();
        
        if data.len() < 4 {
            return Ok(IoTProbeResponse {
                protocol: IoTProtocol::CoAP,
                source_ip: String::new(),
                source_port: 5683,
                device_info,
                raw_response: data.to_vec(),
            });
        }
        
        // Parse fixed header
        let ver_type_tkl = data[0];
        let version = (ver_type_tkl >> 6) & 0x03;
        let message_type = (ver_type_tkl >> 4) & 0x03;
        let token_length = ver_type_tkl & 0x0F;
        
        if version != 1 {
            // Invalid CoAP version
            return Ok(IoTProbeResponse {
                protocol: IoTProtocol::CoAP,
                source_ip: String::new(),
                source_port: 5683,
                device_info,
                raw_response: data.to_vec(),
            });
        }
        
        device_info.insert(
            "response_received".to_string(),
            serde_json::Value::Bool(true),
        );
        
        // Parse code (class and detail)
        let code_byte = data[1];
        let code_class = (code_byte >> 5) & 0x07;
        let code_detail = code_byte & 0x1F;
        let code_str = format!("{}.{:02}", code_class, code_detail);
        device_info.insert(
            "code".to_string(),
            serde_json::Value::String(code_str),
        );
        
        // Parse message type
        let type_str = match message_type {
            0 => "confirmable",
            1 => "non-confirmable",
            2 => "acknowledgement",
            3 => "reset",
            _ => "unknown",
        };
        device_info.insert(
            "type".to_string(),
            serde_json::Value::String(type_str.to_string()),
        );
        
        // Parse message ID
        if data.len() >= 4 {
            let msg_id = u16::from_be_bytes([data[2], data[3]]);
            device_info.insert(
                "message_id".to_string(),
                serde_json::Value::Number(Number::from(msg_id)),
            );
        }
        
        // Skip token if present
        let mut pos = 4 + token_length as usize;
        
        // Parse options (simplified - just skip them for now)
        // In full implementation, would parse Uri-Path, Content-Format, etc.
        while pos < data.len() && data[pos] != 0xFF {
            if data[pos] == 0xFF {
                break; // Payload marker
            }
            let opt_byte = data[pos];
            let opt_delta = (opt_byte >> 4) & 0x0F;
            let opt_length = opt_byte & 0x0F;
            
            // Extended delta/length handling (simplified)
            pos += 1;
            if opt_delta == 13 {
                pos += 1; // Extended delta
            } else if opt_delta == 14 {
                pos += 2; // Extended delta
            }
            if opt_length == 13 {
                pos += 1; // Extended length
            } else if opt_length == 14 {
                pos += 2; // Extended length
            }
            
            pos += opt_length as usize;
        }
        
        // Extract payload (Link-Format)
        if pos < data.len() && data[pos] == 0xFF {
            pos += 1; // Skip payload marker
            if pos < data.len() {
                let payload = &data[pos..];
                if let Ok(link_format) = String::from_utf8(payload.to_vec()) {
                    // Parse Link-Format resources (RFC 6690)
                    // Format: </path>;attr1=val1;attr2=val2,</path2>;attr=val
                    let resources: Vec<serde_json::Value> = link_format
                        .split(',')
                        .filter_map(|link| {
                            let link = link.trim();
                            if link.is_empty() {
                                return None;
                            }
                            
                            // Extract path and attributes
                            if let Some((path, attrs)) = link.split_once(';') {
                                let path = path.trim().trim_matches(|c| c == '<' || c == '>');
                                let mut resource = serde_json::Map::new();
                                resource.insert("path".to_string(), path.into());
                                
                                // Parse attributes
                                let mut attrs_map = serde_json::Map::new();
                                for attr in attrs.split(';') {
                                    if let Some((key, val)) = attr.split_once('=') {
                                        attrs_map.insert(
                                            key.trim().to_string(),
                                            val.trim().trim_matches('"').into(),
                                        );
                                    } else {
                                        attrs_map.insert(attr.trim().to_string(), true.into());
                                    }
                                }
                                if !attrs_map.is_empty() {
                                    resource.insert("attributes".to_string(), attrs_map.into());
                                }
                                
                                Some(resource.into())
                            } else {
                                // Just a path
                                let path = link.trim().trim_matches(|c| c == '<' || c == '>');
                                let mut resource = serde_json::Map::new();
                                resource.insert("path".to_string(), path.into());
                                Some(resource.into())
                            }
                        })
                        .collect();
                    
                    if !resources.is_empty() {
                        device_info.insert(
                            "parsed_resources".to_string(),
                            serde_json::Value::Array(resources),
                        );
                    }
                    
                    // Store raw link format string
                    device_info.insert(
                        "resources".to_string(),
                        serde_json::Value::String(link_format),
                    );
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

