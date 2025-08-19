//! Protocol definitions for network scanning and IoT device discovery
//!
//! This module provides comprehensive protocol support for:
//! - Standard internet protocols (TCP, UDP, ICMP, etc.)
//! - IoT protocols (MQTT, CoAP, Zigbee, etc.)
//! - Network traversal protocols (UPnP, mDNS, etc.)
//! - Specialized discovery protocols

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Network layer protocols
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NetworkProtocol {
    /// Internet Control Message Protocol
    Icmp,
    /// Internet Group Management Protocol
    Igmp,
    /// Generic Routing Encapsulation
    Gre,
    /// Encapsulating Security Payload
    Esp,
    /// Authentication Header
    Ah,
    /// Internet Protocol version 6
    Ipv6,
    /// IPv6 Hop-by-Hop Option
    Hopopt,
    /// IPv6 Routing Header
    Routing,
    /// IPv6 Fragment Header
    Fragment,
    /// IPv6 Encapsulating Security Payload
    Ipv6Esp,
    /// IPv6 Authentication Header
    Ipv6Ah,
    /// IPv6 No Next Header
    NoNext,
    /// IPv6 Destination Options
    Dstopts,
    /// Mobility Header
    Mobility,
    /// Host Identity Protocol
    Hip,
    /// Shim6 Protocol
    Shim6,
    /// Wrapped Encapsulating Security Payload
    Wesp,
    /// Robust Header Compression
    Rohc,
}

impl NetworkProtocol {
    /// Get protocol number as defined in RFC 1700
    pub fn number(&self) -> u8 {
        match self {
            NetworkProtocol::Icmp => 1,
            NetworkProtocol::Igmp => 2,
            NetworkProtocol::Gre => 47,
            NetworkProtocol::Esp => 50,
            NetworkProtocol::Ah => 51,
            NetworkProtocol::Ipv6 => 41,
            NetworkProtocol::Hopopt => 0,
            NetworkProtocol::Routing => 43,
            NetworkProtocol::Fragment => 44,
            NetworkProtocol::Ipv6Esp => 50,
            NetworkProtocol::Ipv6Ah => 51,
            NetworkProtocol::NoNext => 59,
            NetworkProtocol::Dstopts => 60,
            NetworkProtocol::Mobility => 135,
            NetworkProtocol::Hip => 139,
            NetworkProtocol::Shim6 => 140,
            NetworkProtocol::Wesp => 141,
            NetworkProtocol::Rohc => 142,
        }
    }

    /// Get protocol name
    pub fn name(&self) -> &'static str {
        match self {
            NetworkProtocol::Icmp => "ICMP",
            NetworkProtocol::Igmp => "IGMP",
            NetworkProtocol::Gre => "GRE",
            NetworkProtocol::Esp => "ESP",
            NetworkProtocol::Ah => "AH",
            NetworkProtocol::Ipv6 => "IPv6",
            NetworkProtocol::Hopopt => "HOPOPT",
            NetworkProtocol::Routing => "Routing",
            NetworkProtocol::Fragment => "Fragment",
            NetworkProtocol::Ipv6Esp => "IPv6-ESP",
            NetworkProtocol::Ipv6Ah => "IPv6-AH",
            NetworkProtocol::NoNext => "No Next",
            NetworkProtocol::Dstopts => "Dst Options",
            NetworkProtocol::Mobility => "Mobility",
            NetworkProtocol::Hip => "HIP",
            NetworkProtocol::Shim6 => "Shim6",
            NetworkProtocol::Wesp => "WESP",
            NetworkProtocol::Rohc => "ROHC",
        }
    }

    /// Check if protocol supports network traversal
    pub fn supports_traversal(&self) -> bool {
        matches!(
            self,
            NetworkProtocol::Icmp | NetworkProtocol::Gre | NetworkProtocol::Ipv6
        )
    }
}

impl fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for NetworkProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "icmp" => Ok(NetworkProtocol::Icmp),
            "igmp" => Ok(NetworkProtocol::Igmp),
            "gre" => Ok(NetworkProtocol::Gre),
            "esp" => Ok(NetworkProtocol::Esp),
            "ah" => Ok(NetworkProtocol::Ah),
            "ipv6" => Ok(NetworkProtocol::Ipv6),
            "hopopt" => Ok(NetworkProtocol::Hopopt),
            "routing" => Ok(NetworkProtocol::Routing),
            "fragment" => Ok(NetworkProtocol::Fragment),
            "ipv6-esp" => Ok(NetworkProtocol::Ipv6Esp),
            "ipv6-ah" => Ok(NetworkProtocol::Ipv6Ah),
            "no-next" => Ok(NetworkProtocol::NoNext),
            "dstopts" => Ok(NetworkProtocol::Dstopts),
            "mobility" => Ok(NetworkProtocol::Mobility),
            "hip" => Ok(NetworkProtocol::Hip),
            "shim6" => Ok(NetworkProtocol::Shim6),
            "wesp" => Ok(NetworkProtocol::Wesp),
            "rohc" => Ok(NetworkProtocol::Rohc),
            _ => Err(anyhow::anyhow!("Unknown network protocol: {}", s)),
        }
    }
}

/// Transport layer protocols
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
    /// Stream Control Transmission Protocol
    Sctp,
    /// Datagram Congestion Control Protocol
    Dccp,
    /// Reliable Data Protocol
    Rdp,
    /// Multipath TCP (extension)
    Mptcp,
}

impl TransportProtocol {
    /// Get protocol number
    pub fn number(&self) -> u8 {
        match self {
            TransportProtocol::Tcp => 6,
            TransportProtocol::Udp => 17,
            TransportProtocol::Sctp => 132,
            TransportProtocol::Dccp => 33,
            TransportProtocol::Rdp => 27,
            TransportProtocol::Mptcp => 6, // Same as TCP
        }
    }

    /// Get protocol name
    pub fn name(&self) -> &'static str {
        match self {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
            TransportProtocol::Sctp => "SCTP",
            TransportProtocol::Dccp => "DCCP",
            TransportProtocol::Rdp => "RDP",
            TransportProtocol::Mptcp => "MPTCP",
        }
    }

    /// Check if protocol is connection-oriented
    pub fn is_connection_oriented(&self) -> bool {
        matches!(self, TransportProtocol::Tcp | TransportProtocol::Sctp)
    }

    /// Check if protocol supports multicast
    pub fn supports_multicast(&self) -> bool {
        matches!(self, TransportProtocol::Udp | TransportProtocol::Sctp)
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for TransportProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(TransportProtocol::Tcp),
            "udp" => Ok(TransportProtocol::Udp),
            "sctp" => Ok(TransportProtocol::Sctp),
            "dccp" => Ok(TransportProtocol::Dccp),
            "rdp" => Ok(TransportProtocol::Rdp),
            "mptcp" => Ok(TransportProtocol::Mptcp),
            _ => Err(anyhow::anyhow!("Unknown transport protocol: {}", s)),
        }
    }
}

/// Application layer protocols for discovery and traversal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ApplicationProtocol {
    /// Simple Service Discovery Protocol
    Ssdp,
    /// Multicast DNS
    Mdns,
    /// Link-Local Multicast Name Resolution
    Llmnr,
    /// Dynamic Host Configuration Protocol
    Dhcp,
    /// Dynamic Host Configuration Protocol for IPv6
    Dhcpv6,
    /// Network Time Protocol
    Ntp,
    /// Simple Network Management Protocol
    Snmp,
    /// Syslog
    Syslog,
    /// Border Gateway Protocol
    Bgp,
    /// Open Shortest Path First
    Ospf,
    /// Routing Information Protocol
    Rip,
    /// Internet Group Management Protocol v3
    Igmpv3,
    /// Universal Plug and Play
    Upnp,
    /// Zeroconf
    Zeroconf,
    /// Bonjour
    Bonjour,
    /// Avahi
    Avahi,
    /// MQTT (Message Queuing Telemetry Transport)
    Mqtt,
    /// Constrained Application Protocol
    Coap,
    /// Zigbee IP
    ZigbeeIp,
    /// Thread
    Thread,
    /// LoRaWAN
    Lorawan,
    /// Bluetooth Low Energy
    Ble,
    /// Z-Wave
    Zwave,
    /// KNXnet/IP
    Knx,
    /// BACnet
    Bacnet,
    /// Modbus TCP
    ModbusTcp,
    /// DNP3
    Dnp3,
    /// IEC 61850
    Iec61850,
    /// Profinet
    Profinet,
    /// EtherCAT
    Ethercat,
    /// OPC UA
    Opcua,
    /// DDS (Data Distribution Service)
    Dds,
    /// AMQP (Advanced Message Queuing Protocol)
    Amqp,
    /// CoAP over TCP/TLS
    CoapTcp,
    /// WebSocket
    WebSocket,
    /// WebSocket Secure
    WebSocketSecure,
    /// HTTP/2
    Http2,
    /// HTTP/3
    Http3,
    /// QUIC
    Quic,
    /// gRPC
    Grpc,
    /// SIP (Session Initiation Protocol)
    Sip,
    /// STUN (Session Traversal Utilities for NAT)
    Stun,
    /// TURN (Traversal Using Relays around NAT)
    Turn,
    /// ICE (Interactive Connectivity Establishment)
    Ice,
    /// RTCP (RTP Control Protocol)
    Rtcp,
    /// SRTP (Secure Real-time Transport Protocol)
    Srtp,
    /// DTLS (Datagram Transport Layer Security)
    Dtls,
    /// TLS (Transport Layer Security)
    Tls,
    /// SSL (Secure Sockets Layer)
    Ssl,
}

impl ApplicationProtocol {
    /// Get standard port for protocol (if applicable)
    pub fn default_port(&self) -> Option<u16> {
        match self {
            ApplicationProtocol::Ssdp => Some(1900),
            ApplicationProtocol::Mdns => Some(5353),
            ApplicationProtocol::Llmnr => Some(5355),
            ApplicationProtocol::Dhcp => Some(67),
            ApplicationProtocol::Dhcpv6 => Some(546),
            ApplicationProtocol::Ntp => Some(123),
            ApplicationProtocol::Snmp => Some(161),
            ApplicationProtocol::Syslog => Some(514),
            ApplicationProtocol::Bgp => Some(179),
            ApplicationProtocol::Mqtt => Some(1883),
            ApplicationProtocol::Coap => Some(5683),
            ApplicationProtocol::CoapTcp => Some(5684),
            ApplicationProtocol::WebSocket => Some(80),
            ApplicationProtocol::WebSocketSecure => Some(443),
            ApplicationProtocol::Http2 => Some(443),
            ApplicationProtocol::Http3 => Some(443),
            ApplicationProtocol::Quic => Some(443),
            ApplicationProtocol::Grpc => Some(80),
            ApplicationProtocol::Sip => Some(5060),
            ApplicationProtocol::Stun => Some(3478),
            ApplicationProtocol::Turn => Some(3478),
            _ => None,
        }
    }

    /// Get protocol name
    pub fn name(&self) -> &'static str {
        match self {
            ApplicationProtocol::Ssdp => "SSDP",
            ApplicationProtocol::Mdns => "mDNS",
            ApplicationProtocol::Llmnr => "LLMNR",
            ApplicationProtocol::Dhcp => "DHCP",
            ApplicationProtocol::Dhcpv6 => "DHCPv6",
            ApplicationProtocol::Ntp => "NTP",
            ApplicationProtocol::Snmp => "SNMP",
            ApplicationProtocol::Syslog => "Syslog",
            ApplicationProtocol::Bgp => "BGP",
            ApplicationProtocol::Ospf => "OSPF",
            ApplicationProtocol::Rip => "RIP",
            ApplicationProtocol::Igmpv3 => "IGMPv3",
            ApplicationProtocol::Upnp => "UPnP",
            ApplicationProtocol::Zeroconf => "Zeroconf",
            ApplicationProtocol::Bonjour => "Bonjour",
            ApplicationProtocol::Avahi => "Avahi",
            ApplicationProtocol::Mqtt => "MQTT",
            ApplicationProtocol::Coap => "CoAP",
            ApplicationProtocol::ZigbeeIp => "Zigbee IP",
            ApplicationProtocol::Thread => "Thread",
            ApplicationProtocol::Lorawan => "LoRaWAN",
            ApplicationProtocol::Ble => "BLE",
            ApplicationProtocol::Zwave => "Z-Wave",
            ApplicationProtocol::Knx => "KNXnet/IP",
            ApplicationProtocol::Bacnet => "BACnet",
            ApplicationProtocol::ModbusTcp => "Modbus TCP",
            ApplicationProtocol::Dnp3 => "DNP3",
            ApplicationProtocol::Iec61850 => "IEC 61850",
            ApplicationProtocol::Profinet => "Profinet",
            ApplicationProtocol::Ethercat => "EtherCAT",
            ApplicationProtocol::Opcua => "OPC UA",
            ApplicationProtocol::Dds => "DDS",
            ApplicationProtocol::Amqp => "AMQP",
            ApplicationProtocol::CoapTcp => "CoAP/TCP",
            ApplicationProtocol::WebSocket => "WebSocket",
            ApplicationProtocol::WebSocketSecure => "WebSocket Secure",
            ApplicationProtocol::Http2 => "HTTP/2",
            ApplicationProtocol::Http3 => "HTTP/3",
            ApplicationProtocol::Quic => "QUIC",
            ApplicationProtocol::Grpc => "gRPC",
            ApplicationProtocol::Sip => "SIP",
            ApplicationProtocol::Stun => "STUN",
            ApplicationProtocol::Turn => "TURN",
            ApplicationProtocol::Ice => "ICE",
            ApplicationProtocol::Rtcp => "RTCP",
            ApplicationProtocol::Srtp => "SRTP",
            ApplicationProtocol::Dtls => "DTLS",
            ApplicationProtocol::Tls => "TLS",
            ApplicationProtocol::Ssl => "SSL",
        }
    }

    /// Check if protocol is discovery-related
    pub fn is_discovery_protocol(&self) -> bool {
        matches!(
            self,
            ApplicationProtocol::Ssdp
                | ApplicationProtocol::Mdns
                | ApplicationProtocol::Llmnr
                | ApplicationProtocol::Upnp
                | ApplicationProtocol::Zeroconf
                | ApplicationProtocol::Bonjour
                | ApplicationProtocol::Avahi
        )
    }

    /// Check if protocol is IoT-specific
    pub fn is_iot_protocol(&self) -> bool {
        matches!(
            self,
            ApplicationProtocol::Mqtt
                | ApplicationProtocol::Coap
                | ApplicationProtocol::ZigbeeIp
                | ApplicationProtocol::Thread
                | ApplicationProtocol::Lorawan
                | ApplicationProtocol::Ble
                | ApplicationProtocol::Zwave
                | ApplicationProtocol::Knx
                | ApplicationProtocol::Bacnet
                | ApplicationProtocol::ModbusTcp
                | ApplicationProtocol::Dnp3
                | ApplicationProtocol::Iec61850
                | ApplicationProtocol::Profinet
                | ApplicationProtocol::Ethercat
                | ApplicationProtocol::Opcua
                | ApplicationProtocol::Dds
        )
    }

    /// Check if protocol supports multicast
    pub fn supports_multicast(&self) -> bool {
        matches!(
            self,
            ApplicationProtocol::Mdns
                | ApplicationProtocol::Ssdp
                | ApplicationProtocol::Llmnr
                | ApplicationProtocol::Mqtt
                | ApplicationProtocol::Coap
        )
    }

    /// Check if protocol supports encryption
    pub fn supports_encryption(&self) -> bool {
        matches!(
            self,
            ApplicationProtocol::CoapTcp
                | ApplicationProtocol::WebSocketSecure
                | ApplicationProtocol::Http2
                | ApplicationProtocol::Http3
                | ApplicationProtocol::Quic
                | ApplicationProtocol::Dtls
                | ApplicationProtocol::Tls
                | ApplicationProtocol::Ssl
                | ApplicationProtocol::Opcua
        )
    }
}

impl fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for ApplicationProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "ssdp" => Ok(ApplicationProtocol::Ssdp),
            "mdns" => Ok(ApplicationProtocol::Mdns),
            "llmnr" => Ok(ApplicationProtocol::Llmnr),
            "dhcp" => Ok(ApplicationProtocol::Dhcp),
            "dhcpv6" => Ok(ApplicationProtocol::Dhcpv6),
            "ntp" => Ok(ApplicationProtocol::Ntp),
            "snmp" => Ok(ApplicationProtocol::Snmp),
            "syslog" => Ok(ApplicationProtocol::Syslog),
            "bgp" => Ok(ApplicationProtocol::Bgp),
            "ospf" => Ok(ApplicationProtocol::Ospf),
            "rip" => Ok(ApplicationProtocol::Rip),
            "igmpv3" => Ok(ApplicationProtocol::Igmpv3),
            "upnp" => Ok(ApplicationProtocol::Upnp),
            "zeroconf" => Ok(ApplicationProtocol::Zeroconf),
            "bonjour" => Ok(ApplicationProtocol::Bonjour),
            "avahi" => Ok(ApplicationProtocol::Avahi),
            "mqtt" => Ok(ApplicationProtocol::Mqtt),
            "coap" => Ok(ApplicationProtocol::Coap),
            "zigbeeip" => Ok(ApplicationProtocol::ZigbeeIp),
            "thread" => Ok(ApplicationProtocol::Thread),
            "lorawan" => Ok(ApplicationProtocol::Lorawan),
            "ble" => Ok(ApplicationProtocol::Ble),
            "zwave" => Ok(ApplicationProtocol::Zwave),
            "knx" => Ok(ApplicationProtocol::Knx),
            "bacnet" => Ok(ApplicationProtocol::Bacnet),
            "modbustcp" => Ok(ApplicationProtocol::ModbusTcp),
            "dnp3" => Ok(ApplicationProtocol::Dnp3),
            "iec61850" => Ok(ApplicationProtocol::Iec61850),
            "profinet" => Ok(ApplicationProtocol::Profinet),
            "ethercat" => Ok(ApplicationProtocol::Ethercat),
            "opcua" => Ok(ApplicationProtocol::Opcua),
            "dds" => Ok(ApplicationProtocol::Dds),
            "amqp" => Ok(ApplicationProtocol::Amqp),
            "coaptcp" => Ok(ApplicationProtocol::CoapTcp),
            "websocket" => Ok(ApplicationProtocol::WebSocket),
            "websocketsecure" => Ok(ApplicationProtocol::WebSocketSecure),
            "http2" => Ok(ApplicationProtocol::Http2),
            "http3" => Ok(ApplicationProtocol::Http3),
            "quic" => Ok(ApplicationProtocol::Quic),
            "grpc" => Ok(ApplicationProtocol::Grpc),
            "sip" => Ok(ApplicationProtocol::Sip),
            "stun" => Ok(ApplicationProtocol::Stun),
            "turn" => Ok(ApplicationProtocol::Turn),
            "ice" => Ok(ApplicationProtocol::Ice),
            "rtcp" => Ok(ApplicationProtocol::Rtcp),
            "srtp" => Ok(ApplicationProtocol::Srtp),
            "dtls" => Ok(ApplicationProtocol::Dtls),
            "tls" => Ok(ApplicationProtocol::Tls),
            "ssl" => Ok(ApplicationProtocol::Ssl),
            _ => Err(anyhow::anyhow!("Unknown application protocol: {}", s)),
        }
    }
}

/// Protocol family for categorization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProtocolFamily {
    /// Internet protocols (IPv4/IPv6)
    Internet,
    /// Local area network protocols
    Lan,
    /// Wide area network protocols
    Wan,
    /// IoT protocols
    Iot,
    /// Industrial protocols
    Industrial,
    /// Wireless protocols
    Wireless,
    /// Security protocols
    Security,
    /// Discovery protocols
    Discovery,
    /// Streaming protocols
    Streaming,
    /// Messaging protocols
    Messaging,
}

/// Protocol capabilities for network traversal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolCapabilities {
    /// Supports multicast communication
    pub multicast: bool,
    /// Supports broadcast communication
    pub broadcast: bool,
    /// Supports unicast communication
    pub unicast: bool,
    /// Supports encryption
    pub encryption: bool,
    /// Supports authentication
    pub authentication: bool,
    /// Supports compression
    pub compression: bool,
    /// Supports Quality of Service
    pub qos: bool,
    /// Supports NAT traversal
    pub nat_traversal: bool,
    /// Supports firewall traversal
    pub firewall_traversal: bool,
    /// Supports discovery
    pub discovery: bool,
    /// Supports routing
    pub routing: bool,
    /// Supports mesh networking
    pub mesh_networking: bool,
}

impl Default for ProtocolCapabilities {
    fn default() -> Self {
        Self {
            multicast: false,
            broadcast: false,
            unicast: true,
            encryption: false,
            authentication: false,
            compression: false,
            qos: false,
            nat_traversal: false,
            firewall_traversal: false,
            discovery: false,
            routing: false,
            mesh_networking: false,
        }
    }
}

/// Protocol layer in the network stack
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolLayer {
    /// Physical layer
    Physical,
    /// Data link layer
    DataLink,
    /// Network layer
    Network,
    /// Transport layer
    Transport,
    /// Session layer
    Session,
    /// Presentation layer
    Presentation,
    /// Application layer
    Application,
}

/// Protocol identifier that can represent any protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Protocol {
    Network(NetworkProtocol),
    Transport(TransportProtocol),
    Application(ApplicationProtocol),
}

impl Protocol {
    /// Get protocol name
    pub fn name(&self) -> String {
        match self {
            Protocol::Network(p) => p.name().to_string(),
            Protocol::Transport(p) => p.name().to_string(),
            Protocol::Application(p) => p.name().to_string(),
        }
    }

    /// Get protocol number (if applicable)
    pub fn number(&self) -> Option<u16> {
        match self {
            Protocol::Network(p) => Some(p.number() as u16),
            Protocol::Transport(p) => Some(p.number() as u16),
            Protocol::Application(p) => p.default_port(),
        }
    }

    /// Check if protocol supports network traversal
    pub fn supports_traversal(&self) -> bool {
        match self {
            Protocol::Network(p) => p.supports_traversal(),
            Protocol::Transport(_) => true, // Most transport protocols support traversal
            Protocol::Application(p) => {
                p.is_discovery_protocol()
                    || p.supports_multicast()
                    || matches!(
                        p,
                        ApplicationProtocol::Stun
                            | ApplicationProtocol::Turn
                            | ApplicationProtocol::Ice
                    )
            }
        }
    }

    /// Check if protocol is IoT-specific
    pub fn is_iot(&self) -> bool {
        match self {
            Protocol::Application(p) => p.is_iot_protocol(),
            _ => false,
        }
    }

    /// Check if protocol is discovery-related
    pub fn is_discovery(&self) -> bool {
        match self {
            Protocol::Application(p) => p.is_discovery_protocol(),
            Protocol::Network(p) => matches!(p, NetworkProtocol::Icmp),
            _ => false,
        }
    }

    /// Get protocol family
    pub fn family(&self) -> ProtocolFamily {
        match self {
            Protocol::Network(_) => ProtocolFamily::Internet,
            Protocol::Transport(_) => ProtocolFamily::Internet,
            Protocol::Application(p) => {
                if p.is_iot_protocol() {
                    ProtocolFamily::Iot
                } else if p.is_discovery_protocol() {
                    ProtocolFamily::Discovery
                } else {
                    ProtocolFamily::Internet
                }
            }
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Network(p) => write!(f, "{}", p),
            Protocol::Transport(p) => write!(f, "{}", p),
            Protocol::Application(p) => write!(f, "{}", p),
        }
    }
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // Try to parse as network protocol first
        if let Ok(p) = NetworkProtocol::from_str(s) {
            return Ok(Protocol::Network(p));
        }

        // Try transport protocol
        if let Ok(p) = TransportProtocol::from_str(s) {
            return Ok(Protocol::Transport(p));
        }

        // Try application protocol
        if let Ok(p) = ApplicationProtocol::from_str(s) {
            return Ok(Protocol::Application(p));
        }

        Err(anyhow::anyhow!("Unknown protocol: {}", s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_parsing() {
        let tcp: Protocol = "tcp".parse().unwrap();
        assert!(matches!(tcp, Protocol::Transport(TransportProtocol::Tcp)));

        let icmp: Protocol = "icmp".parse().unwrap();
        assert!(matches!(icmp, Protocol::Network(NetworkProtocol::Icmp)));

        let mqtt: Protocol = "mqtt".parse().unwrap();
        assert!(matches!(
            mqtt,
            Protocol::Application(ApplicationProtocol::Mqtt)
        ));
    }

    #[test]
    fn test_protocol_traversal_support() {
        let icmp = Protocol::Network(NetworkProtocol::Icmp);
        assert!(icmp.supports_traversal());

        let mqtt = Protocol::Application(ApplicationProtocol::Mqtt);
        assert!(!mqtt.supports_traversal());

        let mdns = Protocol::Application(ApplicationProtocol::Mdns);
        assert!(mdns.supports_traversal());
    }

    #[test]
    fn test_protocol_iot_detection() {
        let mqtt = Protocol::Application(ApplicationProtocol::Mqtt);
        assert!(mqtt.is_iot());

        let tcp = Protocol::Transport(TransportProtocol::Tcp);
        assert!(!tcp.is_iot());
    }

    #[test]
    fn test_protocol_discovery_detection() {
        let mdns = Protocol::Application(ApplicationProtocol::Mdns);
        assert!(mdns.is_discovery());

        let icmp = Protocol::Network(NetworkProtocol::Icmp);
        assert!(icmp.is_discovery());

        let tcp = Protocol::Transport(TransportProtocol::Tcp);
        assert!(!tcp.is_discovery());
    }
}
