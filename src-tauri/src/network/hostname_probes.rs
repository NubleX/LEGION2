// LEGION2 - Stealthy hostname discovery probes
// Copyright (c) 2025 NubleX / Igor Dunaev

use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::timeout;

/// Result of a hostname probe query
#[derive(Debug, Clone)]
pub struct HostnameProbeResult {
    pub hostname: Option<String>,
    pub protocol: String,
    pub source_ip: IpAddr,
}

/// NetBIOS Name Query (UDP 137)
/// Queries a known Windows device for the NetBIOS name of a target IP
pub struct NetBIOSNameQuery;

impl NetBIOSNameQuery {
    /// Query a known host for NetBIOS name of target IP
    pub async fn query(
        known_host: IpAddr,
        target_ip: IpAddr,
    ) -> Result<HostnameProbeResult> {
        let socket = TokioUdpSocket::bind("0.0.0.0:0").await?;

        // Build NetBIOS NAME_QUERY_REQUEST packet
        let mut packet = Vec::new();
        
        // Transaction ID (random)
        let tx_id = rand::random::<u16>();
        packet.extend_from_slice(&tx_id.to_be_bytes());
        
        // Flags: Standard query (0x0110 = recursion desired, standard query)
        packet.extend_from_slice(&0x0110u16.to_be_bytes());
        
        // Questions: 1
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        // Answer/Authority/Additional RRs: 0
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        
        // Query name: Convert IP to NetBIOS name format
        // For reverse lookup, we use the IP in reverse format
        let ip_bytes = match target_ip {
            IpAddr::V4(ipv4) => ipv4.octets(),
            IpAddr::V6(_) => {
                return Err(anyhow::anyhow!("IPv6 not supported for NetBIOS queries"));
            }
        };
        
        // NetBIOS name: <IP>#<00> (16 bytes padded, then type 0x00)
        let mut name = format!("{:02X}{:02X}{:02X}{:02X}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
        name.push_str("#00");
        
        // Encode NetBIOS name (16 bytes, each byte encoded as two ASCII chars)
        let encoded_name = Self::encode_netbios_name(&name);
        packet.extend_from_slice(&encoded_name);
        
        // Type: NB (0x0020) for NetBIOS name
        packet.extend_from_slice(&0x0020u16.to_be_bytes());
        
        // Class: IN (0x0001)
        packet.extend_from_slice(&0x0001u16.to_be_bytes());
        
        // Send to known host on port 137
        let target = SocketAddr::new(known_host, 137);
        socket.send_to(&packet, target).await?;
        
        // Wait for response
        let mut buf = [0u8; 512];
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                let response = &buf[..len];
                let hostname = Self::parse_response(response)?;
                Ok(HostnameProbeResult {
                    hostname,
                    protocol: "netbios".to_string(),
                    source_ip: known_host,
                })
            }
            _ => {
                // Timeout or error - return empty result
                Ok(HostnameProbeResult {
                    hostname: None,
                    protocol: "netbios".to_string(),
                    source_ip: known_host,
                })
            }
        }
    }
    
    /// Encode NetBIOS name (16 bytes, each byte encoded as two ASCII chars)
    fn encode_netbios_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        let name_bytes = name.as_bytes();
        let mut padded = [0u8; 16];
        let copy_len = name_bytes.len().min(16);
        padded[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        
        for &byte in &padded {
            // NetBIOS encoding: each byte becomes two bytes
            // First byte: (byte >> 4) + 'A'
            // Second byte: (byte & 0x0F) + 'A'
            encoded.push(((byte >> 4) & 0x0F) + b'A');
            encoded.push((byte & 0x0F) + b'A');
        }
        
        encoded
    }
    
    /// Parse NetBIOS NAME_QUERY_RESPONSE
    fn parse_response(data: &[u8]) -> Result<Option<String>> {
        // Basic parsing - look for name in response
        // Full parsing would require proper NetBIOS protocol parsing
        if data.len() < 12 {
            return Ok(None);
        }
        
        // Check if this is a valid NetBIOS response
        // Response should have answers > 0
        let answers = u16::from_be_bytes([data[6], data[7]]);
        if answers == 0 {
            return Ok(None);
        }
        
        // Try to extract name from response
        // This is simplified - full parsing would decode NetBIOS name format
        // For now, return None and let other protocols try
        Ok(None)
    }
}

/// LLMNR Query (Link-Local Multicast Name Resolution)
/// Queries known devices using LLMNR protocol
pub struct LLMNRQuery;

impl LLMNRQuery {
    /// Query known device for hostname using LLMNR
    pub async fn query(
        known_host: IpAddr,
        target_ip: IpAddr,
    ) -> Result<HostnameProbeResult> {
        let socket = TokioUdpSocket::bind("0.0.0.0:0").await?;
        
        // Build LLMNR query packet (similar to DNS)
        let mut packet = Vec::new();
        
        // Transaction ID
        let tx_id = rand::random::<u16>();
        packet.extend_from_slice(&tx_id.to_be_bytes());
        
        // Flags: Standard query with recursion desired
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        
        // Questions: 1
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        // Answer/Authority/Additional RRs: 0
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        
        // Query name: Convert IP to reverse format for PTR query
        let query_name = Self::ip_to_ptr_name(target_ip)?;
        packet.extend_from_slice(&query_name);
        
        // Type: PTR (12)
        packet.extend_from_slice(&12u16.to_be_bytes());
        
        // Class: IN (1)
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        // Send to known host on port 5355 (LLMNR)
        let target = SocketAddr::new(known_host, 5355);
        socket.send_to(&packet, target).await?;
        
        // Wait for response
        let mut buf = [0u8; 512];
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                let response = &buf[..len];
                let hostname = Self::parse_response(response)?;
                Ok(HostnameProbeResult {
                    hostname,
                    protocol: "llmnr".to_string(),
                    source_ip: known_host,
                })
            }
            _ => {
                Ok(HostnameProbeResult {
                    hostname: None,
                    protocol: "llmnr".to_string(),
                    source_ip: known_host,
                })
            }
        }
    }
    
    /// Convert IP to PTR query name format
    fn ip_to_ptr_name(ip: IpAddr) -> Result<Vec<u8>> {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Reverse: 1.2.3.4 -> 4.3.2.1.in-addr.arpa
                let name = format!("{}.{}.{}.{}.in-addr.arpa", 
                    octets[3], octets[2], octets[1], octets[0]);
                Self::encode_dns_name(&name)
            }
            IpAddr::V6(_) => {
                Err(anyhow::anyhow!("IPv6 PTR not implemented"))
            }
        }
    }
    
    /// Encode DNS name format
    fn encode_dns_name(name: &str) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        for part in name.split('.') {
            if part.len() > 63 {
                return Err(anyhow::anyhow!("DNS label too long"));
            }
            encoded.push(part.len() as u8);
            encoded.extend_from_slice(part.as_bytes());
        }
        encoded.push(0); // Null terminator
        Ok(encoded)
    }
    
    /// Parse LLMNR response
    fn parse_response(data: &[u8]) -> Result<Option<String>> {
        // Basic DNS response parsing
        if data.len() < 12 {
            return Ok(None);
        }
        
        // Check answers count
        let answers = u16::from_be_bytes([data[6], data[7]]);
        if answers == 0 {
            return Ok(None);
        }
        
        // Simplified parsing - would need full DNS parser for production
        // For now, return None to let other protocols try
        Ok(None)
    }
}

/// SMB NetBIOS Name Query
/// Queries SMB services on known hosts for NetBIOS name information
pub struct SMBNameQuery;

impl SMBNameQuery {
    /// Query SMB service on known host for NetBIOS name
    pub async fn query(
        known_host: IpAddr,
        _target_ip: IpAddr,
    ) -> Result<HostnameProbeResult> {
        // Try to connect to SMB service and extract NetBIOS name
        // This would require SMB protocol implementation
        // For now, return empty result
        // TODO: Implement SMB NetBIOS name extraction
        
        Ok(HostnameProbeResult {
            hostname: None,
            protocol: "smb".to_string(),
            source_ip: known_host,
        })
    }
}

/// mDNS Hostname Query
/// Queries known mDNS-capable devices for .local hostnames
pub struct MDNSHostnameQuery;

impl MDNSHostnameQuery {
    /// Query known mDNS device for hostname
    pub async fn query(
        known_host: IpAddr,
        target_ip: IpAddr,
    ) -> Result<HostnameProbeResult> {
        let socket = TokioUdpSocket::bind("0.0.0.0:0").await?;
        
        // Build mDNS PTR query for reverse lookup
        let mut packet = Vec::new();
        
        // Transaction ID
        let tx_id = rand::random::<u16>();
        packet.extend_from_slice(&tx_id.to_be_bytes());
        
        // Flags: Standard query
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        
        // Questions: 1
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        // Answer/Authority/Additional RRs: 0
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        
        // Query name: IP in reverse format for .local
        let query_name = Self::ip_to_local_ptr(target_ip)?;
        packet.extend_from_slice(&query_name);
        
        // Type: PTR (12)
        packet.extend_from_slice(&12u16.to_be_bytes());
        
        // Class: IN (1)
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        // Send to known host on port 5353 (mDNS)
        let target = SocketAddr::new(known_host, 5353);
        socket.send_to(&packet, target).await?;
        
        // Wait for response
        let mut buf = [0u8; 512];
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                let response = &buf[..len];
                let hostname = Self::parse_response(response)?;
                Ok(HostnameProbeResult {
                    hostname,
                    protocol: "mdns".to_string(),
                    source_ip: known_host,
                })
            }
            _ => {
                Ok(HostnameProbeResult {
                    hostname: None,
                    protocol: "mdns".to_string(),
                    source_ip: known_host,
                })
            }
        }
    }
    
    /// Convert IP to .local PTR format
    fn ip_to_local_ptr(ip: IpAddr) -> Result<Vec<u8>> {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Format: 4.3.2.1.in-addr.arpa
                let name = format!("{}.{}.{}.{}.in-addr.arpa", 
                    octets[3], octets[2], octets[1], octets[0]);
                LLMNRQuery::encode_dns_name(&name)
            }
            IpAddr::V6(_) => {
                Err(anyhow::anyhow!("IPv6 not implemented for mDNS"))
            }
        }
    }
    
    /// Parse mDNS response
    fn parse_response(data: &[u8]) -> Result<Option<String>> {
        // Basic DNS response parsing
        if data.len() < 12 {
            return Ok(None);
        }
        
        // Check answers count
        let answers = u16::from_be_bytes([data[6], data[7]]);
        if answers == 0 {
            return Ok(None);
        }
        
        // Simplified parsing - would need full DNS parser
        Ok(None)
    }
}

/// Local DNS Server Query
/// Queries discovered DNS servers for reverse DNS (PTR records)
pub struct LocalDNSQuery;

impl LocalDNSQuery {
    /// Query local DNS server for reverse DNS
    pub async fn query(
        dns_server: IpAddr,
        target_ip: IpAddr,
    ) -> Result<HostnameProbeResult> {
        let socket = TokioUdpSocket::bind("0.0.0.0:0").await?;
        
        // Build DNS PTR query
        let mut packet = Vec::new();
        
        // Transaction ID
        let tx_id = rand::random::<u16>();
        packet.extend_from_slice(&tx_id.to_be_bytes());
        
        // Flags: Standard query with recursion desired
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        
        // Questions: 1
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        // Answer/Authority/Additional RRs: 0
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        
        // Query name: Reverse IP for PTR
        let query_name = LLMNRQuery::ip_to_ptr_name(target_ip)?;
        packet.extend_from_slice(&query_name);
        
        // Type: PTR (12)
        packet.extend_from_slice(&12u16.to_be_bytes());
        
        // Class: IN (1)
        packet.extend_from_slice(&1u16.to_be_bytes());
        
        // Send to DNS server on port 53
        let target = SocketAddr::new(dns_server, 53);
        socket.send_to(&packet, target).await?;
        
        // Wait for response
        let mut buf = [0u8; 512];
        match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                let response = &buf[..len];
                let hostname = Self::parse_response(response)?;
                Ok(HostnameProbeResult {
                    hostname,
                    protocol: "dns".to_string(),
                    source_ip: dns_server,
                })
            }
            _ => {
                Ok(HostnameProbeResult {
                    hostname: None,
                    protocol: "dns".to_string(),
                    source_ip: dns_server,
                })
            }
        }
    }
    
    /// Parse DNS response
    fn parse_response(data: &[u8]) -> Result<Option<String>> {
        // Basic DNS response parsing
        if data.len() < 12 {
            return Ok(None);
        }
        
        // Check answers count
        let answers = u16::from_be_bytes([data[6], data[7]]);
        if answers == 0 {
            return Ok(None);
        }
        
        // Simplified parsing - would need full DNS parser for production
        // For now, return None
        Ok(None)
    }
}

