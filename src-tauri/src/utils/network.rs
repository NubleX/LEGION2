// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.
// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security
//     This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
//     License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
//     version.
//     This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
//     warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//     details.
//     You should have received a copy of the GNU General Public License along with this program.
//     If not, see <http://www.gnu.org/licenses/>.

use std::net::IpAddr;
use anyhow::Result;
use ipnet::IpNet;
use crate::core::registry::Registry;

pub fn parse_cidr_range(cidr: &str) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    
    // Check if it's a single IP or CIDR range
    if !cidr.contains('/') {
        // Single IP address
        let ip: IpAddr = cidr.parse()?;
        ips.push(ip);
        return Ok(ips);
    }
    
    // Parse as CIDR range using ipnet for better compatibility
    let network: IpNet = cidr.parse()?;
    
    match network {
        IpNet::V4(v4_net) => {
            // For IPv4, expand all IPs in the range
            for ip in v4_net.hosts() {
                ips.push(IpAddr::V4(ip));
            }
            // Include network and broadcast addresses if empty
            if ips.is_empty() {
                ips.push(IpAddr::V4(v4_net.network()));
                ips.push(IpAddr::V4(v4_net.broadcast()));
            }
        }
        IpNet::V6(v6_net) => {
            // For IPv6, limit to first 256 addresses for performance
            let mut count = 0;
            for ip in v6_net.hosts() {
                ips.push(IpAddr::V6(ip));
                count += 1;
                if count >= 256 {
                    break;
                }
            }
            // Include network address if no hosts
            if ips.is_empty() {
                ips.push(IpAddr::V6(v6_net.network()));
            }
        }
    }
    
    Ok(ips)
}

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_multicast() || ipv6.is_unspecified()
        }
    }
}

pub fn validate_target_ip(ip: &str) -> Result<IpAddr> {
    let parsed: IpAddr = ip.parse()?;
    Ok(parsed)
}

pub fn parse_target_specification(target: &str) -> Result<Vec<IpAddr>> {
    let mut all_ips = Vec::new();
    
    // Split by commas for multiple targets
    for part in target.split(',') {
        let trimmed = part.trim();
        
        if trimmed.contains('-') {
            // IP range like 192.168.1.1-10
            all_ips.extend(parse_ip_range(trimmed)?);
        } else if trimmed.contains('/') {
            // CIDR notation
            all_ips.extend(parse_cidr_range(trimmed)?);
        } else {
            // Single IP
            let ip: IpAddr = trimmed.parse()?;
            all_ips.push(ip);
        }
    }
    
    // Remove duplicates
    all_ips.sort();
    all_ips.dedup();
    
    Ok(all_ips)
}

fn parse_ip_range(range: &str) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    
    // Handle ranges like 192.168.1.1-10 or 192.168.1.1-192.168.1.10
    if let Some(dash_pos) = range.rfind('-') {
        let start_str = &range[..dash_pos];
        let end_str = &range[dash_pos + 1..];
        
        let start_ip: IpAddr = start_str.parse()?;
        
        // Check if end is full IP or just last octet
        let end_ip: IpAddr = if end_str.contains('.') || end_str.contains(':') {
            end_str.parse()?
        } else {
            // Assume it's just the last part
            match start_ip {
                IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    let end_octet: u8 = end_str.parse()?;
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        octets[0], octets[1], octets[2], end_octet
                    ))
                }
                IpAddr::V6(_) => {
                    return Err(anyhow::anyhow!("IPv6 short range notation not supported"));
                }
            }
        };
        
        // Generate IPs in range
        match (start_ip, end_ip) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                let start_int = u32::from(start);
                let end_int = u32::from(end);
                
                for i in start_int..=end_int {
                    ips.push(IpAddr::V4(std::net::Ipv4Addr::from(i)));
                    // Limit to prevent memory issues
                    if ips.len() > 65536 {
                        return Err(anyhow::anyhow!("Range too large (max 65536 IPs)"));
                    }
                }
            }
            _ => return Err(anyhow::anyhow!("Invalid IP range")),
        }
    }
    
    Ok(ips)
}