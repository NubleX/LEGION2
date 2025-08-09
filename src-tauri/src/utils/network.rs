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
use cidr::IpCidr;

pub fn parse_cidr_range(cidr: &str) -> Result<Vec<IpAddr>> {
    let cidr_parsed: IpCidr = cidr.parse()?;
    let mut ips = Vec::new();
    
    // For IPv4 networks
    if let IpCidr::V4(v4_cidr) = cidr_parsed {
        for ip in v4_cidr.iter() {
            ips.push(IpAddr::V4(ip.address()));
        }
    } else {
        // For IPv6, just add the network address for now
        ips.push(cidr_parsed.first_address());
    }
    
    Ok(ips)
}

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_multicast()
        }
    }
}

pub fn validate_target_ip(ip: &str) -> Result<IpAddr> {
    let parsed: IpAddr = ip.parse()?;
    Ok(parsed)
}

pub fn parse_target_specification(target: &str) -> Result<Vec<IpAddr>> {
    // Try parsing as CIDR first
    if target.contains('/') {
        return parse_cidr_range(target);
    }
    
    // Try parsing as single IP
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    
    // Try parsing as IP range (e.g., "192.168.1.1-192.168.1.10")
    if target.contains('-') {
        let parts: Vec<&str> = target.split('-').collect();
        if parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (parts[0].parse::<IpAddr>(), parts[1].parse::<IpAddr>()) {
                return parse_ip_range(start, end);
            }
        }
    }
    
    Err(anyhow::anyhow!("Invalid target specification: {}", target))
}

fn parse_ip_range(start: IpAddr, end: IpAddr) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    
    match (start, end) {
        (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
            let start_num = u32::from(start_v4);
            let end_num = u32::from(end_v4);
            
            if start_num > end_num {
                return Err(anyhow::anyhow!("Invalid IP range: start IP is greater than end IP"));
            }
            
            for num in start_num..=end_num {
                ips.push(IpAddr::V4(num.into()));
            }
        }
        _ => {
            return Err(anyhow::anyhow!("IP range only supported for IPv4 addresses"));
        }
    }
    
    Ok(ips)
}