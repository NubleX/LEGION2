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