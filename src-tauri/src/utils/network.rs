use std::net::{IpAddr, Ipv4Addr};
use anyhow::Result;
use cidr::{IpCidr, Ipv4Cidr};

pub struct NetworkUtils;

impl NetworkUtils {
    pub fn expand_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
        let network: IpCidr = cidr.parse()?;
        let mut ips = Vec::new();
        
        // Limit to prevent memory issues
        const MAX_IPS: usize = 65536;
        
        for (count, ip) in network.iter().enumerate() {
            if count >= MAX_IPS {
                break;
            }
            ips.push(ip);
        }
        
        Ok(ips)
    }

    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || 
                ipv4.is_loopback() ||
                ipv4.is_link_local() ||
                // Additional RFC 1918 checks
                (ipv4.octets()[0] == 10) ||
                (ipv4.octets()[0] == 172 && (16..=31).contains(&ipv4.octets()[1])) ||
                (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168)
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || 
                ipv6.is_unspecified() ||
                // Site-local (deprecated but still used)
                (ipv6.segments()[0] & 0xffc0) == 0xfec0 ||
                // Unique local
                (ipv6.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }

    pub fn get_network_info(ip: &IpAddr) -> NetworkInfo {
        NetworkInfo {
            ip: *ip,
            is_private: Self::is_private_ip(ip),
            ip_type: Self::classify_ip(ip),
        }
    }

    fn classify_ip(ip: &IpAddr) -> IpType {
        match ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_loopback() { IpType::Loopback }
                else if ipv4.is_private() { IpType::Private }
                else if ipv4.is_multicast() { IpType::Multicast }
                else if ipv4.is_broadcast() { IpType::Broadcast }
                else { IpType::Public }
            }
            IpAddr::V6(_) => IpType::IPv6
        }
    }

    pub fn generate_target_list(
        ranges: &[String],
        excludes: &[String],
    ) -> Result<Vec<IpAddr>> {
        let mut targets = Vec::new();
        let mut exclude_set = std::collections::HashSet::new();

        // Process excludes first
        for exclude in excludes {
            if let Ok(ips) = Self::expand_cidr(exclude) {
                exclude_set.extend(ips);
            }
        }

        // Process target ranges
        for range in ranges {
            let ips = Self::expand_cidr(range)?;
            for ip in ips {
                if !exclude_set.contains(&ip) {
                    targets.push(ip);
                }
            }
        }

        Ok(targets)
    }
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub ip: IpAddr,
    pub is_private: bool,
    pub ip_type: IpType,
}

#[derive(Debug, Clone)]
pub enum IpType {
    Loopback,
    Private,
    Public,
    Multicast,
    Broadcast,
    IPv6,
}