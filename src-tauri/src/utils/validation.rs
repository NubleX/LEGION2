use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use anyhow::{Result, bail};
use regex::Regex;

pub struct InputValidator;

impl InputValidator {
    pub fn validate_ip(ip: &str) -> Result<IpAddr> {
        ip.parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip))
    }

    pub fn validate_cidr(cidr: &str) -> Result<()> {
        use cidr::IpCidr;
        cidr.parse::<IpCidr>()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR notation: {}", cidr))?;
        Ok(())
    }

    pub fn validate_port_range(ports: &str) -> Result<Vec<u16>> {
        let mut port_list = Vec::new();

        for part in ports.split(',') {
            let part = part.trim();
            
            if part.contains('-') {
                let range: Vec<&str> = part.split('-').collect();
                if range.len() != 2 {
                    bail!("Invalid port range: {}", part);
                }
                
                let start: u16 = range[0].parse()
                    .map_err(|_| anyhow::anyhow!("Invalid start port: {}", range[0]))?;
                let end: u16 = range[1].parse()
                    .map_err(|_| anyhow::anyhow!("Invalid end port: {}", range[1]))?;
                
                if start > end || end > 65535 {
                    bail!("Invalid port range: {}-{}", start, end);
                }
                
                for port in start..=end {
                    port_list.push(port);
                }
            } else {
                let port: u16 = part.parse()
                    .map_err(|_| anyhow::anyhow!("Invalid port: {}", part))?;
                
                if port > 65535 {
                    bail!("Port out of range: {}", port);
                }
                
                port_list.push(port);
            }
        }

        Ok(port_list)
    }

    pub fn validate_hostname(hostname: &str) -> Result<()> {
        let hostname_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
            .unwrap();
        
        if hostname.len() > 253 {
            bail!("Hostname too long: {}", hostname);
        }
        
        if !hostname_regex.is_match(hostname) {
            bail!("Invalid hostname format: {}", hostname);
        }
        
        Ok(())
    }

    pub fn sanitize_filename(filename: &str) -> String {
        let invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
        filename.chars()
            .map(|c| if invalid_chars.contains(&c) { '_' } else { c })
            .collect()
    }

    pub fn validate_scan_type(scan_type: &str) -> Result<()> {
        match scan_type {
            "quick" | "comprehensive" | "stealth" | "custom" => Ok(()),
            _ => bail!("Invalid scan type: {}", scan_type),
        }
    }
}