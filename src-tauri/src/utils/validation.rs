use anyhow::{Result, anyhow};
use std::net::IpAddr;
use std::str::FromStr;

pub struct InputValidator;

impl InputValidator {
    pub fn validate_cidr(cidr: &str) -> Result<()> {
        if cidr.contains('/') {
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid CIDR format"));
            }
            
            // Validate IP part
            IpAddr::from_str(parts[0])
                .map_err(|_| anyhow!("Invalid IP address in CIDR"))?;
            
            // Validate prefix length
            let prefix: u8 = parts[1].parse()
                .map_err(|_| anyhow!("Invalid prefix length"))?;
            
            if prefix > 32 {
                return Err(anyhow!("Invalid prefix length (max 32)"));
            }
        } else {
            // Single IP address
            IpAddr::from_str(cidr)
                .map_err(|_| anyhow!("Invalid IP address"))?;
        }
        
        Ok(())
    }

    pub fn validate_scan_type(scan_type: &str) -> Result<()> {
        match scan_type {
            "quick" | "comprehensive" | "stealth" => Ok(()),
            _ => Err(anyhow!("Invalid scan type: {}", scan_type))
        }
    }

    pub fn validate_ip_address(ip: &str) -> Result<IpAddr> {
        IpAddr::from_str(ip)
            .map_err(|_| anyhow!("Invalid IP address format"))
    }

    pub fn validate_port(port: u16) -> Result<()> {
        if port == 0 {
            return Err(anyhow!("Port cannot be 0"));
        }
        Ok(())
    }

    pub fn validate_port_range(range: &str) -> Result<()> {
        if range.contains('-') {
            let parts: Vec<&str> = range.split('-').collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid port range format"));
            }
            
            let start: u16 = parts[0].parse()
                .map_err(|_| anyhow!("Invalid start port"))?;
            let end: u16 = parts[1].parse()
                .map_err(|_| anyhow!("Invalid end port"))?;
            
            if start > end {
                return Err(anyhow!("Start port cannot be greater than end port"));
            }
            
            Self::validate_port(start)?;
            Self::validate_port(end)?;
        } else {
            // Single port
            let port: u16 = range.parse()
                .map_err(|_| anyhow!("Invalid port number"))?;
            Self::validate_port(port)?;
        }
        
        Ok(())
    }
}