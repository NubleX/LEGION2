// LEGION2 - Stealthy hostname resolver
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::database::Db;
use crate::network::hostname_probes::{
    LocalDNSQuery, LLMNRQuery, MDNSHostnameQuery, NetBIOSNameQuery,
    SMBNameQuery,
};
use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Protocol capabilities for a known host
#[derive(Debug, Clone)]
pub struct HostCapabilities {
    pub has_smb: bool,      // Port 445 or 139 open
    pub has_dns: bool,       // Port 53 open (DNS server)
    pub has_mdns: bool,      // Port 5353 open or mDNS discovered
    pub has_netbios: bool,   // Port 137 open or Windows OS detected
    pub has_llmnr: bool,     // Windows OS detected (LLMNR typically on Windows)
    pub os_family: Option<String>,
}

/// Registry of known hosts and their capabilities
pub struct HostnameResolver {
    db: Arc<Db>,
    capabilities_cache: Arc<RwLock<HashMap<IpAddr, HostCapabilities>>>,
}

impl HostnameResolver {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            capabilities_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get known hosts from database and build capabilities map
    pub async fn refresh_known_hosts(&self) -> Result<()> {
        let hosts = self.db.get_all_hosts().await?;
        let mut capabilities = self.capabilities_cache.write().await;

        for host in hosts {
            if let Ok(ip) = host.ip.parse::<IpAddr>() {
                let caps = self.build_capabilities(&host).await?;
                capabilities.insert(ip, caps);
            }
        }

        log::info!("Refreshed {} known hosts for hostname resolution", capabilities.len());
        Ok(())
    }

    /// Build capabilities for a host based on its discovered services and OS
    async fn build_capabilities(&self, host: &crate::shared::shared::Host) -> Result<HostCapabilities> {
        let _ = host.ip.parse::<IpAddr>()?;
        
        // Get ports for this host
        let ports = self.db.get_host_ports(&host.id).await?;
        
        let mut has_smb = false;
        let mut has_dns = false;
        let mut has_mdns = false;
        let mut has_netbios = false;
        let mut has_llmnr = false;
        
        // Check ports for protocol support
        for port_str in &ports {
            // Parse port string (format: "number/protocol")
            if let Some((num_str, _)) = port_str.split_once('/') {
                if let Ok(port) = num_str.parse::<u16>() {
                    match port {
                        445 | 139 => has_smb = true,
                        53 => has_dns = true,
                        5353 => has_mdns = true,
                        137 => has_netbios = true,
                        _ => {}
                    }
                }
            }
        }
        
        // Check OS family for protocol hints
        let os_family = host.os_family.clone();
        if let Some(ref family) = os_family {
            let family_lower = family.to_lowercase();
            if family_lower.contains("windows") {
                has_netbios = true; // Windows typically has NetBIOS
                has_llmnr = true;   // Windows has LLMNR
                if !has_smb {
                    // Windows often has SMB even if not explicitly discovered
                    has_smb = true;
                }
            }
        }
        
        Ok(HostCapabilities {
            has_smb,
            has_dns,
            has_mdns,
            has_netbios,
            has_llmnr,
            os_family,
        })
    }

    /// Get known hosts that support a specific protocol
    pub async fn get_hosts_with_capability(&self, protocol: &str) -> Vec<IpAddr> {
        let capabilities = self.capabilities_cache.read().await;
        capabilities
            .iter()
            .filter_map(|(ip, caps)| {
                match protocol {
                    "netbios" if caps.has_netbios => Some(*ip),
                    "llmnr" if caps.has_llmnr => Some(*ip),
                    "smb" if caps.has_smb => Some(*ip),
                    "mdns" if caps.has_mdns => Some(*ip),
                    "dns" if caps.has_dns => Some(*ip),
                    _ => None,
                }
            })
            .collect()
    }

    /// Resolve hostname for a target IP using stealthy methods
    /// Tries protocols in priority order: NetBIOS > LLMNR > SMB > mDNS > Local DNS
    pub async fn resolve_hostname(&self, target_ip: IpAddr) -> Option<String> {
        // Try NetBIOS first (most common on Windows networks)
        if let Some(hostname) = self.try_protocol(target_ip, "netbios").await {
            log::info!("Resolved hostname {} for {} via NetBIOS", hostname, target_ip);
            return Some(hostname);
        }

        // Try LLMNR (Windows name resolution)
        if let Some(hostname) = self.try_protocol(target_ip, "llmnr").await {
            log::info!("Resolved hostname {} for {} via LLMNR", hostname, target_ip);
            return Some(hostname);
        }

        // Try SMB (NetBIOS name from SMB service)
        if let Some(hostname) = self.try_protocol(target_ip, "smb").await {
            log::info!("Resolved hostname {} for {} via SMB", hostname, target_ip);
            return Some(hostname);
        }

        // Try mDNS (Apple/Bonjour devices)
        if let Some(hostname) = self.try_protocol(target_ip, "mdns").await {
            log::info!("Resolved hostname {} for {} via mDNS", hostname, target_ip);
            return Some(hostname);
        }

        // Try Local DNS (if we found a DNS server)
        if let Some(hostname) = self.try_protocol(target_ip, "dns").await {
            log::info!("Resolved hostname {} for {} via Local DNS", hostname, target_ip);
            return Some(hostname);
        }

        None
    }

    /// Try resolving hostname using a specific protocol
    async fn try_protocol(&self, target_ip: IpAddr, protocol: &str) -> Option<String> {
        let known_hosts = self.get_hosts_with_capability(protocol).await;
        
        if known_hosts.is_empty() {
            log::debug!("No known hosts support protocol: {}", protocol);
            return None;
        }

        // Try querying up to 3 known hosts (to avoid overwhelming network)
        for known_host in known_hosts.iter().take(3) {
            let result = match protocol {
                "netbios" => NetBIOSNameQuery::query(*known_host, target_ip).await,
                "llmnr" => LLMNRQuery::query(*known_host, target_ip).await,
                "smb" => SMBNameQuery::query(*known_host, target_ip).await,
                "mdns" => MDNSHostnameQuery::query(*known_host, target_ip).await,
                "dns" => LocalDNSQuery::query(*known_host, target_ip).await,
                _ => return None,
            };

            match result {
                Ok(probe_result) => {
                    if let Some(hostname) = probe_result.hostname {
                        if !hostname.is_empty() {
                            return Some(hostname);
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Protocol {} query failed for {}: {}", protocol, known_host, e);
                }
            }
        }

        None
    }

    /// Get all known hosts
    pub async fn get_known_hosts(&self) -> Vec<IpAddr> {
        let capabilities = self.capabilities_cache.read().await;
        capabilities.keys().copied().collect()
    }
}

