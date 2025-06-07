use anyhow::{Result, Context};
use regex::Regex;
use std::collections::HashMap;
use serde_json::Value;

pub struct OutputParser;

impl OutputParser {
    pub fn parse_nmap_version(output: &str) -> Result<String> {
        let version_regex = Regex::new(r"Nmap version (\d+\.\d+)")?;
        
        if let Some(captures) = version_regex.captures(output) {
            Ok(captures.get(1).unwrap().as_str().to_string())
        } else {
            Err(anyhow::anyhow!("Could not parse nmap version"))
        }
    }

    pub fn parse_masscan_rate(output: &str) -> Result<f64> {
        let rate_regex = Regex::new(r"rate:\s*(\d+\.\d+)\s*kpps")?;
        
        if let Some(captures) = rate_regex.captures(output) {
            let rate: f64 = captures.get(1).unwrap().as_str().parse()?;
            Ok(rate * 1000.0) // Convert kpps to pps
        } else {
            Ok(0.0)
        }
    }

    pub fn extract_ip_addresses(text: &str) -> Vec<String> {
        let ip_regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
        ip_regex.find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    pub fn parse_service_banner(banner: &str) -> ServiceInfo {
        let mut info = ServiceInfo::default();
        
        // Common service patterns
        if banner.contains("SSH") {
            info.service = Some("ssh".to_string());
            if let Some(version) = Self::extract_ssh_version(banner) {
                info.version = Some(version);
            }
        } else if banner.contains("HTTP") {
            info.service = Some("http".to_string());
            if let Some(server) = Self::extract_http_server(banner) {
                info.version = Some(server);
            }
        } else if banner.contains("FTP") {
            info.service = Some("ftp".to_string());
        } else if banner.contains("SMTP") {
            info.service = Some("smtp".to_string());
        }
        
        info.banner = Some(banner.to_string());
        info
    }

    fn extract_ssh_version(banner: &str) -> Option<String> {
        let ssh_regex = Regex::new(r"SSH-(\d+\.\d+)-(\S+)").ok()?;
        if let Some(captures) = ssh_regex.captures(banner) {
            Some(format!("{}-{}", 
                captures.get(1)?.as_str(),
                captures.get(2)?.as_str()
            ))
        } else {
            None
        }
    }

    fn extract_http_server(banner: &str) -> Option<String> {
        let server_regex = Regex::new(r"Server:\s*([^\r\n]+)").ok()?;
        server_regex.captures(banner)?
            .get(1)?
            .as_str()
            .trim()
            .to_string()
            .into()
    }

    pub fn parse_vulnerability_references(refs_str: &str) -> Result<Vec<String>> {
        if refs_str.trim().is_empty() {
            return Ok(Vec::new());
        }
        
        let refs: Value = serde_json::from_str(refs_str)
            .context("Invalid JSON in vulnerability references")?;
        
        match refs {
            Value::Array(arr) => {
                Ok(arr.into_iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect())
            }
            _ => Err(anyhow::anyhow!("References must be JSON array")),
        }
    }

    pub fn clean_ansi_codes(text: &str) -> String {
        let ansi_regex = Regex::new(r"\x1B\[[0-9;]*m").unwrap();
        ansi_regex.replace_all(text, "").to_string()
    }
}

#[derive(Debug, Default, Clone)]
pub struct ServiceInfo {
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

// Rate limiting utility
pub struct RateLimiter {
    tokens: tokio::sync::Mutex<f64>,
    capacity: f64,
    refill_rate: f64,
    last_refill: tokio::sync::Mutex<std::time::Instant>,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: tokio::sync::Mutex::new(capacity),
            capacity,
            refill_rate,
            last_refill: tokio::sync::Mutex::new(std::time::Instant::now()),
        }
    }

    pub async fn acquire(&self) -> bool {
        let now = std::time::Instant::now();
        let mut last_refill = self.last_refill.lock().await;
        let mut tokens = self.tokens.lock().await;

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        *tokens = (*tokens + elapsed * self.refill_rate).min(self.capacity);
        *last_refill = now;

        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}