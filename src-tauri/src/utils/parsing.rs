use regex::Regex;
use anyhow::Result;

pub struct OutputParser;

impl OutputParser {
    pub fn extract_ip_addresses(text: &str) -> Vec<String> {
        let ip_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
        ip_regex
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    pub fn extract_ports(text: &str) -> Vec<u16> {
        let port_regex = Regex::new(r"\b(\d{1,5})/(?:tcp|udp)\b").unwrap();
        port_regex
            .captures_iter(text)
            .filter_map(|cap| cap.get(1)?.as_str().parse().ok())
            .collect()
    }

    pub fn extract_service_info(text: &str) -> Option<(String, Option<String>)> {
        // Basic service extraction - this would be more complex in reality
        if text.contains("http") {
            Some(("http".to_string(), None))
        } else if text.contains("ssh") {
            Some(("ssh".to_string(), None))
        } else if text.contains("ftp") {
            Some(("ftp".to_string(), None))
        } else {
            None
        }
    }

    pub fn parse_nmap_progress(line: &str) -> Option<f32> {
        let progress_regex = Regex::new(r"(\d+(?:\.\d+)?)%").unwrap();
        if let Some(cap) = progress_regex.captures(line) {
            cap.get(1)?.as_str().parse().ok()
        } else {
            None
        }
    }
}