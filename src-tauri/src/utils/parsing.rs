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