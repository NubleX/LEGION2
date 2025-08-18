// [dependencies]
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// regex = "1.0"
// tokio = { version = "1.0", features = ["full"] }
// reqwest = "0.11"
// tracing = "0.1"

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OS {
    pub name: String,
    pub family: String,
    pub generation: String,
    pub os_type: String,
    pub vendor: String,
    pub accuracy: u8,
}

impl OS {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            family: String::new(),
            generation: String::new(),
            os_type: String::new(),
            vendor: String::new(),
            accuracy: 0,
        }
    }

    pub fn from_nmap_xml(os_node: &roxmltree::Node) -> Self {
        let get_attr = |name: &str| -> String {
            os_node
                .attribute(name)
                .unwrap_or("")
                .to_string()
        };

        Self {
            name: get_attr("name"),
            family: get_attr("osfamily"),
            generation: get_attr("osgen"),
            os_type: get_attr("type"),
            vendor: get_attr("vendor"),
            accuracy: get_attr("accuracy")
                .parse()
                .unwrap_or(0),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && 
        self.family.is_empty() && 
        self.vendor.is_empty()
    }
}

pub struct OSDetector {
    fingerprint_db: HashMap<String, OS>,
}

impl OSDetector {
    pub fn new() -> Self {
        Self {
            fingerprint_db: Self::load_fingerprint_database(),
        }
    }

    fn load_fingerprint_database() -> HashMap<String, OS> {
        let mut db = HashMap::new();
        
        // Common OS fingerprints (in practice, this would be loaded from a comprehensive database)
        let fingerprints = vec![
            ("Linux 5.4", OS {
                name: "Linux".to_string(),
                family: "Linux".to_string(),
                generation: "5.4".to_string(),
                os_type: "general purpose".to_string(),
                vendor: "Linux".to_string(),
                accuracy: 95,
            }),
            ("Windows 10", OS {
                name: "Microsoft Windows 10".to_string(),
                family: "Windows".to_string(),
                generation: "10".to_string(),
                os_type: "general purpose".to_string(),
                vendor: "Microsoft".to_string(),
                accuracy: 90,
            }),
            ("Windows Server 2019", OS {
                name: "Microsoft Windows Server 2019".to_string(),
                family: "Windows".to_string(),
                generation: "2019".to_string(),
                os_type: "server".to_string(),
                vendor: "Microsoft".to_string(),
                accuracy: 92,
            }),
            ("macOS 11.0", OS {
                name: "Apple macOS 11.0".to_string(),
                family: "macOS".to_string(),
                generation: "11.0".to_string(),
                os_type: "general purpose".to_string(),
                vendor: "Apple".to_string(),
                accuracy: 88,
            }),
        ];

        for (key, os) in fingerprints {
            db.insert(key.to_string(), os);
        }

        db
    }

    pub async fn detect_via_nmap(&self, target: &str) -> Result<Vec<OS>, Box<dyn std::error::Error>> {
        info!("Running Nmap OS detection on {}", target);
        
        // In a real implementation, you would run nmap with OS detection
        // For example: nmap -O target
        let output = std::process::Command::new("nmap")
            .arg("-O")
            .arg(target)
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_nmap_output(&stdout)
    }

    fn parse_nmap_output(&self, output: &str) -> Result<Vec<OS>, Box<dyn std::error::Error>> {
        let mut detected_os_list = Vec::new();
        
        // Parse Nmap output for OS information
        // This is a simplified parser - in practice you'd use regex or XML parsing
        for line in output.lines() {
            if line.contains("Running:") || line.contains("OS details:") {
                // Extract OS information from line
                if let Some(os) = self.match_fingerprint(line) {
                    detected_os_list.push(os);
                }
            }
        }

        Ok(detected_os_list)
    }

    fn match_fingerprint(&self, line: &str) -> Option<OS> {
        // Match against our fingerprint database
        for (key, os) in &self.fingerprint_db {
            if line.to_lowercase().contains(&key.to_lowercase()) {
                return Some(os.clone());
            }
        }
        
        // Fallback pattern matching
        self.pattern_match_os(line)
    }

    fn pattern_match_os(&self, line: &str) -> Option<OS> {
        // Use regex patterns to identify OS
        use regex::Regex;
        
        // Windows pattern
        let windows_re = Regex::new(r"(?i)windows\s+(nt\s+)?(\d+\.\d+|\d+)").unwrap();
        if let Some(caps) = windows_re.captures(line) {
            if let Some(version) = caps.get(2) {
                return Some(OS {
                    name: format!("Microsoft Windows {}", version.as_str()),
                    family: "Windows".to_string(),
                    generation: version.as_str().to_string(),
                    os_type: "general purpose".to_string(),
                    vendor: "Microsoft".to_string(),
                    accuracy: 80,
                });
            }
        }
        
        // Linux pattern
        let linux_re = Regex::new(r"(?i)linux\s+((\d+\.\d+\.?\d*)|kernel)").unwrap();
        if linux_re.is_match(line) {
            return Some(OS {
                name: "Linux".to_string(),
                family: "Linux".to_string(),
                generation: "Unknown".to_string(),
                os_type: "general purpose".to_string(),
                vendor: "Linux".to_string(),
                accuracy: 75,
            });
        }
        
        // macOS pattern
        let macos_re = Regex::new(r"(?i)mac\s*os\s*x?").unwrap();
        if macos_re.is_match(line) {
            return Some(OS {
                name: "Apple macOS".to_string(),
                family: "macOS".to_string(),
                generation: "Unknown".to_string(),
                os_type: "general purpose".to_string(),
                vendor: "Apple".to_string(),
                accuracy: 70,
            });
        }
        
        None
    }

    pub async fn detect_via_http_headers(&self, url: &str) -> Result<OS, Box<dyn std::error::Error>> {
        debug!("Detecting OS via HTTP headers for {}", url);
        
        let client = reqwest::Client::new();
        let response = client.head(url).send().await?;
        
        let server_header = response
            .headers()
            .get("server")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        
        // Try to identify OS from server header
        if let Some(os) = self.match_fingerprint(server_header) {
            Ok(os)
        } else {
            Err("Could not determine OS from HTTP headers".into())
        }
    }

    pub fn detect_via_ttl(&self, ttl: u8) -> OS {
        // TTL-based OS detection (simplified)
        let (name, family, vendor, accuracy) = match ttl {
            64 => ("Linux/Unix", "Linux", "Linux/Unix", 85),
            128 => ("Windows", "Windows", "Microsoft", 90),
            255 => ("Cisco/Network", "Network", "Cisco", 80),
            _ => ("Unknown", "Unknown", "Unknown", 50),
        };

        OS {
            name: name.to_string(),
            family: family.to_string(),
            generation: "Unknown".to_string(),
            os_type: "general purpose".to_string(),
            vendor: vendor.to_string(),
            accuracy,
        }
    }

    pub fn get_most_accurate(&self, os_list: &[OS]) -> Option<&OS> {
        os_list.iter().max_by_key(|os| os.accuracy)
    }
}

// Implementation of passive fingerprinting using packet analysis
pub struct PassiveOSDetector;

impl PassiveOSDetector {
    pub fn analyze_tcp_signature(&self, tcp_signature: &TcpSignature) -> OS {
        // Analyze TCP/IP stack fingerprinting data
        // This would use p0f-style fingerprinting
        
        let mut os = OS::new();
        
        // TTL analysis
        os = self.analyze_ttl(tcp_signature.ttl);
        
        // Window size analysis
        if tcp_signature.window_size == 65535 && tcp_signature.ttl == 128 {
            os.name = "Windows".to_string();
            os.family = "Windows".to_string();
            os.vendor = "Microsoft".to_string();
            os.accuracy = 85;
        }
        
        // TCP options analysis
        if tcp_signature.tcp_options.contains(&"wscale") {
            // Linux often uses window scaling
            if os.vendor.is_empty() {
                os.name = "Linux".to_string();
                os.family = "Linux".to_string();
                os.vendor = "Linux".to_string();
                os.accuracy = 80;
            }
        }
        
        os
    }
    
    fn analyze_ttl(&self, ttl: u8) -> OS {
        let mut os = OS::new();
        
        match ttl {
            64 => {
                os.name = "Linux/Unix".to_string();
                os.family = "Linux".to_string();
                os.vendor = "Linux/Unix".to_string();
                os.accuracy = 85;
            },
            128 => {
                os.name = "Windows".to_string();
                os.family = "Windows".to_string();
                os.vendor = "Microsoft".to_string();
                os.accuracy = 90;
            },
            255 => {
                os.name = "Network Device".to_string();
                os.family = "Network".to_string();
                os.vendor = "Various".to_string();
                os.accuracy = 80;
            },
            _ => {
                os.accuracy = 30; // Low confidence
            }
        }
        
        os
    }
}

#[derive(Debug)]
pub struct TcpSignature {
    pub ttl: u8,
    pub window_size: u16,
    pub tcp_options: Vec<String>,
    pub mss: u16,
    pub id: u16,
}

// Example usage functions
pub async fn detect_target_os(target: &str) -> Result<Vec<OS>, Box<dyn std::error::Error>> {
    let detector = OSDetector::new();
    
    // Try multiple detection methods
    let mut results = Vec::new();
    
    // Method 1: Nmap detection
    match detector.detect_via_nmap(target).await {
        Ok(os_list) => results.extend(os_list),
        Err(e) => debug!("Nmap detection failed: {}", e),
    }
    
    // Method 2: TTL-based detection (if we have TTL info)
    // This would come from packet capture
    let ttl_detector = PassiveOSDetector;
    let tcp_sig = TcpSignature {
        ttl: 128, // Example TTL
        window_size: 65535,
        tcp_options: vec!["mss".to_string(), "nop".to_string(), "wscale".to_string()],
        mss: 1460,
        id: 1234,
    };
    
    let ttl_os = ttl_detector.analyze_tcp_signature(&tcp_sig);
    if ttl_os.accuracy > 50 {
        results.push(ttl_os);
    }
    
    Ok(results)
}