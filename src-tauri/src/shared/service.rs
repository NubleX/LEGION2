use roxmltree::Node;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Service {
    pub name: String,
    pub product: String,
    pub version: String,
    pub extrainfo: String,
    pub ostype: String,
    pub method: String,
    pub conf: String,
    pub servicefp: String,
    pub tunnel: String,
    pub proto: String,
    pub rpcnum: String,
    pub lowver: String,
    pub cpe: Vec<String>,
    pub devicetype: String,
    pub hostname: String,
    pub highver: String,
}

impl Service {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            product: String::new(),
            version: String::new(),
            extrainfo: String::new(),
            ostype: String::new(),
            method: String::new(),
            conf: String::new(),
            servicefp: String::new(),
            tunnel: String::new(),
            proto: String::new(),
            rpcnum: String::new(),
            lowver: String::new(),
            cpe: Vec::new(),
            devicetype: String::new(),
            hostname: String::new(),
            highver: String::new(),
        }
    }

    pub fn from_xml_node(node: &Node) -> Self {
        Self {
            name: node.attribute("name").unwrap_or("").to_string(),
            product: node.attribute("product").unwrap_or("").to_string(),
            version: node.attribute("version").unwrap_or("").to_string(),
            extrainfo: node.attribute("extrainfo").unwrap_or("").to_string(),
            ostype: node.attribute("ostype").unwrap_or("").to_string(),
            method: node.attribute("method").unwrap_or("").to_string(),
            conf: node.attribute("conf").unwrap_or("").to_string(),
            servicefp: node.attribute("servicefp").unwrap_or("").to_string(),
            tunnel: node.attribute("tunnel").unwrap_or("").to_string(),
            proto: node.attribute("proto").unwrap_or("").to_string(),
            rpcnum: node.attribute("rpcnum").unwrap_or("").to_string(),
            lowver: node.attribute("lowver").unwrap_or("").to_string(),
            cpe: node
                .children()
                .filter(|n| n.tag_name().name() == "cpe")
                .filter_map(|n| n.text())
                .map(|s| s.to_string())
                .collect(),
            devicetype: node.attribute("devicetype").unwrap_or("").to_string(),
            hostname: node.attribute("hostname").unwrap_or("").to_string(),
            highver: node.attribute("highver").unwrap_or("").to_string(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.product.is_empty() && self.version.is_empty()
    }

    pub fn get_banner(&self) -> String {
        // Generate a comprehensive banner from service information
        if !self.servicefp.is_empty() {
            return self.servicefp.clone();
        }

        let mut parts = Vec::new();

        if !self.product.is_empty() {
            parts.push(self.product.clone());
        }

        if !self.version.is_empty() {
            parts.push(self.version.clone());
        }

        if !self.extrainfo.is_empty() {
            parts.push(self.extrainfo.clone());
        }

        if parts.is_empty() {
            parts.push(self.name.clone());
        }

        parts.join(" ")
    }

    pub fn get_version_info(&self) -> Option<String> {
        if !self.product.is_empty() {
            if !self.version.is_empty() {
                Some(format!("{} {}", self.product, self.version))
            } else {
                Some(self.product.clone())
            }
        } else if !self.version.is_empty() {
            Some(self.version.clone())
        } else {
            None
        }
    }

    pub fn is_vulnerable(&self) -> bool {
        // Check for common vulnerability indicators
        let vuln_indicators = [
            "vuln",
            "exploit",
            "backdoor",
            "trojan",
            "unauthorized",
            "insecure",
            "deprecated",
        ];

        let combined_info = format!(
            "{} {} {}",
            self.product.to_lowercase(),
            self.version.to_lowercase(),
            self.extrainfo.to_lowercase()
        );

        vuln_indicators
            .iter()
            .any(|&indicator| combined_info.contains(indicator))
    }

    pub fn get_cpe_uris(&self) -> &[String] {
        &self.cpe
    }

    pub fn get_cpe_products(&self) -> Vec<String> {
        self.cpe
            .iter()
            .filter_map(|cpe_uri| {
                // Parse CPE URI to extract product name
                // CPE format: cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
                let parts: Vec<&str> = cpe_uri.split(':').collect();
                if parts.len() >= 4 {
                    Some(parts[3].to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn is_web_service(&self) -> bool {
        let web_services = [
            "http",
            "https",
            "http-proxy",
            "http-alt",
            "https-alt",
            "webmin",
            "nginx",
            "apache",
        ];

        web_services.contains(&self.name.as_str())
            || self.product.to_lowercase().contains("http")
            || self.extrainfo.to_lowercase().contains("web")
    }

    pub fn is_database_service(&self) -> bool {
        let db_services = [
            "mysql",
            "postgresql",
            "mssql",
            "oracle",
            "mongodb",
            "redis",
            "cassandra",
        ];

        db_services.contains(&self.name.as_str())
            || self.product.to_lowercase().contains("sql")
            || self.product.to_lowercase().contains("database")
    }

    pub fn get_service_type(&self) -> ServiceType {
        if self.is_web_service() {
            ServiceType::Web
        } else if self.is_database_service() {
            ServiceType::Database
        } else if self.name.contains("ssh") || self.product.contains("SSH") {
            ServiceType::Ssh
        } else if self.name.contains("ftp") || self.product.contains("FTP") {
            ServiceType::Ftp
        } else if self.name.contains("smtp") || self.product.contains("SMTP") {
            ServiceType::Smtp
        } else if self.name.contains("dns") || self.product.contains("DNS") {
            ServiceType::Dns
        } else {
            ServiceType::Other
        }
    }

    pub fn get_risk_score(&self) -> u8 {
        // Calculate risk based on service characteristics
        let mut score = 0u8;

        // High-risk services
        if self.is_web_service() || self.is_database_service() {
            score += 3;
        }

        // Services with known vulnerabilities
        if self.is_vulnerable() {
            score += 4;
        }

        // Services with version info (more info = more attack surface)
        if !self.version.is_empty() {
            score += 1;
        }

        // Services with product info
        if !self.product.is_empty() {
            score += 1;
        }

        // Cap at 10
        score.min(10)
    }

    pub fn get_normalized_name(&self) -> String {
        // Normalize service name for consistent identification
        let name_lower = self.name.to_lowercase();

        // Common name mappings
        match name_lower.as_str() {
            "http" => "http".to_string(),
            "https" => "https".to_string(),
            "ssh" => "ssh".to_string(),
            "ftp" => "ftp".to_string(),
            "smtp" => "smtp".to_string(),
            "pop3" => "pop3".to_string(),
            "imap" => "imap".to_string(),
            "dns" | "domain" => "dns".to_string(),
            "smb" | "microsoft-ds" => "smb".to_string(),
            "mysql" => "mysql".to_string(),
            "postgresql" => "postgresql".to_string(),
            "mssql" | "ms-sql-s" => "mssql".to_string(),
            "rdp" | "ms-wbt-server" => "rdp".to_string(),
            "vnc" => "vnc".to_string(),
            "telnet" => "telnet".to_string(),
            "snmp" => "snmp".to_string(),
            _ => name_lower,
        }
    }

    pub fn get_fingerprint_hash(&self) -> String {
        // Create a hash of the service fingerprint for comparison
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.servicefp.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    pub fn matches_pattern(&self, pattern: &str) -> bool {
        let pattern_lower = pattern.to_lowercase();
        self.name.to_lowercase().contains(&pattern_lower)
            || self.product.to_lowercase().contains(&pattern_lower)
            || self.extrainfo.to_lowercase().contains(&pattern_lower)
    }

    pub fn get_confidence(&self) -> u8 {
        // Return confidence level based on available information
        let mut confidence = 0u8;

        if !self.name.is_empty() {
            confidence += 25;
        }

        if !self.product.is_empty() {
            confidence += 25;
        }

        if !self.version.is_empty() {
            confidence += 25;
        }

        if !self.extrainfo.is_empty() {
            confidence += 15;
        }

        if !self.servicefp.is_empty() {
            confidence += 10;
        }

        confidence.min(100)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServiceType {
    Web,
    Database,
    Ssh,
    Ftp,
    Smtp,
    Dns,
    Other,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceType::Web => write!(f, "Web"),
            ServiceType::Database => write!(f, "Database"),
            ServiceType::Ssh => write!(f, "SSH"),
            ServiceType::Ftp => write!(f, "FTP"),
            ServiceType::Smtp => write!(f, "SMTP"),
            ServiceType::Dns => write!(f, "DNS"),
            ServiceType::Other => write!(f, "Other"),
        }
    }
}

// Service collection and management
pub struct ServiceCollection {
    services: Vec<Service>,
}

impl ServiceCollection {
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
        }
    }

    pub fn from_xml_nodes(service_nodes: &[Node]) -> Self {
        let services = service_nodes
            .iter()
            .map(|node| Service::from_xml_node(node))
            .collect();

        Self { services }
    }

    pub fn add_service(&mut self, service: Service) {
        self.services.push(service);
    }

    pub fn get_services(&self) -> &[Service] {
        &self.services
    }

    pub fn get_services_by_type(&self, service_type: ServiceType) -> Vec<&Service> {
        self.services
            .iter()
            .filter(|s| s.get_service_type() == service_type)
            .collect()
    }

    pub fn get_services_by_name(&self, name: &str) -> Vec<&Service> {
        let name_lower = name.to_lowercase();
        self.services
            .iter()
            .filter(|s| s.name.to_lowercase() == name_lower)
            .collect()
    }

    pub fn get_services_matching_pattern(&self, pattern: &str) -> Vec<&Service> {
        self.services
            .iter()
            .filter(|s| s.matches_pattern(pattern))
            .collect()
    }

    pub fn get_vulnerable_services(&self) -> Vec<&Service> {
        self.services.iter().filter(|s| s.is_vulnerable()).collect()
    }

    pub fn get_services_with_version(&self) -> Vec<&Service> {
        self.services
            .iter()
            .filter(|s| !s.version.is_empty())
            .collect()
    }

    pub fn get_services_with_product(&self) -> Vec<&Service> {
        self.services
            .iter()
            .filter(|s| !s.product.is_empty())
            .collect()
    }

    pub fn get_unique_service_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .services
            .iter()
            .map(|s| s.name.clone())
            .filter(|name| !name.is_empty())
            .collect();

        names.sort();
        names.dedup();
        names
    }

    pub fn get_unique_products(&self) -> Vec<String> {
        let mut products: Vec<String> = self
            .services
            .iter()
            .map(|s| s.product.clone())
            .filter(|product| !product.is_empty())
            .collect();

        products.sort();
        products.dedup();
        products
    }

    pub fn count_services(&self) -> usize {
        self.services.len()
    }

    pub fn count_vulnerable_services(&self) -> usize {
        self.services.iter().filter(|s| s.is_vulnerable()).count()
    }

    pub fn get_average_risk_score(&self) -> f64 {
        if self.services.is_empty() {
            return 0.0;
        }

        let total_score: u32 = self
            .services
            .iter()
            .map(|s| s.get_risk_score() as u32)
            .sum();
        total_score as f64 / self.services.len() as f64
    }

    pub fn get_services_by_risk_level(&self, min_risk: u8) -> Vec<&Service> {
        self.services
            .iter()
            .filter(|s| s.get_risk_score() >= min_risk)
            .collect()
    }
}

// Service analyzer for advanced service analysis
pub struct ServiceAnalyzer;

impl ServiceAnalyzer {
    pub fn identify_common_vulnerabilities(services: &[Service]) -> Vec<VulnerabilityInfo> {
        let mut vulnerabilities = Vec::new();

        for service in services {
            // Check for known vulnerable service versions
            if let Some(vuln) = Self::check_known_vulnerabilities(service) {
                vulnerabilities.push(vuln);
            }

            // Check for outdated services
            if let Some(outdated) = Self::check_outdated_service(service) {
                vulnerabilities.push(outdated);
            }
        }

        vulnerabilities
    }

    fn check_known_vulnerabilities(service: &Service) -> Option<VulnerabilityInfo> {
        // This would typically check against a vulnerability database
        // Simplified example:
        let vulnerable_combinations =
            [("apache", "2.2.15"), ("nginx", "1.0.1"), ("openssh", "5.3")];

        for &(product, version) in &vulnerable_combinations {
            if service.product.to_lowercase().contains(product) && service.version == version {
                return Some(VulnerabilityInfo {
                    service_name: service.name.clone(),
                    product: service.product.clone(),
                    version: service.version.clone(),
                    vulnerability_type: "Known Vulnerable Version".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!(
                        "{} {} has known critical vulnerabilities",
                        service.product, service.version
                    ),
                });
            }
        }

        None
    }

    fn check_outdated_service(service: &Service) -> Option<VulnerabilityInfo> {
        // Check if service version is significantly outdated
        // This is a simplified check - in practice you'd use version comparison libraries
        let old_versions = [("apache", "2.2"), ("nginx", "1.0"), ("openssh", "5.3")];

        for &(product, old_version) in &old_versions {
            if service.product.to_lowercase().contains(product)
                && service.version.starts_with(old_version)
            {
                return Some(VulnerabilityInfo {
                    service_name: service.name.clone(),
                    product: service.product.clone(),
                    version: service.version.clone(),
                    vulnerability_type: "Outdated Software".to_string(),
                    severity: "MEDIUM".to_string(),
                    description: format!(
                        "{} {} is significantly outdated",
                        service.product, service.version
                    ),
                });
            }
        }

        None
    }

    pub fn get_service_statistics(services: &[Service]) -> ServiceStatistics {
        let total_services = services.len();
        let vulnerable_count = services.iter().filter(|s| s.is_vulnerable()).count();
        let web_services = services.iter().filter(|s| s.is_web_service()).count();
        let db_services = services.iter().filter(|s| s.is_database_service()).count();

        let average_risk: f64 = if total_services > 0 {
            services
                .iter()
                .map(|s| s.get_risk_score() as f64)
                .sum::<f64>()
                / total_services as f64
        } else {
            0.0
        };

        ServiceStatistics {
            total_services,
            vulnerable_services: vulnerable_count,
            web_services,
            database_services: db_services,
            average_risk_score: average_risk,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VulnerabilityInfo {
    pub service_name: String,
    pub product: String,
    pub version: String,
    pub vulnerability_type: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct ServiceStatistics {
    pub total_services: usize,
    pub vulnerable_services: usize,
    pub web_services: usize,
    pub database_services: usize,
    pub average_risk_score: f64,
}
