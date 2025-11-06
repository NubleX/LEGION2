// [dependencies]
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// reqwest = { version = "0.11", features = ["json"] }
// tokio = { version = "1.0", features = ["full"] }
// tracing = "0.1"
// anyhow = "1.0"
// thiserror = "1.0"
// chrono = { version = "0.4", features = ["serde"] }

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CVE {
    pub name: String,           // CVE ID (e.g., "CVE-2021-34527")
    pub product: String,         // Affected product name
    pub version: String,        // Affected version
    pub url: String,            // CVE details URL
    pub source: String,         // Source of the CVE data
    pub severity: Severity,     // CVSS severity level
    pub exploit_id: String,     // Associated exploit ID
    pub exploit: String,        // Exploit description
    pub exploit_url: String,    // URL to exploit details
    pub description: String,    // CVE description
    pub cvss_score: Option<f32>, // CVSS score (0.0 - 10.0)
    pub published_date: Option<DateTime<Utc>>, // Publication date
    pub last_modified_date: Option<DateTime<Utc>>, // Last modified date
    pub references: Vec<String>, // Reference URLs
    pub cwe: Vec<String>,       // CWE IDs
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    #[serde(rename = "critical")]
    Critical,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "unknown")]
    Unknown,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Unknown
    }
}

impl Severity {
    pub fn from_cvss_score(score: f32) -> Self {
        match score {
            9.0..=10.0 => Severity::Critical,
            7.0..=8.9 => Severity::High,
            4.0..=6.9 => Severity::Medium,
            0.1..=3.9 => Severity::Low,
            0.0 => Severity::None,
            _ => Severity::Unknown,
        }
    }

    pub fn from_string(severity_str: &str) -> Self {
        match severity_str.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            "none" => Severity::None,
            _ => Severity::Unknown,
        }
    }
}

impl CVE {
    pub fn new(cve_data: HashMap<String, String>) -> Self {
        let default_severity = "unknown".to_string();
        let severity_str = cve_data.get("severity").unwrap_or(&default_severity);
        let severity = Severity::from_string(severity_str);

        let cvss_score = cve_data.get("cvss_score")
            .and_then(|s| s.parse::<f32>().ok());

        Self {
            name: cve_data.get("id").unwrap_or(&"unknown".to_string()).clone(),
            product: cve_data.get("product").unwrap_or(&"unknown".to_string()).clone(),
            version: cve_data.get("version").unwrap_or(&"unknown".to_string()).clone(),
            url: cve_data.get("url").unwrap_or(&"unknown".to_string()).clone(),
            source: cve_data.get("source").unwrap_or(&"unknown".to_string()).clone(),
            severity,
            exploit_id: cve_data.get("exploitId").unwrap_or(&"unknown".to_string()).clone(),
            exploit: cve_data.get("exploit").unwrap_or(&"unknown".to_string()).clone(),
            exploit_url: cve_data.get("exploitUrl").unwrap_or(&"unknown".to_string()).clone(),
            description: cve_data.get("description").unwrap_or(&"".to_string()).clone(),
            cvss_score,
            published_date: None,
            last_modified_date: None,
            references: Vec::new(),
            cwe: Vec::new(),
        }
    }

    pub fn is_exploitable(&self) -> bool {
        !self.exploit_id.is_empty() && self.exploit_id != "unknown"
    }

    pub fn is_critical(&self) -> bool {
        matches!(self.severity, Severity::Critical | Severity::High)
    }

    pub fn risk_score(&self) -> f32 {
        // Calculate a risk score based on severity and exploit availability
        let severity_multiplier = match self.severity {
            Severity::Critical => 1.0,
            Severity::High => 0.8,
            Severity::Medium => 0.5,
            Severity::Low => 0.2,
            Severity::None => 0.0,
            Severity::Unknown => 0.1,
        };

        let exploit_multiplier = if self.is_exploitable() { 1.5 } else { 1.0 };

        self.cvss_score.unwrap_or(5.0) * severity_multiplier * exploit_multiplier
    }

    pub fn matches_product_version(&self, product: &str, version: &str) -> bool {
        self.product.to_lowercase().contains(&product.to_lowercase()) &&
        (self.version == "unknown" || 
         self.version == "*" || 
         self.version.contains(version))
    }
}

// CVE Database for local storage and querying
pub struct CVEDatabase {
    db: Arc<crate::offensive::cve_db::CveDb>,
    client: Client,
}

impl CVEDatabase {
    pub fn new() -> Result<Self> {
        let client = Client::new();
        let db = Arc::new(crate::offensive::cve_db::CveDb::new()?);
        
        Ok(Self {
            db,
            client,
        })
    }

    pub async fn add_cve(&self, cve: CVE) -> Result<()> {
        self.db.add_cve(&cve).await?;
        Ok(())
    }

    pub async fn get_cve(&self, cve_id: &str) -> Result<Option<CVE>> {
        self.db.get_cve(cve_id).await
    }

    pub async fn search_by_product(&self, product: &str) -> Result<Vec<CVE>> {
        self.db.search_by_product(product).await
    }

    pub async fn search_by_severity(&self, severity: Severity) -> Result<Vec<CVE>> {
        // Get all CVEs and filter by severity
        let all_cves = self.db.search_by_product("").await?;
        Ok(all_cves.into_iter()
            .filter(|cve| cve.severity == severity)
            .collect())
    }

    pub async fn search_exploitable(&self) -> Result<Vec<CVE>> {
        let all_cves = self.db.search_by_product("").await?;
        Ok(all_cves.into_iter()
            .filter(|cve| cve.is_exploitable())
            .collect())
    }

    pub async fn search_critical(&self) -> Result<Vec<CVE>> {
        let all_cves = self.db.search_by_product("").await?;
        Ok(all_cves.into_iter()
            .filter(|cve| cve.is_critical())
            .collect())
    }

    pub async fn get_cves_by_risk_score(&self) -> Result<Vec<CVE>> {
        let mut cves = self.db.search_by_product("").await?;
        cves.sort_by(|a, b| b.risk_score().partial_cmp(&a.risk_score()).unwrap());
        Ok(cves)
    }

    pub async fn count_by_severity(&self) -> Result<HashMap<Severity, usize>> {
        let all_cves = self.db.search_by_product("").await?;
        let mut counts = HashMap::new();
        
        for cve in all_cves {
            *counts.entry(cve.severity.clone()).or_insert(0) += 1;
        }
        
        Ok(counts)
    }

    pub async fn count(&self) -> Result<usize> {
        self.db.count().await
    }
}

// CVE Fetcher for retrieving CVE data from external sources
pub struct CVEFetcher {
    client: Client,
    nvd_api_key: Option<String>,
}

impl CVEFetcher {
    pub fn new(nvd_api_key: Option<String>) -> Self {
        let client = Client::new();
        
        Self {
            client,
            nvd_api_key,
        }
    }

    pub async fn fetch_cve(&self, cve_id: &str) -> Result<CVE> {
        info!("Fetching CVE data for {}", cve_id);
        
        // Try NVD API first
        match self.fetch_from_nvd(cve_id).await {
            Ok(cve) => return Ok(cve),
            Err(e) => {
                debug!("Failed to fetch from NVD: {}", e);
                // Fall back to other sources if needed
            }
        }
        
        // Create a basic CVE object if all sources fail
        let mut cve_data = HashMap::new();
        cve_data.insert("id".to_string(), cve_id.to_string());
        cve_data.insert("url".to_string(), format!("https://nvd.nist.gov/vuln/detail/{}", cve_id));
        cve_data.insert("source".to_string(), "NVD".to_string());
        
        Ok(CVE::new(cve_data))
    }

    /// Fetch CVE and store it in the database
    pub async fn fetch_and_store_cve(&self, cve_id: &str, database: &CVEDatabase) -> Result<CVE> {
        // Check if CVE already exists in database
        if let Ok(Some(existing)) = database.get_cve(cve_id).await {
            debug!("CVE {} already in database", cve_id);
            return Ok(existing);
        }
        
        // Fetch from NVD
        let cve = self.fetch_cve(cve_id).await?;
        
        // Store in database
        database.add_cve(cve.clone()).await?;
        info!("Stored CVE {} in database", cve_id);
        
        Ok(cve)
    }

    /// Search for CVEs by product keyword and store results
    pub async fn search_and_store_cves(&self, keyword: &str, database: &CVEDatabase) -> Result<Vec<CVE>> {
        let cves = self.search_cves(keyword).await?;
        
        // Store each CVE in database
        for cve in &cves {
            if let Err(e) = database.add_cve(cve.clone()).await {
                warn!("Failed to store CVE {}: {}", cve.name, e);
            }
        }
        
        info!("Stored {} CVEs from search for '{}'", cves.len(), keyword);
        Ok(cves)
    }

    async fn fetch_from_nvd(&self, cve_id: &str) -> Result<CVE> {
        let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", cve_id);
        
        let mut request = self.client.get(&url);
        
        // Add API key if available
        if let Some(api_key) = &self.nvd_api_key {
            request = request.header("apiKey", api_key);
        }
        
        let response = request.send().await?;
        
        if !response.status().is_success() {
            anyhow::bail!("NVD API request failed with status: {}", response.status());
        }
        
        let text = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&text)?;
        
        self.parse_nvd_response(&json, cve_id)
    }

    fn parse_nvd_response(&self, json: &serde_json::Value, cve_id: &str) -> Result<CVE> {
        let vulns = json["vulnerabilities"]
            .as_array()
            .context("Invalid NVD response format")?;
        
        if vulns.is_empty() {
            anyhow::bail!("No vulnerability data found for {}", cve_id);
        }
        
        let vuln = &vulns[0];
        let cve_item = &vuln["cve"];
        
        let description = cve_item["descriptions"]
            .as_array()
            .and_then(|descs| descs.iter().find(|d| d["lang"] == "en"))
            .and_then(|d| d["value"].as_str())
            .unwrap_or("No description available")
            .to_string();
        
        // Extract CVSS score (try v3.1 first, then v3.0, then v2.0)
        let cvss_score = cve_item["metrics"]
            .as_object()
            .and_then(|metrics| {
                metrics.get("cvssMetricV31")
                    .or_else(|| metrics.get("cvssMetricV30"))
                    .or_else(|| metrics.get("cvssMetricV2"))
            })
            .and_then(|metric| metric.as_array())
            .and_then(|arr| arr.first())
            .and_then(|metric| metric["cvssData"]["baseScore"].as_f64())
            .map(|score| score as f32);
        
        let severity = if let Some(score) = cvss_score {
            Severity::from_cvss_score(score)
        } else {
            Severity::Unknown
        };
        
        // Extract product and version from CPE (Common Platform Enumeration)
        let mut product = "unknown".to_string();
        let mut version = "unknown".to_string();
        
        if let Some(configurations) = cve_item["configurations"].as_array() {
            for config in configurations {
                if let Some(nodes) = config["nodes"].as_array() {
                    for node in nodes {
                        if let Some(cpe_match) = node["cpeMatch"].as_array() {
                            for cpe in cpe_match {
                                if let Some(cpe_str) = cpe["criteria"].as_str() {
                                    // Parse CPE format: cpe:2.3:a:vendor:product:version:...
                                    let parts: Vec<&str> = cpe_str.split(':').collect();
                                    if parts.len() >= 5 {
                                        product = parts[4].to_string();
                                        if parts.len() >= 6 {
                                            version = parts[5].to_string();
                                        }
                                        // Break after first match
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Extract published and modified dates
        let published_date = cve_item["published"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        
        let last_modified_date = cve_item["lastModified"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        
        let references: Vec<String> = cve_item["references"]
            .as_array()
            .map(|refs| {
                refs.iter()
                    .filter_map(|r| r["url"].as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        
        let cwe: Vec<String> = cve_item["weaknesses"]
            .as_array()
            .map(|weaknesses| {
                weaknesses
                    .iter()
                    .filter_map(|w| {
                        w["description"]
                            .as_array()
                            .and_then(|descs| descs.first())
                            .and_then(|d| d["value"].as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        
        let mut cve_data = HashMap::new();
        cve_data.insert("id".to_string(), cve_id.to_string());
        cve_data.insert("description".to_string(), description);
        cve_data.insert("url".to_string(), format!("https://nvd.nist.gov/vuln/detail/{}", cve_id));
        cve_data.insert("source".to_string(), "NVD".to_string());
        cve_data.insert("product".to_string(), product);
        cve_data.insert("version".to_string(), version);
        
        if let Some(score) = cvss_score {
            cve_data.insert("cvss_score".to_string(), score.to_string());
        }
        
        let mut cve = CVE::new(cve_data);
        cve.severity = severity;
        cve.references = references;
        cve.cwe = cwe;
        cve.published_date = published_date;
        cve.last_modified_date = last_modified_date;
        
        Ok(cve)
    }

    pub async fn search_cves(&self, keyword: &str) -> Result<Vec<CVE>> {
        info!("Searching CVEs for keyword: {}", keyword);
        
        let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}", keyword);
        
        let mut request = self.client.get(&url);
        
        if let Some(api_key) = &self.nvd_api_key {
            request = request.header("apiKey", api_key);
        }
        
        let response = request.send().await?;
        
        if !response.status().is_success() {
            anyhow::bail!("NVD API search failed with status: {}", response.status());
        }
        
        let text = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&text)?;
        self.parse_nvd_search_response(&json)
    }

    fn parse_nvd_search_response(&self, json: &serde_json::Value) -> Result<Vec<CVE>> {
        let vulns = json["vulnerabilities"]
            .as_array()
            .context("Invalid NVD search response format")?;
        
        let mut cves = Vec::new();
        
        for vuln in vulns {
            let cve_item = &vuln["cve"];
            let cve_id = cve_item["id"]
                .as_str()
                .context("Missing CVE ID")?
                .to_string();
            
            let cve_id_clone = cve_id.clone();
            
            // Parse basic information (similar to parse_nvd_response)
            let description = cve_item["descriptions"]
                .as_array()
                .and_then(|descs| descs.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str())
                .unwrap_or("No description available")
                .to_string();
            
            let mut cve_data = HashMap::new();
            cve_data.insert("id".to_string(), cve_id_clone.clone());
            cve_data.insert("description".to_string(), description);
            cve_data.insert("url".to_string(), format!("https://nvd.nist.gov/vuln/detail/{}", cve_id_clone));
            cve_data.insert("source".to_string(), "NVD".to_string());
            
            let cve = CVE::new(cve_data);
            cves.push(cve);
        }
        
        Ok(cves)
    }
}

// CVE Matcher for finding relevant CVEs for products/versions
pub struct CVEMatcher {
    database: CVEDatabase,
}

impl CVEMatcher {
    pub fn new(database: CVEDatabase) -> Self {
        Self { database }
    }

    pub async fn find_cves_for_product(&self, product: &str, version: Option<&str>) -> Result<Vec<CVE>> {
        let cves = self.database.search_by_product(product).await?;
        Ok(cves.into_iter()
            .filter(|cve| {
                if let Some(ver) = version {
                    cve.matches_product_version(product, ver)
                } else {
                    true
                }
            })
            .collect())
    }

    pub async fn find_exploitable_cves(&self, product: &str, version: Option<&str>) -> Result<Vec<CVE>> {
        let cves = self.find_cves_for_product(product, version).await?;
        Ok(cves.into_iter()
            .filter(|cve| cve.is_exploitable())
            .collect())
    }

    pub async fn find_critical_cves(&self, product: &str, version: Option<&str>) -> Result<Vec<CVE>> {
        let cves = self.find_cves_for_product(product, version).await?;
        Ok(cves.into_iter()
            .filter(|cve| cve.is_critical())
            .collect())
    }

    pub async fn get_risk_assessment(&self, product: &str, version: Option<&str>) -> Result<RiskAssessment> {
        let cves = self.find_cves_for_product(product, version).await?;
        
        let total_cves = cves.len();
        let exploitable_cves = cves.iter().filter(|cve| cve.is_exploitable()).count();
        let critical_cves = cves.iter().filter(|cve| cve.is_critical()).count();
        
        let highest_risk_cve = cves
            .iter()
            .max_by(|a, b| a.risk_score().partial_cmp(&b.risk_score()).unwrap());
        
        Ok(RiskAssessment {
            product: product.to_string(),
            version: version.map(|s| s.to_string()),
            total_cves,
            exploitable_cves,
            critical_cves,
            highest_risk_cve: highest_risk_cve.map(|cve| cve.name.clone()),
            overall_risk_score: cves.iter().map(|cve| cve.risk_score()).sum(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub product: String,
    pub version: Option<String>,
    pub total_cves: usize,
    pub exploitable_cves: usize,
    pub critical_cves: usize,
    pub highest_risk_cve: Option<String>,
    pub overall_risk_score: f32,
}

// Utility functions for working with CVEs
pub fn filter_cves_by_severity<'a>(cves: &'a [CVE], severity: Severity) -> Vec<&'a CVE> {
    cves.iter()
        .filter(|cve| cve.severity == severity)
        .collect()
}

pub fn sort_cves_by_risk(cves: &mut [CVE]) {
    cves.sort_by(|a, b| b.risk_score().partial_cmp(&a.risk_score()).unwrap());
}

pub fn get_unique_products(cves: &[CVE]) -> Vec<String> {
    let mut products: Vec<String> = cves
        .iter()
        .map(|cve| cve.product.clone())
        .filter(|product| !product.is_empty() && product != "unknown")
        .collect();
    
    products.sort();
    products.dedup();
    products
}