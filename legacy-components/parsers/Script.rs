// [dependencies]
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// roxmltree = "0.18"
// regex = "1.0"
// reqwest = "0.11"
// tokio = { version = "1.0", features = ["full"] }
// tracing = "0.1"
// anyhow = "1.0"
// thiserror = "1.0"
// url = "2.0"

use anyhow::{Context, Result};
use roxmltree::Node;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

// Assuming you have these modules from previous implementations
// You'll need to adjust the imports based on your actual module structure
mod exploit_db;
mod cve;
use exploit_db::PyExploitDb;
use cve::CVE;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Script {
    pub id: String,
    pub output: String,
    pub elements: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeEntry {
    pub r#type: String,
    pub source: String,
    pub product: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub severity: String,
    pub url: String,
    pub exploit_id: Option<String>,
    pub exploit: Option<String>,
    pub exploit_url: Option<String>,
    pub r#type: String,
    pub version: String,
    pub source: String,
    pub product: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    #[error("ExploitDB error: {0}")]
    ExploitDbError(String),
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl Script {
    pub fn from_xml_node(node: &Node) -> Self {
        let mut elements = HashMap::new();
        
        // Parse script elements
        for child in node.children() {
            if child.is_element() && child.tag_name().name() == "elem" {
                if let Some(key) = child.attribute("key") {
                    elements.insert(key.to_string(), child.text().unwrap_or("").to_string());
                }
            }
        }
        
        Self {
            id: node.attribute("id").unwrap_or("").to_string(),
            output: node.attribute("output").unwrap_or(node.text().unwrap_or("")).to_string(),
            elements,
        }
    }

    pub fn process_shodan_script_output(&self, shodan_output: &str) -> Vec<String> {
        let output = shodan_output
            .replace("\t\t\t", "\t")
            .replace("\t\t", "\t")
            .replace("\t", ";")
            .replace("\n;", "\n")
            .replace(" ", "");
        
        output
            .split('\n')
            .filter(|entry| entry.len() > 1)
            .map(|s| s.to_string())
            .collect()
    }

    pub async fn process_vulners_script_output(&self, vulners_output: &str) -> Result<HashMap<String, CpeEntry>, ScriptError> {
        let mut output = vulners_output
            .replace("\t\t\t", "\t")
            .replace("\t\t", "\t")
            .replace("\t", ";")
            .replace("\n;", "\n")
            .replace(" ", "");
        
        let lines: Vec<&str> = output
            .split('\n')
            .filter(|entry| entry.len() > 1)
            .collect();
        
        // Initialize ExploitDB
        let mut py_exploit_db = PyExploitDb::new()
            .map_err(|e| ScriptError::ExploitDbError(e.to_string()))?;
        py_exploit_db.debug = false;
        py_exploit_db.auto_update = false;
        py_exploit_db.open_file().await
            .map_err(|e| ScriptError::ExploitDbError(e.to_string()))?;
        
        let mut cpe_list = Vec::new();
        let mut processed_lines = Vec::new();
        let mut cpe_counter = 0;
        
        for line in &lines {
            if line.contains("cpe") {
                cpe_list.push(*line);
                processed_lines.push("CPE");
                cpe_counter += 1;
            } else {
                processed_lines.push(line);
            }
        }
        
        let joined_output = processed_lines.join(" ");
        let cpe_sections: Vec<&str> = joined_output
            .split("CPE")
            .filter(|entry| entry.len() > 1)
            .collect();
        
        let mut results_dict = HashMap::new();
        
        for (counter, cpe_entry) in cpe_list.iter().enumerate() {
            let cpe_data: Vec<&str> = cpe_entry
                .split(':')
                .filter(|entry| entry.len() > 1)
                .collect();
            
            if cpe_data.len() < 5 {
                continue;
            }
            
            let cpe_details = CpeEntry {
                r#type: cpe_data[1].to_string(),
                source: cpe_data[2].to_string(),
                product: cpe_data[3].to_string(),
                version: cpe_data[4].to_string(),
            };
            
            if counter < cpe_sections.len() {
                let cve_section = cpe_sections[counter];
                let cve_entries: Vec<&str> = cve_section
                    .split(' ')
                    .filter(|entry| entry.len() > 1)
                    .collect();
                
                // Process CVEs for this CPE
                // In a real implementation, you'd store the CVE data in the CPE entry
                // For now, we'll just store the CPE details
                results_dict.insert(cpe_data[3].to_string(), cpe_details);
            }
        }
        
        Ok(results_dict)
    }

    pub async fn get_cves(&self) -> Result<Option<Vec<CVE>>, ScriptError> {
        let cve_output = &self.output;
        
        if cve_output.is_empty() {
            return Ok(None);
        }
        
        let cves_results = self.process_vulners_script_output(cve_output).await?;
        let mut cve_objects = Vec::new();
        
        // Initialize ExploitDB for CVE lookups
        let mut py_exploit_db = PyExploitDb::new()
            .map_err(|e| ScriptError::ExploitDbError(e.to_string()))?;
        py_exploit_db.debug = false;
        py_exploit_db.auto_update = false;
        py_exploit_db.open_file().await
            .map_err(|e| ScriptError::ExploitDbError(e.to_string()))?;
        
        for (product, cpe_data) in cves_results {
            // Parse CVE data from the output
            // This is a simplified version - in practice you'd extract actual CVE data
            let cve_data = self.extract_cve_data_from_output(cve_output, &product)?;
            
            for cve_entry in cve_data {
                let exploit_results = py_exploit_db.search_cve(&cve_entry.id).await;
                
                let mut cve_obj = CVE::new();
                cve_obj.name = cve_entry.id.clone();
                cve_obj.url = cve_entry.url.clone();
                cve_obj.source = cpe_data.source.clone();
                cve_obj.severity = cve_entry.severity.clone();
                cve_obj.product = product.clone();
                cve_obj.version = cpe_data.version.clone();
                
                if let Some(exploit) = exploit_results {
                    cve_obj.exploit_id = Some(exploit.id.clone());
                    cve_obj.exploit = Some(exploit.description.clone());
                    cve_obj.exploit_url = Some(format!("https://www.exploit-db.com/exploits/{}", exploit.id));
                }
                
                cve_objects.push(cve_obj);
            }
        }
        
        if cve_objects.is_empty() {
            Ok(None)
        } else {
            Ok(Some(cve_objects))
        }
    }

    fn extract_cve_data_from_output(&self, output: &str, product: &str) -> Result<Vec<CveEntry>, ScriptError> {
        let mut cve_entries = Vec::new();
        
        // Use regex to find CVE patterns in the output
        use regex::Regex;
        let cve_re = Regex::new(r"CVE-\d{4}-\d{4,7}").unwrap();
        
        for mat in cve_re.find_iter(output) {
            let cve_id = mat.as_str().to_string();
            
            // Extract severity and URL if available
            // This is a simplified approach - in practice you'd parse the structured output
            let severity = self.extract_severity_for_cve(output, &cve_id);
            let url = format!("https://nvd.nist.gov/vuln/detail/{}", cve_id);
            
            cve_entries.push(CveEntry {
                id: cve_id,
                severity,
                url,
                exploit_id: None,
                exploit: None,
                exploit_url: None,
                r#type: "unknown".to_string(),
                version: "unknown".to_string(),
                source: "unknown".to_string(),
                product: product.to_string(),
            });
        }
        
        Ok(cve_entries)
    }

    fn extract_severity_for_cve(&self, output: &str, cve_id: &str) -> String {
        // Look for severity information near the CVE ID
        // This is a simplified approach - in practice you'd parse the structured output
        if output.contains(&format!("{};HIGH", cve_id)) {
            "HIGH".to_string()
        } else if output.contains(&format!("{};MEDIUM", cve_id)) {
            "MEDIUM".to_string()
        } else if output.contains(&format!("{};LOW", cve_id)) {
            "LOW".to_string()
        } else {
            "UNKNOWN".to_string()
        }
    }

    pub async fn script_selector(&self, host_id: i64) -> Result<Vec<cve::CveEntity>, ScriptError> {
        let script_id = self.id.to_lowercase();
        let mut results = Vec::new();
        
        if script_id.contains("vulners") {
            info!("Processing VULNERS script output for host {}", host_id);
            
            if let Some(cve_results) = self.get_cves().await? {
                for cve_entry in cve_results {
                    let t_cve = cve::CveEntity {
                        name: cve_entry.name.clone(),
                        url: cve_entry.url.clone(),
                        source: cve_entry.source.clone(),
                        severity: cve_entry.severity.clone(),
                        product: cve_entry.product.clone(),
                        version: cve_entry.version.clone(),
                        host_id,
                        exploit_id: cve_entry.exploit_id.clone(),
                        exploit: cve_entry.exploit.clone(),
                        exploit_url: cve_entry.exploit_url.clone(),
                    };
                    results.push(t_cve);
                }
            }
        } else if script_id.contains("shodan-api") {
            info!("Processing SHODAN script output for host {}", host_id);
            // Process Shodan output
            let _shodan_results = self.process_shodan_script_output(&self.output);
            // In a real implementation, you'd process these results
        } else {
            debug!("Processing script {} for host {}", script_id, host_id);
        }
        
        Ok(results)
    }

    pub fn is_vulners_script(&self) -> bool {
        self.id.to_lowercase().contains("vulners")
    }

    pub fn is_shodan_script(&self) -> bool {
        self.id.to_lowercase().contains("shodan")
    }

    pub fn is_vulnerable(&self) -> bool {
        // Check for common vulnerability indicators in script output
        let vuln_indicators = ["vuln", "cve", "exploit", "vulnerable", "risk"];
        let output_lower = self.output.to_lowercase();
        
        vuln_indicators.iter().any(|&indicator| output_lower.contains(indicator))
    }

    pub fn get_cve_ids(&self) -> Vec<String> {
        // Extract CVE IDs from script output using regex
        use regex::Regex;
        let re = Regex::new(r"CVE-\d{4}-\d{4,7}").unwrap();
        re.find_iter(&self.output)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    pub fn get_banner(&self) -> String {
        // Extract banner information from script output
        if !self.output.is_empty() {
            // Return first line of output as banner
            self.output.lines().next().unwrap_or(&self.output).to_string()
        } else {
            format!("Script: {}", self.id)
        }
    }

    pub fn get_elements(&self) -> &HashMap<String, String> {
        &self.elements
    }

    pub fn get_element(&self, key: &str) -> Option<&String> {
        self.elements.get(key)
    }
}

// Script collection and management
pub struct ScriptCollection {
    scripts: Vec<Script>,
}

impl ScriptCollection {
    pub fn new() -> Self {
        Self { scripts: Vec::new() }
    }

    pub fn from_xml_nodes(script_nodes: &[Node]) -> Self {
        let scripts = script_nodes
            .iter()
            .map(|node| Script::from_xml_node(node))
            .collect();
        
        Self { scripts }
    }

    pub fn add_script(&mut self, script: Script) {
        self.scripts.push(script);
    }

    pub fn get_scripts(&self) -> &[Script] {
        &self.scripts
    }

    pub fn get_script_by_id(&self, id: &str) -> Option<&Script> {
        self.scripts.iter().find(|s| s.id == id)
    }

    pub fn get_vulners_scripts(&self) -> Vec<&Script> {
        self.scripts
            .iter()
            .filter(|s| s.is_vulners_script())
            .collect()
    }

    pub fn get_shodan_scripts(&self) -> Vec<&Script> {
        self.scripts
            .iter()
            .filter(|s| s.is_shodan_script())
            .collect()
    }

    pub fn get_vulnerable_scripts(&self) -> Vec<&Script> {
        self.scripts
            .iter()
            .filter(|s| s.is_vulnerable())
            .collect()
    }

    pub fn get_scripts_with_cves(&self) -> Vec<&Script> {
        self.scripts
            .iter()
            .filter(|s| !s.get_cve_ids().is_empty())
            .collect()
    }

    pub fn count_scripts(&self) -> usize {
        self.scripts.len()
    }

    pub fn count_vulners_scripts(&self) -> usize {
        self.scripts.iter().filter(|s| s.is_vulners_script()).count()
    }

    pub fn count_shodan_scripts(&self) -> usize {
        self.scripts.iter().filter(|s| s.is_shodan_script()).count()
    }
}

// Script processor for handling multiple scripts
pub struct ScriptProcessor;

impl ScriptProcessor {
    pub async fn process_host_scripts(scripts: &[Script], host_id: i64) -> Result<Vec<cve::CveEntity>, ScriptError> {
        let mut all_cves = Vec::new();
        
        for script in scripts {
            let cves = script.script_selector(host_id).await?;
            all_cves.extend(cves);
        }
        
        Ok(all_cves)
    }

    pub fn get_unique_script_ids(scripts: &[Script]) -> Vec<String> {
        let mut ids: Vec<String> = scripts.iter().map(|s| s.id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    pub fn get_scripts_by_category(scripts: &[Script]) -> HashMap<String, Vec<&Script>> {
        let mut categorized = HashMap::new();
        
        for script in scripts {
            let category = if script.is_vulners_script() {
                "vulners".to_string()
            } else if script.is_shodan_script() {
                "shodan".to_string()
            } else if script.is_vulnerable() {
                "vulnerable".to_string()
            } else {
                "other".to_string()
            };
            
            categorized.entry(category).or_insert_with(Vec::new).push(script);
        }
        
        categorized
    }
}