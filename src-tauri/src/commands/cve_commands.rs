// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::offensive::CVE::{
    CVEDatabase, CVEFetcher, CVEMatcher, CVE, RiskAssessment,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveDetail {
    pub name: String,
    pub product: String,
    pub version: String,
    pub url: String,
    pub source: String,
    pub severity: String,
    pub exploit_id: String,
    pub exploit: String,
    pub exploit_url: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub published_date: Option<String>,
    pub last_modified_date: Option<String>,
    pub references: Vec<String>,
    pub cwe: Vec<String>,
    pub is_exploitable: bool,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessmentInfo {
    pub product: String,
    pub version: Option<String>,
    pub total_cves: usize,
    pub exploitable_cves: usize,
    pub critical_cves: usize,
    pub highest_risk_cve: Option<String>,
    pub overall_risk_score: f32,
}

impl From<CVE> for CveDetail {
    fn from(cve: CVE) -> Self {
        let risk_score = cve.risk_score();
        let is_exploitable = cve.is_exploitable();
        Self {
            name: cve.name,
            product: cve.product,
            version: cve.version,
            url: cve.url,
            source: cve.source,
            severity: format!("{:?}", cve.severity).to_lowercase(),
            exploit_id: cve.exploit_id,
            exploit: cve.exploit,
            exploit_url: cve.exploit_url,
            description: cve.description,
            cvss_score: cve.cvss_score,
            published_date: cve.published_date.map(|d| d.to_rfc3339()),
            last_modified_date: cve.last_modified_date.map(|d| d.to_rfc3339()),
            references: cve.references,
            cwe: cve.cwe,
            is_exploitable,
            risk_score,
        }
    }
}

impl From<RiskAssessment> for RiskAssessmentInfo {
    fn from(assessment: RiskAssessment) -> Self {
        Self {
            product: assessment.product,
            version: assessment.version,
            total_cves: assessment.total_cves,
            exploitable_cves: assessment.exploitable_cves,
            critical_cves: assessment.critical_cves,
            highest_risk_cve: assessment.highest_risk_cve,
            overall_risk_score: assessment.overall_risk_score,
        }
    }
}

fn cve_database() -> Result<CVEDatabase, String> {
    CVEDatabase::new().map_err(|e| format!("Failed to open CVE database: {}", e))
}

#[tauri::command]
pub async fn search_cves_by_product(
    product: String,
    version: Option<String>,
) -> Result<Vec<CveDetail>, String> {
    let database = cve_database()?;
    let matcher = CVEMatcher::new(database);

    let cves = matcher
        .find_cves_for_product(&product, version.as_deref())
        .await
        .map_err(|e| format!("CVE search failed: {}", e))?;

    Ok(cves.into_iter().map(CveDetail::from).collect())
}

#[tauri::command]
pub async fn fetch_cve(cve_id: String) -> Result<CveDetail, String> {
    let database = cve_database()?;
    let fetcher = CVEFetcher::new(None);

    let cve = fetcher
        .fetch_and_store_cve(&cve_id, &database)
        .await
        .map_err(|e| format!("Failed to fetch CVE {}: {}", cve_id, e))?;

    Ok(CveDetail::from(cve))
}

#[tauri::command]
pub async fn get_all_cves() -> Result<Vec<CveDetail>, String> {
    let database = cve_database()?;

    let cves = database
        .search_by_product("")
        .await
        .map_err(|e| format!("Failed to list CVEs: {}", e))?;

    Ok(cves.into_iter().map(CveDetail::from).collect())
}

#[tauri::command]
pub async fn get_cve_risk_assessment(
    product: String,
    version: Option<String>,
) -> Result<RiskAssessmentInfo, String> {
    let database = cve_database()?;
    let matcher = CVEMatcher::new(database);

    let assessment = matcher
        .get_risk_assessment(&product, version.as_deref())
        .await
        .map_err(|e| format!("Risk assessment failed: {}", e))?;

    Ok(RiskAssessmentInfo::from(assessment))
}

#[tauri::command]
pub async fn search_and_store_cves(keyword: String) -> Result<Vec<CveDetail>, String> {
    let database = cve_database()?;
    let fetcher = CVEFetcher::new(None);

    let cves = fetcher
        .search_and_store_cves(&keyword, &database)
        .await
        .map_err(|e| format!("NVD search failed for '{}': {}", keyword, e))?;

    Ok(cves.into_iter().map(CveDetail::from).collect())
}
