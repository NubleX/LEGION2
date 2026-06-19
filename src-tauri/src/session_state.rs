// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::shared::session::{SessionAnalytics, SessionManager, SessionParser};
use anyhow::Result;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static SESSION_MANAGER: LazyLock<Mutex<SessionManager>> =
    LazyLock::new(|| Mutex::new(SessionManager::new()));
static LATEST_ANALYTICS: LazyLock<Mutex<Option<SessionAnalytics>>> =
    LazyLock::new(|| Mutex::new(None));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAnalyticsInfo {
    pub nmap_version: String,
    pub scan_args: String,
    pub total_hosts: u32,
    pub up_hosts: u32,
    pub down_hosts: u32,
    pub scan_type: String,
    pub protocol: String,
    pub num_services: u32,
    pub duration_seconds: Option<i64>,
    pub hosts_up_percentage: f64,
    pub scan_efficiency: f64,
    pub ports_per_host: f64,
    pub scan_intensity: String,
    pub performance_rating: String,
    pub scan_summary: String,
}

impl From<SessionAnalytics> for SessionAnalyticsInfo {
    fn from(analytics: SessionAnalytics) -> Self {
        let duration_seconds = analytics.session.duration().map(|d| d.num_seconds());
        Self {
            nmap_version: analytics.session.nmap_version.clone(),
            scan_args: analytics.session.scan_args.clone(),
            total_hosts: analytics.session.total_hosts,
            up_hosts: analytics.session.up_hosts,
            down_hosts: analytics.session.down_hosts,
            scan_type: analytics.session.scan_type.clone(),
            protocol: analytics.session.protocol.clone(),
            num_services: analytics.session.num_services,
            duration_seconds,
            hosts_up_percentage: analytics.session.hosts_up_percentage(),
            scan_efficiency: analytics.scan_efficiency,
            ports_per_host: analytics.ports_per_host,
            scan_intensity: format!("{:?}", analytics.scan_intensity),
            performance_rating: analytics.performance_rating().to_string(),
            scan_summary: analytics.session.scan_summary(),
        }
    }
}

pub fn record_from_xml(xml_content: &str) -> Result<SessionAnalyticsInfo> {
    let session = SessionParser::parse_nmap_xml(xml_content)?;
    SESSION_MANAGER.lock().add_session(session.clone());
    let analytics = SessionAnalytics::from_session(session);
    let info = SessionAnalyticsInfo::from(analytics.clone());
    *LATEST_ANALYTICS.lock() = Some(analytics);
    Ok(info)
}

pub fn record_from_file(file_path: &str) -> Result<SessionAnalyticsInfo> {
    let content = std::fs::read_to_string(file_path)?;
    record_from_xml(&content)
}

pub fn latest_analytics() -> Option<SessionAnalyticsInfo> {
    LATEST_ANALYTICS
        .lock()
        .clone()
        .map(SessionAnalyticsInfo::from)
}

pub fn session_manager() -> &'static Mutex<SessionManager> {
    &SESSION_MANAGER
}
