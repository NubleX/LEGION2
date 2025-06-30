pub mod models;
pub mod operations;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use models::*;

pub struct Database {
    pub hosts: Arc<RwLock<HashMap<String, Host>>>,
    pub ports: Arc<RwLock<HashMap<String, Port>>>,
    pub vulnerabilities: Arc<RwLock<HashMap<String, Vulnerability>>>,
    pub projects: Arc<RwLock<HashMap<String, Project>>>,
}

impl Database {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
            ports: Arc::new(RwLock::new(HashMap::new())),
            vulnerabilities: Arc::new(RwLock::new(HashMap::new())),
            projects: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn hosts(&self) -> &Arc<RwLock<HashMap<String, Host>>> {
        &self.hosts
    }

    pub fn ports(&self) -> &Arc<RwLock<HashMap<String, Port>>> {
        &self.ports
    }

    pub fn vulnerabilities(&self) -> &Arc<RwLock<HashMap<String, Vulnerability>>> {
        &self.vulnerabilities
    }

    pub fn projects(&self) -> &Arc<RwLock<HashMap<String, Project>>> {
        &self.projects
    }
}