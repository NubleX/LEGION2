// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024 and Kali Linux users were left with a broken program.

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