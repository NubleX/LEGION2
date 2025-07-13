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

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvent {
    pub scan_id: String,
    pub event_type: EventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ScanStarted,
    HostDiscovered,
    PortFound,
    ServiceIdentified,
    VulnerabilityFound,
    ScanProgress,
    ScanCompleted,
    ScanError,
    ScanOutput,
}

pub struct EventStreamer {
    tx: broadcast::Sender<ScanEvent>,
}

impl EventStreamer {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ScanEvent> {
        self.tx.subscribe()
    }

    pub async fn send_event(&self, event: ScanEvent) {
        if let Err(e) = self.tx.send(event) {
            eprintln!("Failed to send event: {}", e);
        }
    }
}