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