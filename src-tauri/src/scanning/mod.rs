pub mod models;
pub mod engine;
pub mod coordinator;
pub mod masscan;
pub mod nmap;
pub mod sources;

// Re-export events from shared for compatibility
pub use crate::shared::{EventType, ScanEvent};
pub mod events {
    pub use crate::shared::{EventType, ScanEvent};
}