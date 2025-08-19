pub mod masscan;
pub mod netsniffer; // Temporarily disabled due to etherparse API compatibility issues
pub mod nmap;
pub mod scanner_engine;

// Events module re-exports from shared
pub mod events {
    pub use crate::shared::shared::{EventType, ScanEvent};
}
