//! Module organization for LEGION2
//! THERE WILL BE MANY!
//! Contains submodules for different scanning and analysis capabilities

// Import from scanning directory
pub use crate::scanning::masscan::MasscanScanner;
pub use crate::scanning::nmap::NmapScanner;

// Import from core directory
pub use crate::core::sinks::{UiSink, DbSink};

/// Module configuration and initialization
pub fn init() -> anyhow::Result<()> {
    log::info!("Initializing LEGION2 modules...");
    
    // Perform any one-time module initialization here
    // For example: checking binary dependencies, setting up paths
    
    Ok(())
}

// Re-export commonly used types
pub use scanning::masscan::MasscanScanner;
pub use scanning::nmap::NmapScanner;
pub use core::sinks::{UiSink, DbSink};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_init() {
        assert!(init().is_ok());
    }
}