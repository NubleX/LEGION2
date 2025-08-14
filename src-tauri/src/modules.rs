// Module organization for LEGION2
// THERE WILL BE MANY!
// Contains submodules for different scanning and analysis capabilities
// The Modules System's Architectural Purpose:
// This module serves as the main entry point for LEGION2's modular architecture.
// The modules.rs is designed to be a Plugin Registry for modular extensibility, but it's not fully implemented yet. Here's what it's meant to do:

//   1. Module Discovery & Registration

//   // Future modules.rs
//   pub struct ModuleRegistry {
//       sources: HashMap<String, SourceFactory>,
//       transforms: HashMap<String, TransformFactory>, // Not implemented yet
//       sinks: HashMap<String, SinkFactory>,
//       analyzers: HashMap<String, AnalyzerFactory>,  // Future: vuln analysis
//       scripts: HashMap<String, ScriptFactory>,      // Future: custom scripts
//   }

//   2. Dynamic Pipeline Construction

//   Instead of hardcoded match plan.source_type, you'd have:

//   // Current (hardcoded)
//   match plan.source_type.as_str() {
//       "masscan" => MasscanScanner::new(),
//       "nmap" => NmapScanner::new(),
//   }

//   // Future (modular)
//   let pipeline = PipelineBuilder::new()
//       .source(modules.get_source(&plan.source_type)?)
//       .transforms(plan.modules.iter().map(|m| modules.get_transform(m)))
//       .sinks(plan.sink_types.iter().map(|s| modules.get_sink(s)))
//       .build()?;

//   3. Planned Modules (based on the comment "THERE WILL BE MANY!"):

//   - Sources: masscan, nmap, rustscan, zmap, custom-script
//   - Transforms: port-classifier, service-identifier, vuln-mapper, correlation-engine
//   - Sinks: ui, db, json-export, xml-export, elastic-search
//   - Analyzers: cve-lookup, exploit-db, metasploit-search

//   4. Configuration-Driven Scanning

//   // plan.modules would enable things like:
//   let plan = Plan {
//       source_type: "masscan",
//       modules: vec![
//           "port-classifier".to_string(),    // Transform: classify ports as web/db/etc
//           "service-identifier".to_string(), // Transform: identify services
//           "vuln-mapper".to_string(),        // Transform: map services to CVEs
//       ],
//       sink_types: vec!["ui", "db", "json-export"],
//       // ...
//   };

//   Current State:

//   - Registry Pattern: Implemented for sources & sinks
//   - Module Discovery: Just imports, no dynamic registration
//   - Transform Pipeline: Not implemented (plan.modules unused)
//   - Plugin System: No runtime module loading

//   Architectural Benefits When Complete:

//   1. Extensibility: Add new scanners without changing core code
//   2. Composability: Mix & match scan components
//   3. Configuration: Define scan pipelines in JSON/YAML
//   4. Testing: Mock modules for unit tests
//   5. Performance: Parallel transform chains

// Import from scanning directory
pub use crate::scanning::masscan::MasscanScanner;
pub use crate::scanning::nmap::NmapScanner;

// Import from core directory
pub use crate::core::sinks::{UiSink, DbSink};

// Import shared observation types
pub use crate::shared::{Observation, ObservationKind, ObsStream};

// Import plan types and builders
pub use crate::plan::{Plan, ScanType, ScanTiming, PortRange, Protocol, PortState};

/// Module configuration and initialization
pub fn init() -> anyhow::Result<()> {
    log::info!("Initializing LEGION2 modules...");

    // Perform any one-time module initialization here
    // For example: checking binary dependencies, setting up paths

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_init() {
        assert!(init().is_ok());
    }
}
