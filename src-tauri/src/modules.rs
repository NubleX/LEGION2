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

// These re-exports are for future modular architecture
// Keeping them for when the plugin system is fully implemented

use crate::core::traits::Transform;
use crate::core::transformer::{
    IpEnrichmentTransform, ProgressTrackingTransform, ServiceParsingTransform, VulnerabilityTransform,
};
use anyhow::Result;
use std::collections::HashMap;

/// Factory function type for creating transforms
pub type TransformFactory = Box<dyn Fn() -> Box<dyn Transform> + Send + Sync>;

/// Module Registry for dynamic transform pipeline construction
pub struct ModuleRegistry {
    transforms: HashMap<String, TransformFactory>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            transforms: HashMap::new(),
        };

        // Register standard transforms
        registry.register_standard_transforms();
        registry
    }

    fn register_standard_transforms(&mut self) {
        // Register built-in transforms
        self.register_transform(
            "ip-enrichment",
            Box::new(|| Box::new(IpEnrichmentTransform::new())),
        );

        self.register_transform(
            "service-parsing",
            Box::new(|| Box::new(ServiceParsingTransform::new())),
        );

        self.register_transform(
            "progress-tracking",
            Box::new(|| Box::new(ProgressTrackingTransform::new())),
        );

        // XML and MAC enrichment transforms
        self.register_transform(
            "xml-parsing",
            Box::new(|| Box::new(ServiceParsingTransform::new())), // Uses enhanced service parsing with XML
        );

        self.register_transform(
            "mac-enrichment", 
            Box::new(|| Box::new(IpEnrichmentTransform::new())), // MAC vendor lookup integrated
        );

        // Vulnerability analysis transforms 
        // Note: VulnerabilityTransform requires CveDatabase and ExploitDb dependencies
        // For now, we comment this out until the dependencies are properly injected
        // self.register_transform(
        //     "vulnerability-analysis",
        //     Box::new(|| Box::new(VulnerabilityTransform::new())),
        // );

        // Additional semantic aliases
        self.register_transform(
            "port-classifier",
            Box::new(|| {
                Box::new(ServiceParsingTransform::new()) // Alias for service parsing
            }),
        );

        self.register_transform(
            "service-identifier",
            Box::new(|| {
                Box::new(ServiceParsingTransform::new()) // Alias for service parsing
            }),
        );

        self.register_transform(
            "network-fingerprinting",
            Box::new(|| Box::new(IpEnrichmentTransform::new())), // Network analysis capabilities
        );

        log::info!("Registered {} transform modules", self.transforms.len());
    }

    pub fn register_transform(&mut self, name: &str, factory: TransformFactory) {
        self.transforms.insert(name.to_string(), factory);
        log::debug!("Registered transform module: {}", name);
    }

    pub fn create_transform(&self, name: &str) -> Option<Box<dyn Transform>> {
        self.transforms.get(name).map(|factory| factory())
    }

    pub fn list_available_transforms(&self) -> Vec<String> {
        self.transforms.keys().cloned().collect()
    }

    /// Build a transform pipeline from module names
    pub fn build_transform_pipeline(
        &self,
        module_names: &[String],
    ) -> Result<Vec<Box<dyn Transform>>> {
        let mut transforms = Vec::new();

        for name in module_names {
            if let Some(transform) = self.create_transform(name) {
                log::debug!("Added transform to pipeline: {}", name);
                transforms.push(transform);
            } else {
                log::warn!("Unknown transform module: {}", name);
                return Err(anyhow::anyhow!("Unknown transform module: {}", name));
            }
        }

        Ok(transforms)
    }
}

// Global module registry instance
static mut MODULE_REGISTRY: Option<ModuleRegistry> = None;
static INIT: std::sync::Once = std::sync::Once::new();

/// Get the global module registry instance
pub fn get_registry() -> &'static ModuleRegistry {
    unsafe {
        INIT.call_once(|| {
            MODULE_REGISTRY = Some(ModuleRegistry::new());
        });
        MODULE_REGISTRY.as_ref().unwrap()
    }
}

/// Module configuration and initialization
pub fn init() -> anyhow::Result<()> {
    log::info!("Initializing LEGION2 modules...");

    // Initialize the global registry
    let registry = get_registry();
    let available = registry.list_available_transforms();
    log::info!("Available transform modules: {:?}", available);

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
