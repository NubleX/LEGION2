use crate::core::transformer::{
    IpEnrichmentTransform, ProgressTrackingTransform, ServiceParsingTransform,
    VulnerabilityTransform, MacEnrichmentTransform, PassiveOsTransform,
    CveExploitEnrichmentTransform, PortServiceCveTransform, StealthyHostnameTransform,
};
use crate::shared::traits::Transform;
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
            Box::new(|| Box::new(MacEnrichmentTransform::new())), // MAC vendor lookup from OUI
        );

        self.register_transform(
            "mac_enrichment",
            Box::new(|| Box::new(MacEnrichmentTransform::new())), // Alias with underscore
        );

        self.register_transform(
            "passive-os",
            Box::new(|| Box::new(PassiveOsTransform::new())), // Passive OS detection
        );

        self.register_transform(
            "passive_os",
            Box::new(|| Box::new(PassiveOsTransform::new())), // Alias with underscore
        );

        // Vulnerability analysis transforms
        self.register_transform(
            "vulnerability-analysis",
            Box::new(|| Box::new(VulnerabilityTransform::new())),
        );

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

        // CVE and Exploit enrichment transforms
        self.register_transform(
            "cve-enrichment",
            Box::new(|| Box::new(CveExploitEnrichmentTransform::new())),
        );

        self.register_transform(
            "cve_enrichment",
            Box::new(|| Box::new(CveExploitEnrichmentTransform::new())), // Alias with underscore
        );

        // Port-service-CVE correlation transform
        self.register_transform(
            "port-service-cve",
            Box::new(|| Box::new(PortServiceCveTransform::new())),
        );

        self.register_transform(
            "port_service_cve",
            Box::new(|| Box::new(PortServiceCveTransform::new())), // Alias with underscore
        );

        // Stealthy hostname discovery transform
        self.register_transform(
            "stealthy_hostname",
            Box::new(|| Box::new(StealthyHostnameTransform::new())),
        );

        self.register_transform(
            "hostname_resolution",
            Box::new(|| Box::new(StealthyHostnameTransform::new())), // Alias
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
