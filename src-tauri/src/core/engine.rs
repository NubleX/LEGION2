use crate::core::registry::Registry;
use crate::shared::traits::Transform;
use crate::core::transformer::CompositeTransform;
use crate::plan::Plan;
use crate::shared::shared::{ObsStream, Observation};
use anyhow::Result;
use futures::{stream, StreamExt};
use tokio::sync::broadcast;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EngineState {
    Idle,
    Running,
    Completed,
    Error,
    #[allow(dead_code)] // Reserved for future cancellation state tracking
    Cancelled,
}

#[derive(Clone)]
pub struct Engine {
    pub registry: Registry,
    pub state: Arc<Mutex<EngineState>>,
    pub current_scan_id: Arc<Mutex<Option<String>>>,
}

impl Engine {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry,
            state: Arc::new(Mutex::new(EngineState::Idle)),
            current_scan_id: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn get_state(&self) -> EngineState {
        *self.state.lock().await
    }

    pub async fn is_ready(&self) -> bool {
        let state = self.get_state().await;
        // Allow multiple concurrent scans for recursive discovery
        // Only block if explicitly cancelled or in error state
        matches!(state, EngineState::Idle | EngineState::Completed | EngineState::Running | EngineState::Error)
    }

    /// Reset the engine to a clean state for new scans
    pub async fn reset(&self) -> Result<()> {
        log::info!("Resetting engine state");
        
        // Set state to idle
        *self.state.lock().await = EngineState::Idle;
        
        // Clear current scan ID
        *self.current_scan_id.lock().await = None;
        
        // Clear registry state
        self.registry.clear_active_sources().await;
        
        log::info!("Engine reset completed");
        Ok(())
    }

    pub async fn execute(&self, plan: Plan) -> Result<()> {
        log::info!("Engine starting execution with transforms in pipeline");

        // Check if engine is ready for new scan
        // For recursive discovery and continuous netsniffer, allow concurrent operations
        let current_state = self.get_state().await;
        if matches!(current_state, EngineState::Error) {
            return Err(anyhow::anyhow!("Engine in error state, cannot start new scan"));
        }

        // Set running state and scan ID (allow concurrent scans for recursive discovery)
        // Only update if not already running (to support concurrent operations)
        if current_state == EngineState::Idle || current_state == EngineState::Completed {
            *self.state.lock().await = EngineState::Running;
        }
        *self.current_scan_id.lock().await = Some(plan.scan_id.to_string());
        
        log::info!("Engine state set to Running for scan: {}", plan.scan_id);

        // Execute the scan and update state based on outcome
        let execution_result = async {
            // Create source from plan
            let source = self.registry.create_source(&plan).await?;
            let raw_stream = source.start(&plan).await?;

            // Apply transforms to the stream - use plan.modules for dynamic pipeline
            let transform = if plan.modules.is_empty() {
                // Default transforms if no modules specified
                log::info!("No modules specified, using default transform pipeline");
                // Use with_transform builder to add enrichment transforms
                use crate::core::transformer::{MacEnrichmentTransform, PassiveOsTransform, StealthyHostnameTransform};
                CompositeTransform::new()
                    .with_transform(Box::new(MacEnrichmentTransform::new()))
                    .with_transform(Box::new(PassiveOsTransform::new()))
                    .with_transform(Box::new(StealthyHostnameTransform::new()))
            } else {
                // Build transform pipeline from plan.modules
                log::info!(
                    "Building transform pipeline from modules: {:?}",
                    plan.modules
                );
                let mut composite = CompositeTransform::from_modules(&plan.modules)
                    .map_err(|e| anyhow::anyhow!("Failed to build transform pipeline: {}", e))?;
                
                // Always add enrichment transforms even when modules are specified
                use crate::core::transformer::{MacEnrichmentTransform, PassiveOsTransform, StealthyHostnameTransform};
                composite = composite.with_transform(Box::new(MacEnrichmentTransform::new()));
                composite = composite.with_transform(Box::new(PassiveOsTransform::new()));
                composite = composite.with_transform(Box::new(StealthyHostnameTransform::new()));
                
                composite
            };

            let processed_stream = transform.apply(raw_stream).await?;

            // Create sinks from plan
            let sinks = self.registry.create_sinks(&plan)?;

            // Create broadcast channel for distributing processed observations
            let (brtx, _) = broadcast::channel::<Observation>(1024);

            // Spawn task to read from processed stream and broadcast to sinks
            let tx = brtx.clone();
            let broadcast_task = tokio::spawn(async move {
                let mut stream = processed_stream;
                while let Some(obs) = stream.next().await {
                    log::debug!("Broadcasting observation: {:?}", obs);
                    let _ = tx.send(obs);
                }
                log::info!("Source stream completed - closing broadcast");
                // tx goes out of scope here, which closes the broadcast channel
            });

            // Start all sinks with transformed data
            let mut tasks = Vec::new();
            for sink in sinks {
                let rx = brtx.subscribe();
                let obs_stream = broadcast_to_stream(rx);
                tasks.push(tokio::spawn(async move {
                    log::info!("Starting sink: {}", sink.name());
                    if let Err(e) = sink.run(obs_stream).await {
                        log::error!("Sink {} failed: {}", sink.name(), e);
                    }
                }));
            }

            // For continuous sources (like netsniffer), don't wait for completion
            // The source will run indefinitely until cancelled
            if plan.source_type == "netsniffer" {
                log::info!("Netsniffer running continuously - not waiting for completion");
                // Don't await broadcast_task - let it run forever
                // Sink tasks will continue processing observations indefinitely
                tokio::spawn(async move {
                    if let Err(e) = broadcast_task.await {
                        log::error!("Broadcast task failed: {}", e);
                    }
                });
                return Ok::<(), anyhow::Error>(());
            }
            
            // Wait for source stream to complete (broadcast task)
            // Sink tasks will complete naturally when broadcast closes
            if let Err(e) = broadcast_task.await {
                log::error!("Broadcast task failed: {}", e);
                return Err(anyhow::anyhow!("Broadcast task failed: {}", e));
            }
            
            log::info!("Engine execution completed - source finished, {} sink tasks running", tasks.len());
            Ok::<(), anyhow::Error>(())
        }.await;

        // Update state based on execution result
        match execution_result {
            Ok(_) => {
                *self.state.lock().await = EngineState::Completed;
                log::info!("Engine execution completed successfully for scan: {}", plan.scan_id);
            }
            Err(e) => {
                *self.state.lock().await = EngineState::Error;
                log::error!("Engine execution failed for scan: {}: {}", plan.scan_id, e);
                return Err(e);
            }
        }

        Ok(())
    }
}

fn broadcast_to_stream(sub: broadcast::Receiver<Observation>) -> ObsStream {
    stream::unfold(sub, |mut receiver| async move {
        match receiver.recv().await {
            Ok(obs) => Some((obs, receiver)),
            Err(_) => None,
        }
    })
    .boxed()
}
