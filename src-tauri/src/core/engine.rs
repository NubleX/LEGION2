use crate::core::registry::Registry;
use crate::core::traits::Transform;
use crate::core::transforms::CompositeTransform;
use crate::plan::Plan;
use crate::shared::{ObsStream, Observation};
use anyhow::Result;
use futures::{stream, StreamExt};
use tokio::sync::broadcast;

pub struct Engine {
    pub registry: Registry,
}

impl Engine {
    pub async fn execute(&self, plan: Plan) -> Result<()> {
        log::info!("Engine starting execution with transforms in pipeline");

        // Create source from plan
        let source = self.registry.create_source(&plan).await?;
        let raw_stream = source.start(&plan).await?;

        // Apply transforms to the stream - use plan.modules for dynamic pipeline
        let transform = if plan.modules.is_empty() {
            // Default transforms if no modules specified
            log::info!("No modules specified, using default transform pipeline");
            CompositeTransform::new()
        } else {
            // Build transform pipeline from plan.modules
            log::info!(
                "Building transform pipeline from modules: {:?}",
                plan.modules
            );
            CompositeTransform::from_modules(&plan.modules)
                .map_err(|e| anyhow::anyhow!("Failed to build transform pipeline: {}", e))?
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

        // Wait for source stream to complete (broadcast task)
        // Sink tasks will complete naturally when broadcast closes
        if let Err(e) = broadcast_task.await {
            log::error!("Broadcast task failed: {}", e);
        }
        
        log::info!("Engine execution completed - source finished, {} sink tasks running", tasks.len());
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
