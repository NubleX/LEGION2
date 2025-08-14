use anyhow::Result;
use futures::{stream, StreamExt};
use tokio::sync::broadcast;
use crate::core::registry::Registry;
use crate::shared::{Observation, ObsStream};
use crate::plan::Plan;
// Traits are used indirectly through the registry

pub struct Engine { 
    pub registry: Registry 
}

impl Engine {
    pub async fn execute(&self, plan: Plan) -> Result<()> {
        // Create source from plan
        let source = self.registry.create_source(&plan).await?;
        let mut stream = source.start(&plan).await?;

        // Create sinks from plan  
        let sinks = self.registry.create_sinks(&plan)?;

        // Create broadcast channel for distributing observations
        let (brtx, _) = broadcast::channel::<Observation>(1024);
        
        // Spawn task to read from source and broadcast to sinks
        let tx = brtx.clone();
        tokio::spawn(async move {
            while let Some(obs) = stream.next().await { 
                let _ = tx.send(obs); 
            }
        });

        // Start all sinks
        let mut tasks = Vec::new();
        for sink in sinks {
            let rx = brtx.subscribe();
            let obs_stream = broadcast_to_stream(rx);
            tasks.push(tokio::spawn(async move {
                sink.run(obs_stream).await
            }));
        }

        // Wait for all tasks to complete
        for task in tasks {
            let _ = task.await;
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
    }).boxed()
}