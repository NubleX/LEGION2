use anyhow::Result;
use futures::{stream, StreamExt};
use tokio::sync::{broadcast, mpsc};
use crate::core::registry::Registry;
use super::types::{Observation, ObsStream, Plan};

pub struct Engine { pub registry: Registry }

impl Engine {
  pub async fn execute(&self, plan: Plan) -> Result<()> {
    // Source: first module in plan.modules should be "masscan" now
    let mut stream = self.registry.source("masscan").start(&plan).await?;
    for m in &plan.modules {
      if let Ok(tf) = self.registry.transform(m) {
        stream = tf.apply(stream).await?;
      }
    }

    let (tx, mut rx) = mpsc::channel::<Observation>(1024);
    tokio::spawn(async move {
      let mut s = stream;
      while let Some(obs) = s.next().await { let _ = tx.send(obs).await; }
    });

    let (brtx, brrx) = broadcast::channel::<Observation>(1024);
    tokio::spawn(async move {
      while let Some(obs) = rx.recv().await { let _ = brtx.send(obs); }
    });

    let ui = self.registry.sink("ui");
    let db = self.registry.sink("db");

    let ui_task = ui.run(broadcast_to_stream(brrx.subscribe()));
    let db_task = db.run(broadcast_to_stream(brrx.subscribe()));
    tokio::try_join!(ui_task, db_task)?;
    Ok(())
  }
}

fn broadcast_to_stream(mut sub: broadcast::Receiver<Observation>) -> ObsStream {
  stream::unfold((), move |_| async {
    match sub.recv().await { Ok(o) => Some((o, ())), Err(_) => None }
  }).boxed()
}