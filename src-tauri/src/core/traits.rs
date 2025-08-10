use async_trait::async_trait;
use anyhow::Result;
use super::types::{ObsStream, Plan};

#[async_trait]
pub trait Source: Send + Sync {
  fn name(&self) -> &'static str;
  async fn start(&self, plan: &Plan) -> Result<ObsStream>;
}

#[async_trait]
pub trait Transform: Send + Sync {
  fn name(&self) -> &'static str;
  async fn apply(&self, input: ObsStream) -> Result<ObsStream>;
}

#[async_trait]
pub trait Sink: Send + Sync {
  fn name(&self) -> &'static str;
  async fn run(&self, input: ObsStream) -> Result<()>;
}
