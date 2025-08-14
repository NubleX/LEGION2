use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ObservationKind { Host, Service, Banner, TopologyEdge, Metric, Error }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
  pub ts: DateTime<Utc>,
  pub kind: ObservationKind,
  pub key: String,                         // e.g. "10.0.0.5:22/tcp"
  pub fields: serde_json::Map<String, serde_json::Value>,
  pub raw: Option<String>,
  pub scan_id: Uuid,
}

pub type ObsStream = futures::stream::BoxStream<'static, Observation>;

#[derive(Clone, Debug, Deserialize)]
pub struct Plan {
  pub scan_id: Uuid,
  pub targets: String,
  pub ports: String,
  pub rate: Option<u64>,
  pub extra: Vec<String>,
  pub modules: Vec<String>,
  pub source_type: String,
  pub sink_types: Vec<String>,
}