use anyhow::{Result, anyhow};
use chrono::Utc;
use serde::Serialize;
use tauri::Emitter;
use tokio::{io::{AsyncBufReadExt, BufReader}, process::Command};
use crate::db::Db;
use chrono::Utc;
use crate::core::registry::Registry;

#[derive(Serialize)]
pub struct HostEvent { pub ts: String, pub ip: String, pub port: u16, pub proto: String, pub reason: Option<String> }
#[derive(Serialize)]
pub struct StatusEvent { pub phase: String, pub message: String }
#[derive(Serialize)]
pub struct ProgressEvent { pub ts: String, pub scanned: Option<u64>, pub rate: Option<u64> }

pub async fn run_masscan_stream_and_store<W: tauri::Manager>(
  app: &W, db: &Db, bin: &std::path::Path, targets: &str, ports: &str, extra: &[String]
) -> anyhow::Result<()> {
  use tokio::{io::{AsyncBufReadExt, BufReader}, process::Command};
  use tauri::Emitter;

  let mut cmd = Command::new(bin);
  cmd.arg("-p").arg(ports)
     .arg(targets)
     .args(["--rate", "5000"]) // TODO: param
     .args(["--open", "--wait", "0"]) // fast flush
     .args(extra)
     .arg("--output-format").arg("list");

  let mut child = cmd.stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;

  app.emit_all("masscan:status", StatusEvent { phase: "starting".into(), message: format!("spawned {:?}", bin) })?;

  if let Some(out) = child.stdout.take() {
    let reader = BufReader::new(out);
    tokio::pin!(reader);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
      if let Some(evt) = parse_masscan_line(&line) {
        // store
        db.upsert_host(&evt.ip, Utc::now())?;
        db.upsert_service(&evt.ip, evt.port, &evt.proto, evt.reason.as_deref(), Utc::now())?;
        // emit
        app.emit_all("masscan:host", &evt)?;
      }
    }
  }

  let status = child.wait().await?;
  app.emit_all("masscan:status", StatusEvent { phase: "finished".into(), message: status.to_string() })?;
  app.emit_all("masscan:done", serde_json::json!({ "ts": Utc::now().to_rfc3339() }))?;
  Ok(())
}

fn parse_masscan_line(line: &str) -> Option<HostEvent> {
    // The default 'list' format lines look like:
    // Discovered open port 22/tcp on 10.0.0.5
    if !line.starts_with("Discovered open port ") { return None; }
    let rest = line.trim_start_matches("Discovered open port ");
    let mut parts = rest.split_whitespace();
    let port_proto = parts.next()?; // e.g., 22/tcp
    let _on = parts.next()?; // "on"
    let ip = parts.next()?;  // e.g., 10.0.0.5

    let mut it = port_proto.split('/');
    let port: u16 = it.next()?.parse().ok()?;
    let proto = it.next().unwrap_or("tcp").to_string();

    Some(HostEvent { ts: chrono::Utc::now().to_rfc3339(), ip: ip.to_string(), port, proto, reason: None })
}