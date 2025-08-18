// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::core::registry::Registry;
use crate::database::Db;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Runtime};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

#[derive(Serialize, Clone)]
pub struct NmapHostEvent {
    pub ts: String,
    pub ip: String,
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub reason: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct NmapStatusEvent {
    pub phase: String,
    pub message: String,
}

#[derive(Serialize, Clone)]
pub struct NmapProgressEvent {
    pub ts: String,
    pub percent: Option<f32>,
    pub eta: Option<String>,
}

pub async fn run_nmap_stream<R: Runtime>(
    app: &AppHandle<R>,
    bin_path: &std::path::Path,
    target: &str,
    args: &[String],
) -> Result<()> {
    let mut cmd = Command::new(bin_path);
    cmd.arg(target).args(args).args(["-v", "--open"]); // verbose output for streaming

    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    app.emit(
        "nmap:status",
        NmapStatusEvent {
            phase: "starting".into(),
            message: format!("spawned nmap for target: {}", target),
        },
    )?;

    // Stream stdout
    if let Some(out) = child.stdout.take() {
        let reader = BufReader::new(out);
        tokio::pin!(reader);
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await? {
            // Parse different types of nmap output
            if let Some(evt) = parse_nmap_host_line(&line) {
                app.emit("nmap:host", evt)?;
            } else if let Some(progress) = parse_nmap_progress_line(&line) {
                app.emit("nmap:progress", progress)?;
            } else if !line.trim().is_empty() {
                // Send general log messages
                app.emit(
                    "nmap:log",
                    NmapStatusEvent {
                        phase: "scanning".into(),
                        message: line,
                    },
                )?;
            }
        }
    }

    let status = child.wait().await?;
    app.emit(
        "nmap:status",
        NmapStatusEvent {
            phase: "finished".into(),
            message: format!("exit status: {}", status),
        },
    )?;
    app.emit(
        "nmap:done",
        serde_json::json!({ "ts": Utc::now().to_rfc3339() }),
    )?;
    Ok(())
}

pub async fn run_nmap_stream_and_store<R: Runtime>(
    app: &AppHandle<R>,
    db: &Db,
    bin: &std::path::Path,
    target: &str,
    args: &[String],
) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.arg(target).args(args).args(["-v", "--open"]);

    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    app.emit(
        "nmap:status",
        NmapStatusEvent {
            phase: "starting".into(),
            message: format!("spawned nmap for target: {}", target),
        },
    )?;

    if let Some(out) = child.stdout.take() {
        let reader = BufReader::new(out);
        tokio::pin!(reader);
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await? {
            if let Some(evt) = parse_nmap_host_line(&line) {
                // Store in database
                db.upsert_host(&evt.ip, None, None).await?;
                db.upsert_service(&evt.ip, evt.port, &evt.proto, evt.service.as_deref())
                    .await?;

                // Emit to frontend
                app.emit("nmap:host", &evt)?;
            } else if let Some(progress) = parse_nmap_progress_line(&line) {
                app.emit("nmap:progress", progress)?;
            } else if !line.trim().is_empty() {
                app.emit(
                    "nmap:log",
                    NmapStatusEvent {
                        phase: "scanning".into(),
                        message: line,
                    },
                )?;
            }
        }
    }

    let status = child.wait().await?;
    app.emit(
        "nmap:status",
        NmapStatusEvent {
            phase: "finished".into(),
            message: format!("exit status: {}", status),
        },
    )?;
    app.emit(
        "nmap:done",
        serde_json::json!({ "ts": Utc::now().to_rfc3339() }),
    )?;
    Ok(())
}

fn parse_nmap_host_line(line: &str) -> Option<NmapHostEvent> {
    // Parse lines like "Discovered open port 22/tcp on 192.168.1.1"
    // or "22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)"

    if line.contains("Discovered open port") {
        // Format: "Discovered open port 22/tcp on 192.168.1.1"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 && parts[0] == "Discovered" && parts[1] == "open" {
            let port_proto = parts[3]; // "22/tcp"
            let ip = parts[5]; // "192.168.1.1"

            if let Some((port_str, proto)) = port_proto.split_once('/') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some(NmapHostEvent {
                        ts: Utc::now().to_rfc3339(),
                        ip: ip.to_string(),
                        port,
                        proto: proto.to_string(),
                        state: "open".to_string(),
                        service: None,
                        reason: None,
                    });
                }
            }
        }
    } else if line.contains("/tcp") || line.contains("/udp") {
        // Format: "22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let port_proto = parts[0]; // "22/tcp"
            let state = parts[1]; // "open"
            let service = if parts.len() > 2 {
                Some(parts[2])
            } else {
                None
            };

            if let Some((port_str, proto)) = port_proto.split_once('/') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some(NmapHostEvent {
                        ts: Utc::now().to_rfc3339(),
                        ip: "".to_string(), // IP would need to be tracked from previous lines
                        port,
                        proto: proto.to_string(),
                        state: state.to_string(),
                        service: service.map(|s| s.to_string()),
                        reason: None,
                    });
                }
            }
        }
    }

    None
}

fn parse_nmap_progress_line(line: &str) -> Option<NmapProgressEvent> {
    // Parse lines like "Stats: 0:00:05 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan"
    // or percentage indicators from nmap

    if line.contains("% done") {
        // Try to extract percentage
        if let Some(percent_pos) = line.find('%') {
            let before_percent = &line[..percent_pos];
            if let Some(space_pos) = before_percent.rfind(' ') {
                let percent_str = &before_percent[space_pos + 1..];
                if let Ok(percent) = percent_str.parse::<f32>() {
                    return Some(NmapProgressEvent {
                        ts: Utc::now().to_rfc3339(),
                        percent: Some(percent),
                        eta: None,
                    });
                }
            }
        }
    }

    None
}
