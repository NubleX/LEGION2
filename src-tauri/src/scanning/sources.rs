use super::engine::{Source, Observation};
use async_trait::async_trait;
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use std::net::IpAddr;
use std::str::FromStr;
use anyhow::Result;
use chrono::Utc;
use crate::core::registry;

/// Source that reads masscan stdout and converts to observations
pub struct MasscanSource {
    reader: Option<BufReader<tokio::process::ChildStdout>>,
    stderr_reader: Option<BufReader<tokio::process::ChildStderr>>,
    child: Option<tokio::process::Child>,
    finished: bool,
}

impl MasscanSource {
    pub async fn new(targets: &str, ports: &str, extra_args: Vec<String>) -> Result<Self> {
        // Get masscan binary path
        let masscan_path = Self::get_masscan_path().await?;
        
        // Build command arguments
        let mut args = vec![
            "-p".to_string(),
            ports.to_string(),
            "--rate".to_string(),
            "1000".to_string(),
            "--open".to_string(),
        ];
        args.extend(extra_args);
        args.push(targets.to_string());

        log::info!("Starting masscan with args: {:?}", args);

        // Start masscan process
        let mut child = Command::new(&masscan_path)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to start masscan: {}", e))?;

        // Get readers
        let stdout = child.stdout.take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get stdout"))?;
        let stderr = child.stderr.take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get stderr"))?;

        Ok(Self {
            reader: Some(BufReader::new(stdout)),
            stderr_reader: Some(BufReader::new(stderr)),
            child: Some(child),
            finished: false,
        })
    }

    async fn get_masscan_path() -> Result<String> {
        // Check local bin directory first
        let bin_dir = crate::utils::os::get_bin_directory();
        let local_masscan = bin_dir.join(if cfg!(windows) { "masscan.exe" } else { "masscan" });
        
        if local_masscan.exists() {
            return Ok(local_masscan.to_string_lossy().to_string());
        }

        // Check if masscan is available in system PATH
        if crate::utils::os::is_masscan_available().await {
            return Ok("masscan".to_string());
        }

        Err(anyhow::anyhow!("Masscan not found in local bin directory or system PATH"))
    }

    fn parse_masscan_line(line: &str) -> Option<Observation> {
        let timestamp = Utc::now();

        // Parse masscan output format: "Discovered open port 80/tcp on 192.168.1.1"
        if line.starts_with("Discovered open port ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let port_proto = parts[3]; // "80/tcp"
                let ip_str = parts[5]; // "192.168.1.1"
                
                if let Some((port_str, protocol)) = port_proto.split_once('/') {
                    if let (Ok(port), Ok(ip)) = (port_str.parse::<u16>(), IpAddr::from_str(ip_str)) {
                        return Some(Observation::ServiceFound {
                            ip,
                            port,
                            protocol: protocol.to_string(),
                            reason: "open".to_string(),
                            timestamp,
                        });
                    }
                }
            }
        }

        // Return progress for other lines
        Some(Observation::Progress {
            message: line.to_string(),
            percentage: None,
            timestamp,
        })
    }
}

#[async_trait]
impl Source for MasscanSource {
    async fn next_observation(&mut self) -> Result<Option<Observation>> {
        if self.finished {
            return Ok(None);
        }

        // Try reading from stdout first
        if let Some(reader) = &mut self.reader {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF on stdout, switch to stderr
                    self.reader = None;
                }
                Ok(_) => {
                    let line = line.trim();
                    if !line.is_empty() {
                        if let Some(obs) = Self::parse_masscan_line(line) {
                            return Ok(Some(obs));
                        }
                    }
                }
                Err(e) => {
                    log::error!("Error reading stdout: {}", e);
                    self.reader = None;
                }
            }
        }

        // Try reading from stderr
        if let Some(stderr_reader) = &mut self.stderr_reader {
            let mut line = String::new();
            match stderr_reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF on stderr
                    self.stderr_reader = None;
                }
                Ok(_) => {
                    let line = line.trim();
                    if !line.is_empty() {
                        return Ok(Some(Observation::Progress {
                            message: line.to_string(),
                            percentage: None,
                            timestamp: Utc::now(),
                        }));
                    }
                }
                Err(e) => {
                    log::error!("Error reading stderr: {}", e);
                    self.stderr_reader = None;
                }
            }
        }

        // Check if process is finished
        if self.reader.is_none() && self.stderr_reader.is_none() {
            if let Some(child) = &mut self.child {
                match child.try_wait() {
                    Ok(Some(exit_status)) => {
                        log::info!("Masscan process finished with status: {:?}", exit_status);
                        self.finished = true;
                        self.child = None;
                        
                        if exit_status.success() {
                            return Ok(Some(Observation::Progress {
                                message: "Masscan scan completed successfully".to_string(),
                                percentage: Some(100.0),
                                timestamp: Utc::now(),
                            }));
                        } else {
                            return Ok(Some(Observation::Error {
                                message: format!("Masscan failed with exit code: {:?}", exit_status.code()),
                                timestamp: Utc::now(),
                            }));
                        }
                    }
                    Ok(None) => {
                        // Process still running, but no more output
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        log::error!("Error checking process status: {}", e);
                        self.finished = true;
                        self.child = None;
                        return Ok(Some(Observation::Error {
                            message: format!("Process error: {}", e),
                            timestamp: Utc::now(),
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    async fn is_finished(&self) -> bool {
        self.finished
    }
}