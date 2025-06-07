use super::*;
use anyhow::{Result, Context};
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use xml_rs::{EventReader, Event};

pub struct NmapScanner {
    rate_limit: tokio::sync::Semaphore,
}

impl NmapScanner {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            rate_limit: tokio::sync::Semaphore::new(max_concurrent),
        }
    }

    pub async fn scan_target(
        &self,
        target: &ScanTarget,
        progress_callback: Option<tokio::sync::mpsc::Sender<ScanProgress>>,
    ) -> Result<ScanResult> {
        let _permit = self.rate_limit.acquire().await?;
        
        let mut cmd = Command::new("nmap");
        
        // Build nmap command based on scan type
        self.configure_nmap_command(&mut cmd, target)?;
        
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start nmap process")?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();

        // Stream output for real-time updates
        while let Some(line) = reader.next_line().await? {
            if let Some(callback) = &progress_callback {
                let progress = self.parse_nmap_progress(&line)?;
                let _ = callback.send(progress).await;
            }
        }

        let output = child.wait_with_output().await?;
        
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Nmap scan failed: {}", 
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        self.parse_nmap_xml(target, &output.stdout)
    }

    fn configure_nmap_command(&self, cmd: &mut Command, target: &ScanTarget) -> Result<()> {
        cmd.arg("-oX").arg("-"); // XML output to stdout
        
        match &target.scan_type {
            ScanType::Quick => {
                cmd.args(["-sS", "-T4", "--top-ports", "1000"]);
            }
            ScanType::Comprehensive => {
                cmd.args(["-sS", "-sV", "-O", "-A", "-T4"]);
                cmd.args(["-p", "1-65535"]);
            }
            ScanType::Stealth => {
                cmd.args(["-sS", "-T2", "-f"]);
            }
            ScanType::Custom { options } => {
                for opt in options.split_whitespace() {
                    cmd.arg(opt);
                }
            }
        }

        cmd.arg(target.ip.to_string());
        Ok(())
    }

    fn parse_nmap_xml(&self, target: &ScanTarget, xml_data: &[u8]) -> Result<ScanResult> {
        let mut result = ScanResult {
            id: Uuid::new_v4(),
            target_id: target.id,
            timestamp: Utc::now(),
            status: ScanStatus::Completed,
            open_ports: Vec::new(),
            os_detection: None,
            vulnerabilities: Vec::new(),
        };

        // XML parsing implementation
        let parser = EventReader::new(xml_data);
        
        for event in parser {
            match event? {
                Event::StartElement { name, attributes, .. } => {
                    match name.local_name.as_str() {
                        "port" => {
                            let port = self.parse_port_element(&attributes)?;
                            result.open_ports.push(port);
                        }
                        "osmatch" => {
                            let os = self.parse_os_element(&attributes)?;
                            result.os_detection = Some(os);
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        Ok(result)
    }

    fn parse_nmap_progress(&self, line: &str) -> Result<ScanProgress> {
        // Parse nmap progress output
        if line.contains("% done") {
            let percent = self.extract_percentage(line)?;
            Ok(ScanProgress {
                percent,
                message: line.to_string(),
                eta: None,
            })
        } else {
            Ok(ScanProgress {
                percent: 0.0,
                message: line.to_string(),
                eta: None,
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub percent: f32,
    pub message: String,
    pub eta: Option<DateTime<Utc>>,
}