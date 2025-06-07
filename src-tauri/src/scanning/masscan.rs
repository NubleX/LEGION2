use super::*;
use anyhow::{Result, Context};
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

pub struct MasscanScanner {
    rate_limit: tokio::sync::Semaphore,
    max_rate: u32, // packets per second
}

impl MasscanScanner {
    pub fn new(max_concurrent: usize, max_rate: u32) -> Self {
        Self {
            rate_limit: tokio::sync::Semaphore::new(max_concurrent),
            max_rate,
        }
    }

    pub async fn scan_range(
        &self,
        targets: &[IpAddr],
        ports: &[u16],
        progress_callback: Option<tokio::sync::mpsc::Sender<ScanProgress>>,
    ) -> Result<Vec<ScanResult>> {
        let _permit = self.rate_limit.acquire().await?;
        
        let mut cmd = Command::new("masscan");
        self.configure_masscan_command(&mut cmd, targets, ports)?;
        
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start masscan process")?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();
        let mut results = Vec::new();

        // Parse masscan output in real-time
        while let Some(line) = reader.next_line().await? {
            if let Some(callback) = &progress_callback {
                let progress = self.parse_masscan_progress(&line)?;
                let _ = callback.send(progress).await;
            }

            if let Ok(result) = self.parse_masscan_output(&line) {
                results.push(result);
            }
        }

        let output = child.wait_with_output().await?;
        
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Masscan failed: {}", 
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(results)
    }

    pub async fn fast_port_discovery(
        &self,
        cidr_range: &str,
        top_ports: usize,
        progress_callback: Option<tokio::sync::mpsc::Sender<ScanProgress>>,
    ) -> Result<Vec<ScanResult>> {
        let _permit = self.rate_limit.acquire().await?;
        
        let ports = self.get_top_ports(top_ports);
        
        let mut cmd = Command::new("masscan");
        cmd.arg(cidr_range)
            .arg("-p")
            .arg(self.format_port_list(&ports))
            .arg("--rate")
            .arg(self.max_rate.to_string())
            .arg("--output-format")
            .arg("list")
            .arg("--output-filename")
            .arg("-"); // stdout

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start masscan for port discovery")?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();
        let mut results = Vec::new();

        while let Some(line) = reader.next_line().await? {
            if let Some(callback) = &progress_callback {
                if line.contains("rate:") {
                    let progress = ScanProgress {
                        percent: 0.0, // Masscan doesn't provide percentage
                        message: line.clone(),
                        eta: None,
                    };
                    let _ = callback.send(progress).await;
                }
            }

            if let Ok(result) = self.parse_masscan_list_output(&line) {
                results.push(result);
            }
        }

        let output = child.wait_with_output().await?;
        
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Masscan port discovery failed: {}", 
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(results)
    }

    fn configure_masscan_command(
        &self,
        cmd: &mut Command,
        targets: &[IpAddr],
        ports: &[u16],
    ) -> Result<()> {
        // Add targets
        for target in targets {
            cmd.arg(target.to_string());
        }

        // Add ports
        cmd.arg("-p").arg(self.format_port_list(ports));

        // Rate limiting
        cmd.arg("--rate").arg(self.max_rate.to_string());

        // Output format
        cmd.arg("--output-format").arg("list");
        cmd.arg("--output-filename").arg("-"); // stdout

        // Banner grabbing (if supported)
        cmd.arg("--banners");

        Ok(())
    }

    fn format_port_list(&self, ports: &[u16]) -> String {
        if ports.is_empty() {
            return "1-65535".to_string();
        }

        ports.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn parse_masscan_output(&self, line: &str) -> Result<ScanResult> {
        // Parse masscan list format: "open tcp 22 192.168.1.1 1234567890"
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if parts.len() < 4 || parts[0] != "open" {
            return Err(anyhow::anyhow!("Invalid masscan output format"));
        }

        let protocol = parts[1].to_string();
        let port: u16 = parts[2].parse()
            .context("Failed to parse port number")?;
        let ip: IpAddr = parts[3].parse()
            .context("Failed to parse IP address")?;

        let port_info = Port {
            number: port,
            protocol,
            state: "open".to_string(),
            service: None, // Masscan doesn't provide service detection
            version: None,
            banner: if parts.len() > 4 { 
                Some(parts[4..].join(" ")) 
            } else { 
                None 
            },
        };

        Ok(ScanResult {
            id: Uuid::new_v4(),
            target_id: Uuid::new_v4(), // Generate temporary ID
            timestamp: Utc::now(),
            status: ScanStatus::Completed,
            open_ports: vec![port_info],
            os_detection: None, // Masscan doesn't do OS detection
            vulnerabilities: Vec::new(),
        })
    }

    fn parse_masscan_list_output(&self, line: &str) -> Result<ScanResult> {
        self.parse_masscan_output(line)
    }

    fn parse_masscan_progress(&self, line: &str) -> Result<ScanProgress> {
        if line.contains("rate:") {
            // Extract rate information
            if let Some(rate_start) = line.find("rate:") {
                let rate_info = &line[rate_start..];
                Ok(ScanProgress {
                    percent: 0.0, // Masscan doesn't provide percentage
                    message: format!("Scanning - {}", rate_info),
                    eta: None,
                })
            } else {
                Ok(ScanProgress {
                    percent: 0.0,
                    message: line.to_string(),
                    eta: None,
                })
            }
        } else if line.contains("Scanning") {
            Ok(ScanProgress {
                percent: 0.0,
                message: line.to_string(),
                eta: None,
            })
        } else {
            Err(anyhow::anyhow!("Not a progress line"))
        }
    }

    fn get_top_ports(&self, count: usize) -> Vec<u16> {
        // Top 1000 most common ports (subset shown)
        let top_ports = vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, // ... extend as needed
        ];

        top_ports.into_iter().take(count).collect()
    }

    // Advanced scanning methods
    pub async fn syn_scan_with_excludes(
        &self,
        target_range: &str,
        exclude_ranges: &[&str],
        ports: &[u16],
        progress_callback: Option<tokio::sync::mpsc::Sender<ScanProgress>>,
    ) -> Result<Vec<ScanResult>> {
        let _permit = self.rate_limit.acquire().await?;
        
        let mut cmd = Command::new("masscan");
        cmd.arg(target_range);

        // Add exclusions
        for exclude in exclude_ranges {
            cmd.arg("--exclude").arg(exclude);
        }

        cmd.arg("-p").arg(self.format_port_list(ports))
            .arg("--rate").arg(self.max_rate.to_string())
            .arg("-sS") // SYN scan
            .arg("--output-format").arg("list")
            .arg("--output-filename").arg("-");

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start masscan SYN scan")?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();
        let mut results = Vec::new();

        while let Some(line) = reader.next_line().await? {
            if let Some(callback) = &progress_callback {
                if let Ok(progress) = self.parse_masscan_progress(&line) {
                    let _ = callback.send(progress).await;
                }
            }

            if let Ok(result) = self.parse_masscan_output(&line) {
                results.push(result);
            }
        }

        let output = child.wait_with_output().await?;
        
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Masscan SYN scan failed: {}", 
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(results)
    }

    pub async fn udp_scan(
        &self,
        targets: &[IpAddr],
        udp_ports: &[u16],
        progress_callback: Option<tokio::sync::mpsc::Sender<ScanProgress>>,
    ) -> Result<Vec<ScanResult>> {
        let _permit = self.rate_limit.acquire().await?;
        
        let mut cmd = Command::new("masscan");
        
        for target in targets {
            cmd.arg(target.to_string());
        }

        cmd.arg("-pU:").arg(self.format_port_list(udp_ports))
            .arg("--rate").arg((self.max_rate / 10).to_string()) // Slower for UDP
            .arg("--output-format").arg("list")
            .arg("--output-filename").arg("-");

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start masscan UDP scan")?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();
        let mut results = Vec::new();

        while let Some(line) = reader.next_line().await? {
            if let Some(callback) = &progress_callback {
                if let Ok(progress) = self.parse_masscan_progress(&line) {
                    let _ = callback.send(progress).await;
                }
            }

            if let Ok(result) = self.parse_masscan_output(&line) {
                results.push(result);
            }
        }

        let output = child.wait_with_output().await?;
        
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Masscan UDP scan failed: {}", 
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(results)
    }
}