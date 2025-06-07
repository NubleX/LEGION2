use anyhow::{Result, Context};
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::sync::mpsc;
use std::time::Duration;

pub struct ProcessManager {
    timeout: Duration,
}

impl ProcessManager {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub async fn execute_with_timeout(
        &self,
        command: &str,
        args: &[&str],
    ) -> Result<(String, String)> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .context("Command timed out")?
            .context("Failed to execute command")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((stdout, stderr))
    }

    pub async fn execute_streaming<F>(
        &self,
        command: &str,
        args: &[&str],
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(String) -> Result<()> + Send + 'static,
    {
        let mut child = Command::new(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn process")?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();

        while let Ok(Some(line)) = tokio::time::timeout(Duration::from_millis(100), reader.next_line()).await {
            if let Some(line) = line? {
                callback(line)?;
            }
        }

        let _ = child.wait().await?;
        Ok(())
    }

    pub async fn kill_process_tree(pid: u32) -> Result<()> {
        #[cfg(unix)]
        {
            use std::process::Command as StdCommand;
            StdCommand::new("pkill")
                .args(["-P", &pid.to_string()])
                .output()
                .context("Failed to kill process tree")?;
        }

        #[cfg(windows)]
        {
            use std::process::Command as StdCommand;
            StdCommand::new("taskkill")
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .output()
                .context("Failed to kill process tree")?;
        }

        Ok(())
    }
}