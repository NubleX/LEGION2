use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use anyhow::Result;

pub struct ProcessExecutor;

impl ProcessExecutor {
    pub async fn execute_command(
        command: &str,
        args: &[&str],
        timeout_secs: u64,
    ) -> Result<(String, String, i32)> {
        let mut cmd = Command::new(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Set timeout
        let output = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            cmd.wait_with_output()
        ).await??;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        Ok((stdout, stderr, exit_code))
    }

    pub async fn execute_with_callback<F>(
        command: &str,
        args: &[&str],
        mut callback: F,
    ) -> Result<i32>
    where
        F: FnMut(String) + Send,
    {
        let mut child = Command::new(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            while let Ok(Some(line)) = lines.next_line().await {
                callback(line);
            }
        }

        let status = child.wait().await?;
        Ok(status.code().unwrap_or(-1))
    }
}