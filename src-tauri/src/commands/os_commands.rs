// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::os;

/// Check whether masscan and nmap have the required Linux capabilities for raw socket scanning.
/// Returns a JSON object with masscan_ok, nmap_ok, status string, and platform.
#[tauri::command]
pub async fn check_scanner_capabilities() -> Result<serde_json::Value, String> {
    #[cfg(target_os = "linux")]
    {
        let (masscan_ok, nmap_ok, status) = os::check_scanner_capabilities().await;
        Ok(serde_json::json!({
            "masscan_ok": masscan_ok,
            "nmap_ok": nmap_ok,
            "status": status,
            "platform": "linux"
        }))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(serde_json::json!({
            "masscan_ok": true,
            "nmap_ok": true,
            "status": "Capability check not required on this platform.",
            "platform": "other"
        }))
    }
}

/// Set raw-socket capabilities on masscan and nmap using pkexec (prompts for password graphically).
/// No terminal or sudo required.
#[tauri::command]
pub async fn set_scanner_capabilities() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        os::set_scanner_capabilities().await
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok("Capability setup is not required on this platform.".to_string())
    }
}
