// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.
// LEGION (https://gotham-security.com)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::Arc;

use tauri::State;

use crate::analysis::{AnalysisEngine, AnalysisResult};

/// Run analysis for a specific host
#[tauri::command]
pub async fn analyze_host(
    engine: State<'_, Arc<AnalysisEngine>>,
    host_ip: String,
) -> Result<AnalysisResult, String> {
    engine
        .analyze_host(&host_ip)
        .await
        .map_err(|e| e.to_string())
}

/// Run full network analysis
#[tauri::command]
pub async fn analyze_network(
    engine: State<'_, Arc<AnalysisEngine>>,
) -> Result<AnalysisResult, String> {
    engine.analyze_network().await.map_err(|e| e.to_string())
}

/// Get currently running analyses
#[tauri::command]
pub async fn get_active_analyses(
    engine: State<'_, Arc<AnalysisEngine>>,
) -> Result<Vec<String>, String> {
    Ok(engine.get_active_analyses().await)
}
