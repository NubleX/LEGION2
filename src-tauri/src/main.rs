// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024 and Kali Linux users were left with a broken program.

// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security

//     This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
//     License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
//     version.

//     This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
//     warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//     details.

//     You should have received a copy of the GNU General Public License along with this program.
//     If not, see <http://www.gnu.org/licenses/>.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod commands;

use commands::{start_scan, stop_scan, get_vulnerabilities, is_scanning, ScanState};
use std::collections::HashMap;
use std::sync::Mutex;

fn main() {
    let scan_state = Mutex::new(ScanState {
        active_scans: HashMap::new(),
    });
    
    tauri::Builder::default()
        .manage(scan_state)
        .invoke_handler(tauri::generate_handler![
            start_scan,
            stop_scan,
            get_vulnerabilities,
            is_scanning
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");  
}
