// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
// Forked from an earlier version of LEGION, originally created by Gotham Security.
// Archived in 2024.

// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details. You should have received a copy
// of the GNU General Public License along with this program.
// If not, see <http://www.gnu.org/licenses/>.

// Minimal scanning configuration type used by the frontend

export interface ScanConfig {
  targets: string;
  scanType: string;
  ports?: string;
  excludeHosts?: string;
  useNmap?: boolean;
  useMasscan?: boolean;
  extra?: string;
  rate?: number;
  detectOS?: boolean;
  detectVersions?: boolean;
  skipPing?: boolean;
}
