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

import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

// Mock Tauri APIs for browser development
if (typeof window.__TAURI__ === 'undefined') {
  const mockTauri = {
    invoke: (cmd: string, args?: any) => {
      console.log(`%c[Tauri Mock]%c Invoke '${cmd}'`, 'color: #24C8DB; font-weight: bold', 'color: inherit', args);
      switch (cmd) {
        case 'get_hosts':
          return Promise.resolve([{ id: 1, ip: '127.0.0.1', hostname: 'localhost' }]);
        case 'start_scan':
          return Promise.resolve('mock-scan-123');
        default:
          return Promise.resolve({});
      }
    },
    event: {
      listen: (event: string, handler: (event: any) => void) => {
        console.log(`%c[Tauri Mock]%c Listening to '${event}'`, 'color: #24C8DB; font-weight: bold', 'color: inherit');
        // Mock some events for demonstration
        if (event === 'scan-progress') {
          setInterval(() => handler({ payload: { progress: Math.random() * 100 } }), 2000);
        }
        if (event === 'scan-result') {
          setTimeout(() => handler({ payload: { ip: '127.0.0.1', ports: [80, 443] } }), 5000);
        }
        return () => {
          console.log(`%c[Tauri Mock]%c Unsubscribed from '${event}'`, 'color: #24C8DB; font-weight: bold', 'color: inherit');
        };
      },
    },
    convertFileSrc: (src: string) => `http://localhost:1420/mock-asset/${src}`,
  };
  (window as any).__TAURI__ = mockTauri;
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)