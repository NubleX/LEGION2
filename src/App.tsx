// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.

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

import { ScanConfig } from './types/scanning';
import ScanForm from './components/ScanForm';
import NetworkMap from './components/NetworkMap';
import ToolOutput from './components/ToolOutput';

function App() {
  const fakeScanStore = {
    activeScans: []
  };

  const fakeHostStore = {
    hosts: []
  };

  const fakeToolStore = {
    outputs: []
  };

  const setSelectedHost = (host: any) => console.log("selected", host);

  const startScan = async (config: ScanConfig) => console.log("starting scan with", config);

  return (
    <div className="min-h-screen bg-gray-950 text-white p-6">
      <div className="flex gap-4 h-screen">
        <ScanForm
          className="flex-1 overflow-auto"
          onStartScan={startScan}
          isScanning={fakeScanStore.activeScans.length > 0}
        />

        <NetworkMap
          className="flex-1 overflow-auto"
          hosts={fakeHostStore.hosts}
          onHostSelect={setSelectedHost}
        />

        <ToolOutput
          className="flex-1 overflow-auto"
          outputs={fakeToolStore.outputs}
          isLive={true}
        />
      </div>
    </div>
  );
}

export default App;