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

import React, { useEffect, useState } from 'react';
import { scanAPI } from '../services/tauriApi';

interface ScanProgressProps {
  scanId: string;
}

const ScanProgress: React.FC<ScanProgressProps> = ({ scanId }) => {
  const [progress, setProgress] = useState<any>(null);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      try {
        const p = await scanAPI.getScanProgress(scanId);
        if (!cancelled) {
          setProgress(p);
          if (await scanAPI.isScanning()) {
            setTimeout(poll, 1000);
          }
        }
      } catch (err) {
        console.error('Failed to fetch scan progress', err);
      }
    };

    poll();

    return () => {
      cancelled = true;
    };
  }, [scanId]);

  const handleCancel = () => {
    scanAPI.cancelNetworkScan(scanId).catch(console.error);
  };

  if (!progress) {
    return <div>Loading progress...</div>;
  }

  return (
    <div>
      <div>{progress.stage}</div>
      <div>{progress.percentage}%</div>
      <button onClick={handleCancel}>Cancel</button>
    </div>
  );
};

export default ScanProgress;

