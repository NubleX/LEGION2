// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

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

