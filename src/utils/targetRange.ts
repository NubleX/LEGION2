// LEGION2 - Target range matching utilities
// Copyright (c) 2025 NubleX / Igor Dunaev

function ipToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;

  let value = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      return null;
    }
    value = (value << 8) | octet;
  }

  return value >>> 0;
}

function isIpInCidr(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split('/');
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }

  const ipNum = ipToNumber(ip);
  const networkNum = ipToNumber(network);
  if (ipNum === null || networkNum === null) {
    return false;
  }

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (networkNum & mask);
}

function isIpInRange(ip: string, range: string): boolean {
  const [startIp, endPart] = range.split('-');
  const startNum = ipToNumber(startIp.trim());
  if (startNum === null) return false;

  const endPartTrimmed = endPart.trim();
  let endNum: number | null;

  if (endPartTrimmed.includes('.')) {
    endNum = ipToNumber(endPartTrimmed);
  } else {
    const startOctets = startIp.trim().split('.').map(Number);
    if (startOctets.length !== 4) return false;
    const lastOctet = Number(endPartTrimmed);
    if (!Number.isInteger(lastOctet) || lastOctet < 0 || lastOctet > 255) {
      return false;
    }
    endNum = ipToNumber(`${startOctets[0]}.${startOctets[1]}.${startOctets[2]}.${lastOctet}`);
  }

  if (endNum === null) return false;

  const ipNum = ipToNumber(ip);
  if (ipNum === null) return false;

  const min = Math.min(startNum, endNum);
  const max = Math.max(startNum, endNum);
  return ipNum >= min && ipNum <= max;
}

export function isIpInTargetRange(ip: string, targets: string): boolean {
  const trimmedTargets = targets.trim();
  if (!trimmedTargets) return true;

  return trimmedTargets
    .split(/[,\n]/)
    .map((part) => part.trim())
    .filter(Boolean)
    .some((part) => {
      if (part.includes('/')) {
        return isIpInCidr(ip, part);
      }
      if (part.includes('-')) {
        return isIpInRange(ip, part);
      }
      return ip === part;
    });
}
