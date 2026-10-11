import net from 'node:net';

export function parseTarget(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 45 || value.trim() !== value) {
    throw new Error('Target must be one literal IPv4 or IPv6 address.');
  }
  if (net.isIP(value) === 0) throw new Error('Target must be a literal IPv4 or IPv6 address; hostnames and ranges are not supported.');
  return value;
}

export function parsePorts(value) {
  if (typeof value !== 'string' || value.length > 160) throw new Error('Provide 1 to 32 comma-separated TCP ports.');
  const parts = value.split(',');
  if (parts.length < 1 || parts.length > 32 || parts.some(p => !/^[0-9]{1,5}$/.test(p))) {
    throw new Error('Provide 1 to 32 decimal TCP ports between 1 and 65535.');
  }
  const ports = parts.map(Number);
  if (ports.some(p => p < 1 || p > 65535) || new Set(ports).size !== ports.length) {
    throw new Error('Ports must be unique integers between 1 and 65535.');
  }
  return ports;
}
